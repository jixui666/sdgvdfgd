//
//  ContainerScan.swift
//  uuvpn —— 移植自 WQFiles-main/WQAccess.m 的容器枚举。
//
//  上游的关键设计（不是写死 inode，也不是每次全量扫）：
//
//    APFS 的 object id 单调递增且从不复用，所以「扫描时探测到的 probe inode」
//    之后新建的容器一定 id 更大。于是：
//      1. 全量扫一次，把 {probe, roots: path -> inode} 存到 Caches 的 plist
//      2. 下次启动只扫 probe+1 .. 新的上界（增量，通常几十个 id）
//      3. 用 fsgetpath 逐个确认旧条目还在原路径（被删/移动的丢掉）
//      4. 每 7 天做一次全量，卷或 id 空间变了也做全量
//
//  线程模型也照上游：最多 4 个 worker（核数的一半），32768 个 id 一个 chunk
//  用 work-stealing 队列分配 —— 线程太多只会抢 VFS 锁，实测 96 线程时单次
//  fsgetpath 从 ~1µs 退化到 ~543µs（4M inode 要 22 秒）。
//

import Foundation

enum ContainerScan {

    // MARK: - 配置（与 WQFiles 一致）

    /// 探测到的 inode + 这个余量作为上界（上游 kWQInodeMargin）
    static let inodeMargin: Int64 = 100_000
    /// 缓存格式变了就换号：旧缓存没有 filledLow/fullDone，会永远停在热点窗口。
    static let cacheVersion = 2
    /// 强制全量的间隔：7 天（上游 kWQFullScanInterval）
    static let fullScanInterval: TimeInterval = 7 * 24 * 3600
    /// 一次 chunk 的 inode 数（上游 chunk = 32768）
    static let chunkSize: Int64 = 32_768
    /// 单轮扫描的 inode 上限，防止 id 空间异常时跑飞
    static let hardCeiling: Int64 = 50_000_000

    /// 扫描的容器根，与上游 wq_shared_scan_roots 完全一致
    static var bases: [String] {
        [
            "/private/var/mobile/Containers/Data/Application",
            "/private/var/mobile/Containers/Data/PluginKitPlugin",
            "/private/var/mobile/Containers/Data/InternalDaemon"
        ]
    }

    // MARK: - 结果模型

    struct Result {
        /// base -> (path -> inode)
        var roots: [String: [String: Int64]]
        var probeInode: Int64
        var fullScanAt: TimeInterval
        var didFullScan: Bool

        var totalContainers: Int {
            roots.values.reduce(0) { $0 + $1.count }
        }

        func allPaths() -> [String] {
            roots.values.reduce(into: [String]()) { $0.append(contentsOf: $1.keys) }
        }
    }

    // MARK: - 磁盘缓存

    private static var cachePath: String? {
        guard let dir = NSSearchPathForDirectoriesInDomains(
            .cachesDirectory, .userDomainMask, true
        ).first else { return nil }
        return (dir as NSString).appendingPathComponent("wq-container-scan.plist")
    }

    private static func loadCache(
        probeInode: Int64,
        now: TimeInterval
    ) -> CachePayload? {
        guard let path = cachePath,
              let raw = NSDictionary(contentsOfFile: path) as? [String: Any],
              let version = raw["version"] as? Int, version == cacheVersion,
              let probe = raw["probe"] as? Int64,
              let fullAt = raw["fullAt"] as? TimeInterval,
              let rootsRaw = raw["roots"] as? [String: [String: Int64]] else {
            return nil
        }
        // inode 空间被重置（换卷 / 恢复备份）→ 缓存作废
        guard probe > 0, probe <= probeInode else {
            traceLog("scan: cache rejected — volume ids were reset")
            return nil
        }
        let filledLow = raw["filledLow"] as? Int64 ?? 0
        let hotLow = raw["hotLow"] as? Int64 ?? 0
        // fullDone=false 表示这只覆盖了热点窗口：它要能续跑，所以不受 7 天限制。
        let fullDone = raw["fullDone"] as? Bool ?? (filledLow > 0 && hotLow <= filledLow)
        if fullDone {
            let age = now - fullAt
            guard age >= 0, age < fullScanInterval else {
                traceLog("scan: cache rejected — weekly full scan due")
                return nil
            }
        }
        for base in bases where rootsRaw[base] == nil {
            traceLog("scan: cache rejected — missing root \(base)")
            return nil
        }
        return CachePayload(
            probe: probe, fullAt: fullAt, filledLow: filledLow,
            hotLow: hotLow, fullDone: fullDone, roots: rootsRaw
        )
    }

    private static func saveCache(
        probe: Int64,
        fullAt: TimeInterval,
        filledLow: Int64,
        hotLow: Int64,
        fullDone: Bool,
        roots: [String: [String: Int64]]
    ) {
        guard let path = cachePath else { return }
        let payload: [String: Any] = [
            "version": cacheVersion,
            "probe": probe,
            "fullAt": fullAt,
            "filledLow": filledLow,
            "hotLow": hotLow,
            "fullDone": fullDone,
            "roots": roots
        ]
        if !(payload as NSDictionary).write(toFile: path, atomically: true) {
            traceLog("scan: cannot save container list to \(path)")
        }
    }

    struct CachePayload {
        var probe: Int64
        var fullAt: TimeInterval
        var filledLow: Int64
        var hotLow: Int64
        var fullDone: Bool
        var roots: [String: [String: Int64]]
    }

    // MARK: - inode 上界探测（上游 wq_volume_max_inode）

    /// 建一个临时文件读它的 inode，加 margin 作为本轮上界。
    /// 比写死 50M 好得多，也覆盖得住刚安装的 App。
    static func volumeMaxInode() -> Int64 {
        let directories = [
            NSTemporaryDirectory(),
            (NSHomeDirectory() as NSString).appendingPathComponent("Documents"),
            NSSearchPathForDirectoriesInDomains(.cachesDirectory, .userDomainMask, true).first ?? ""
        ]
        for directory in directories where !directory.isEmpty {
            let probe = (directory as NSString)
                .appendingPathComponent("wq-inode-\(arc4random())")
            let fd = open(probe, O_CREAT | O_EXCL | O_WRONLY, 0o600)
            guard fd >= 0 else { continue }
            var info = stat()
            let ok = fstat(fd, &info) == 0
            close(fd)
            unlink(probe)
            guard ok, info.st_ino > 0 else { continue }
            let bound = Int64(info.st_ino) + inodeMargin
            return min(hardCeiling, max(bound, 1_000_000))
        }
        return hardCeiling
    }

    // MARK: - 扫描（4 worker + 32768 work-stealing，上游 wq_scan_children）

    /// 扫 `firstId...lastId`，收集 bases 的直接子项，返回 path -> inode。
    static func scanChildren(
        bases scanBases: [String],
        firstId: Int64,
        lastId: Int64
    ) -> [String: Int64] {
        guard firstId <= lastId, !scanBases.isEmpty else { return [:] }
        let total = lastId - firstId + 1
        let chunkCount = Int((total + chunkSize - 1) / chunkSize)
        guard chunkCount > 0 else { return [:] }

        let cores = ProcessInfo.processInfo.activeProcessorCount
        let workers = max(1, min(4, max(1, cores / 2)))

        // 每个 chunk 结果写自己那一格，不同 index 互不重叠
        // [String: Int64] 是值类型但共享 CoW 存储，initialize(repeating:) 会让所有
        // 格子指向同一份空存储，并发写入触发 CoW 竞态。逐格初始化。
        let buffer = UnsafeMutablePointer<[String: Int64]>.allocate(capacity: chunkCount)
        for index in 0..<chunkCount {
            buffer.advanced(by: index).initialize(to: [:])
        }
        defer {
            for index in 0..<chunkCount {
                buffer.advanced(by: index).deinitialize(count: 1)
            }
            buffer.deallocate()
        }

        let lock = NSLock()
        var nextChunk = 0
        DispatchQueue.concurrentPerform(iterations: workers) { _ in
            while true {
                lock.lock()
                let index = nextChunk
                nextChunk += 1
                lock.unlock()
                guard index < chunkCount else { return }

                let first = firstId + Int64(index) * chunkSize
                let last = min(first + chunkSize - 1, lastId)
                guard first <= last else { continue }
                buffer[index] = rawScan(bases: scanBases, from: first, to: last)
            }
        }

        var merged: [String: Int64] = [:]
        for index in 0..<chunkCount {
            merged.merge(buffer[index]) { existing, _ in existing }
        }
        return merged
    }

    /// 一次 C 调用扫一个 chunk，同时匹配所有 base。
    private static func rawScan(
        bases scanBases: [String],
        from: Int64,
        to: Int64
    ) -> [String: Int64] {
        var pointers: [UnsafeMutablePointer<CChar>?] = scanBases.map { strdup($0) }
        defer { for pointer in pointers { free(pointer) } }

        var output: [String: Int64] = [:]
        let count = Int32(pointers.count)
        pointers.withUnsafeMutableBufferPointer { buffer in
            guard let raw = bad_query_scan_multi(buffer.baseAddress, count, from, to) else { return }
            defer { free(raw) }
            let text = String(cString: raw)
            for line in text.split(separator: "\n") where !line.isEmpty {
                let path = String(line)
                // 直接 stat 拿 inode（比再走 fsgetpath 快）
                let inode = bad_query_inode_for_path(path)
                if inode > 0 { output[path] = inode }
            }
        }
        return output
    }

    // MARK: - 缓存校验（上游 wq_scan_verify）

    /// 用缓存的 inode 反查路径，能对上的保留，对不上的（删除/移动）丢弃。
    static func verify(
        roots: [String: [String: Int64]]
    ) -> (kept: [String: [String: Int64]], dropped: Int) {
        var kept: [String: [String: Int64]] = [:]
        var dropped = 0
        for (base, entries) in roots {
            var survivors: [String: Int64] = [:]
            for (path, inode) in entries {
                if bad_query_inode_for_path(path) == inode {
                    survivors[path] = inode
                } else {
                    dropped += 1
                }
            }
            kept[base] = survivors
        }
        return (kept, dropped)
    }

    // MARK: - 对外：拿到容器列表（带缓存，增量）

    // MARK: 进程内缓存
    //
    // cachedEntries(for:) 会被每个 bundleID 各调一次（13 个配置 × 2 个 root），
    // 如果每次都跑 containerRoots() 就等于扫 26 遍全量 —— 实测 11ms 内就叠了两次
    // volume bound 日志，扫描永远跑不完。这里按 TTL 直接返回上一次的结果。
    private static let memoryLock = NSLock()
    private static var memoryResult: Result?
    private static var memoryAt: TimeInterval = 0
    private static let memoryTTL: TimeInterval = 600

    /// 单实例守卫：同一时刻只允许一次 walk。没有它，App Data 和 PluginKit
    /// 两个 root 会相隔 95ms 各起一次全量扫（38M inode 永远扫不完），
    /// 缓存落不了盘，每轮都从 inode 1 重来。
    private static let flightLock = NSLock()
    private static var flighting = false

    private static func storeMemory(_ result: Result) {
        memoryLock.lock()
        memoryResult = result
        memoryAt = Date().timeIntervalSince1970
        memoryLock.unlock()
    }

    private static func selfContainerInode() -> Int64 {
        guard let documents = NSSearchPathForDirectoriesInDomains(
            .documentDirectory, .userDomainMask, true
        ).first else { return 0 }
        var info = stat()
        guard stat(documents, &info) == 0 else { return 0 }
        return Int64(info.st_ino)
    }

    /// 把一次扫描结果按 base 归位（扫描本身已按 base 匹配，这里只做分派）。
    private static func merge(
        _ found: [String: Int64],
        into roots: inout [String: [String: Int64]]
    ) {
        for (path, inode) in found {
            for base in bases where belongs(path, to: base) {
                roots[base, default: [:]][path] = inode
            }
        }
    }

    /// 等到全量扫完（或超时），返回最新快照。
    ///
    /// 这是 3105 与移植版最本质的差别：3105 的 `containerIndexSnapshot(waitForBuild:)
    /// 会一直阻塞到 1..ceiling 走完（约 220s），所以第一个 cycle 就能命中所有
    /// 已安装 app；而热点窗口只覆盖 2.1M/37.95M ≈ 5.5%，早装的 app 全在低 inode
    /// 区，等不到就等于索引只有那 5 个越狱工具（log2_86 / container-index_7.txt）。
    static func waitForFullScan(timeout: TimeInterval = 240) -> Result {
        var result = containerRoots()
        if result.didFullScan { return result }
        let deadline = Date().addingTimeInterval(timeout)
        let started = Date()
        while Date() < deadline {
            Thread.sleep(forTimeInterval: 0.5)
            memoryLock.lock()
            let snapshot = memoryResult
            memoryLock.unlock()
            if let snapshot = snapshot {
                result = snapshot
                if result.didFullScan {
                    let elapsed = String(format: "%.0f", Date().timeIntervalSince(started))
                    traceLog("scan: full scan settled — \(result.totalContainers) containers in \(elapsed)s")
                    return result
                }
            }
        }
        traceLog("scan: full scan still incomplete after \(Int(timeout))s — keeping \(result.totalContainers) containers (will resume next cycle)")
        return result
    }

    static func containerRoots(forceFull: Bool = false) -> Result {
        memoryLock.lock()
        if !forceFull, let cached = memoryResult,
           Date().timeIntervalSince1970 - memoryAt < memoryTTL {
            memoryLock.unlock()
            traceLog("scan: memory hit — \(cached.totalContainers) containers")
            return cached
        }
        memoryLock.unlock()

        flightLock.lock()
        if flighting {
            let snapshot = memoryResult
            flightLock.unlock()
            if let snapshot = snapshot {
                traceLog("scan: walk already running — serving \(snapshot.totalContainers) cached containers")
                return snapshot
            }
            // 冷启动且第一次 walk 还在跑：返回一个「每个 root 都是空数组」的快照，
            // 而不是空字典 —— 空字典会让 cachedEntries 返回 nil，调用方接着自己
            // 再跑一遍 38M inode 的全量扫（log2_86 的 12s 窗口里两套 walk 并行）。
            traceLog("scan: walk already running — no snapshot yet, deferring")
            return emptyResult()
        }
        flighting = true
        flightLock.unlock()

        let result = scanAndCache(forceFull: forceFull)

        flightLock.lock()
        flighting = false
        flightLock.unlock()
        return result
    }

    private static func emptyResult() -> Result {
        var roots: [String: [String: Int64]] = [:]
        for base in bases { roots[base] = [:] }
        return Result(roots: roots, probeInode: 0, fullScanAt: 0, didFullScan: false)
    }

    private static func scanAndCache(forceFull: Bool) -> Result {
        let now = Date().timeIntervalSince1970
        let ceiling = volumeMaxInode()
        traceLog("scan: volume bound=\(ceiling) workers<=4 chunk=\(chunkSize)")

        if !forceFull, let cache = loadCache(probeInode: ceiling, now: now) {
            let verified = verify(roots: cache.roots)
            var roots = verified.kept
            var probe = cache.probe
            traceLog("scan: cache hit probe=\(cache.probe) kept=\(verified.kept.values.reduce(0) { $0 + $1.count }) dropped=\(verified.dropped) filledLow=\(cache.filledLow) fullDone=\(cache.fullDone)")

            if ceiling > cache.probe {
                let fresh = scanChildren(
                    bases: bases, firstId: cache.probe + 1, lastId: ceiling
                )
                traceLog("scan: incremental \(cache.probe + 1)..\(ceiling) added=\(fresh.count)")
                merge(fresh, into: &roots)
                probe = ceiling
                saveCache(
                    probe: probe, fullAt: cache.fullAt, filledLow: cache.filledLow,
                    hotLow: cache.hotLow, fullDone: false, roots: roots
                )
            }
            let cached = Result(
                roots: roots, probeInode: probe,
                fullScanAt: cache.fullAt, didFullScan: cache.fullDone
            )
            storeMemory(cached)

            if !cache.fullDone {
                // 上一次只扫完了热点窗口（进程在补齐途中被回收）。继续从
                // filledLow / probe 往后补，否则低 inode 区永远扫不到 ——
                // 这正是容器索引一直停在 5 条的原因。
                traceLog("scan: resume fill from low=\(cache.filledLow) high=\(probe)")
                startBackgroundFill(
                    roots: roots, hotLow: cache.hotLow, ceiling: ceiling,
                    probe: probe, filledLow: cache.filledLow, fullAt: cache.fullAt
                )
            }
            return cached
        }

        // 冷启动：先扫自己容器周边 4M 个 id（系统 app 与后装的 app 都落在这
        // 附近），立刻落盘给本轮用；剩下的 id 交给后台分窗口补齐。
        let own = selfContainerInode()
        let hotLow = own > 0 ? max(1, own - 2_000_000) : 1
        let hotHigh = own > 0 ? min(ceiling, own + 2_000_000) : min(ceiling, 4_000_000)
        let started = Date()
        var roots: [String: [String: Int64]] = [:]
        for base in bases { roots[base] = [:] }
        if hotLow <= hotHigh {
            merge(scanChildren(bases: bases, firstId: hotLow, lastId: hotHigh), into: &roots)
        }
        let hotCount = roots.values.reduce(0) { $0 + $1.count }
        let hotElapsed = String(format: "%.1f", Date().timeIntervalSince(started))
        traceLog("scan: hot window \(hotLow)..\(hotHigh) — \(hotCount) containers in \(hotElapsed)s (own=\(own))")

        let partialFullAt = now
        saveCache(
            probe: hotHigh, fullAt: partialFullAt, filledLow: 0,
            hotLow: hotLow, fullDone: false, roots: roots
        )
        let snapshot = Result(
            roots: roots, probeInode: hotHigh,
            fullScanAt: partialFullAt, didFullScan: false
        )
        storeMemory(snapshot)

        startBackgroundFill(
            roots: roots, hotLow: hotLow, ceiling: ceiling,
            probe: hotHigh, filledLow: 0, fullAt: partialFullAt
        )
        return snapshot
    }

    /// 把热点窗口以外的 id 补完：先高区（probe+1..ceiling），再低区
    /// （filledLow+1..hotLow-1）。每扫完一个 4M 窗口就落盘，进程被回收后
    /// 下一轮能从 filledLow/probe 继续，而不是重头再扫。
    private static func startBackgroundFill(
        roots: [String: [String: Int64]],
        hotLow: Int64,
        ceiling: Int64,
        probe: Int64,
        filledLow: Int64,
        fullAt: TimeInterval
    ) {
        DispatchQueue.global(qos: .utility).async {
            var merged = roots
            var low = filledLow
            var high = probe

            var cursor = high + 1
            while cursor <= ceiling {
                let last = min(cursor + 4_000_000 - 1, ceiling)
                merge(scanChildren(bases: bases, firstId: cursor, lastId: last), into: &merged)
                cursor = last + 1
                high = last
                saveCache(
                    probe: high, fullAt: fullAt, filledLow: low,
                    hotLow: hotLow, fullDone: false, roots: merged
                )
            }

            let lowEnd = max(0, hotLow - 1)
            cursor = low + 1
            while cursor <= lowEnd {
                let last = min(cursor + 4_000_000 - 1, lowEnd)
                merge(scanChildren(bases: bases, firstId: cursor, lastId: last), into: &merged)
                cursor = last + 1
                low = last
                saveCache(
                    probe: high, fullAt: fullAt, filledLow: low,
                    hotLow: hotLow, fullDone: false, roots: merged
                )
            }

            let doneAt = Date().timeIntervalSince1970
            saveCache(
                probe: ceiling, fullAt: doneAt, filledLow: lowEnd,
                hotLow: hotLow, fullDone: true, roots: merged
            )
            storeMemory(Result(
                roots: merged, probeInode: ceiling,
                fullScanAt: doneAt, didFullScan: true
            ))
            traceLog("scan: background fill finished — \(merged.values.reduce(0) { $0 + $1.count }) containers (low=\(low) high=\(high))")
        }
    }

    /// path 是否是 base 的直接子项（base 可能是 /private/var/... 写法）
    private static func belongs(_ path: String, to base: String) -> Bool {
        var normalized = base
        if normalized.hasPrefix("/private/var/") {
            normalized = String(normalized.dropFirst("/private".count))
        }
        guard path.hasPrefix(normalized + "/") else { return false }
        let rest = path.dropFirst(normalized.count + 1)
        return !rest.contains("/")
    }

    // MARK: - 给 ContainerStore 用的便捷入口

    /// 返回某个容器根下的直接子项路径（带磁盘缓存 + 增量扫描）。
    /// path 传 /var/... 或 /private/var/... 都可以。
    static func cachedEntries(for path: String) -> [String]? {
        var normalized = path
        while normalized.count > 1 && normalized.hasSuffix("/") { normalized.removeLast() }
        let lookup: String
        if normalized.hasPrefix("/var/") {
            lookup = "/private" + normalized
        } else {
            lookup = normalized
        }
        guard bases.contains(lookup) || bases.contains(normalized) else { return nil }

        let result = containerRoots()
        let key = bases.first { $0 == lookup || $0 == normalized }
        guard let key, let entries = result.roots[key] else { return nil }
        traceLog("enumerate: \(normalized) served from ContainerScan cache — \(entries.count) entries (full=\(result.didFullScan))")
        // 空结果也要如实返回 []，不能 nil：nil 会让调用方退回自己的 inode walk，
        // 于是两个 root 又各扫一遍全量。
        return entries.isEmpty ? [] : entries.keys.sorted()
    }

}
