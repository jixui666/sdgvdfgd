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
    static let cacheVersion = 1
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
    ) -> (probe: Int64, fullAt: TimeInterval, roots: [String: [String: Int64]])? {
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
        let age = now - fullAt
        guard age >= 0, age < fullScanInterval else {
            traceLog("scan: cache rejected — weekly full scan due")
            return nil
        }
        for base in bases where rootsRaw[base] == nil {
            traceLog("scan: cache rejected — missing root \(base)")
            return nil
        }
        return (probe, fullAt, rootsRaw)
    }

    private static func saveCache(
        probe: Int64,
        fullAt: TimeInterval,
        roots: [String: [String: Int64]]
    ) {
        guard let path = cachePath else { return }
        let payload: [String: Any] = [
            "version": cacheVersion,
            "probe": probe,
            "fullAt": fullAt,
            "roots": roots
        ]
        if !(payload as NSDictionary).write(toFile: path, atomically: true) {
            traceLog("scan: cannot save container list to \(path)")
        }
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
        let buffer = UnsafeMutablePointer<[String: Int64]>.allocate(capacity: chunkCount)
        buffer.initialize(repeating: [:], count: chunkCount)
        defer {
            buffer.deinitialize(count: chunkCount)
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

    static func containerRoots(forceFull: Bool = false) -> Result {
        let now = Date().timeIntervalSince1970
        let ceiling = volumeMaxInode()
        traceLog("scan: volume bound=\(ceiling) workers<=4 chunk=\(chunkSize)")

        if !forceFull, let cache = loadCache(probeInode: ceiling, now: now) {
            let verified = verify(roots: cache.roots)
            var roots = verified.kept
            var probe = cache.probe
            traceLog("scan: cache hit probe=\(cache.probe) kept=\(verified.kept.values.reduce(0) { $0 + $1.count }) dropped=\(verified.dropped)")

            if ceiling > cache.probe {
                let fresh = scanChildren(
                    bases: bases, firstId: cache.probe + 1, lastId: ceiling
                )
                traceLog("scan: incremental \(cache.probe + 1)..\(ceiling) added=\(fresh.count)")
                for (path, inode) in fresh {
                    for base in bases where belongs(path, to: base) {
                        roots[base, default: [:]][path] = inode
                    }
                }
                probe = ceiling
                saveCache(probe: probe, fullAt: cache.fullAt, roots: roots)
            }
            return Result(
                roots: roots, probeInode: probe,
                fullScanAt: cache.fullAt, didFullScan: false
            )
        }

        let started = Date()
        let scanned = scanChildren(bases: bases, firstId: 1, lastId: ceiling)
        var roots: [String: [String: Int64]] = [:]
        for base in bases {
            roots[base] = [:]
        }
        for (path, inode) in scanned {
            for base in bases where belongs(path, to: base) {
                roots[base, default: [:]][path] = inode
            }
        }
        let elapsed = String(format: "%.1f", Date().timeIntervalSince(started))
        traceLog("scan: full 1..\(ceiling) — \(scanned.count) containers in \(elapsed)s")
        saveCache(probe: ceiling, fullAt: now, roots: roots)
        return Result(
            roots: roots, probeInode: ceiling, fullScanAt: now, didFullScan: true
        )
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
        return entries.keys.sorted()
    }

}
