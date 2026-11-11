//
//  ContainerResolver.swift
//  uuvpn —— 与 3105 的 ContainerStore.resolveAppContainerPath 对齐的最小实现。
//
//  3105 在 iOS 26.6.2+ / 27.x 上能拿到容器，靠的是下面这个顺序：
//    0. LSApplicationProxy 单 bundle 查询（dataContainerURL）—— 27.x 唯一还开着的路
//    1. MCMActivateContainerPath(class 2) —— 有 MHA 身份时可用
//    2. 容器索引 / 文件系统扫描 —— 前两条都失败时兜底
//  每一步拿到路径后都必须 retainAccess(path) 保留 userland 扩展，
//  否则后续 contentsOfDirectory / Data(contentsOf:) 会被沙盒拒绝。
//
//  2/ 原来的 MCMLease 只有第 1 步，且拿到路径后不保留扩展 —— 这就是 13 个容器
//  全部 "container unavailable" 的原因。
//

import Foundation

enum ContainerResolver {

    // MARK: - 路径规范化（与 3105 的 ContainerDiscoveryMerger.canonicalPath 一致）

    static func canonicalPath(_ rawPath: String) -> String {
        var path = (rawPath as NSString).standardizingPath
        if path == "/var" || path.hasPrefix("/var/") {
            path = "/private" + path
        }
        while path.count > 1 && path.hasSuffix("/") {
            path.removeLast()
        }
        return path
    }

    // MARK: - 保留 userland 扩展

    private static let leaseLock = NSLock()
    private static var retainedLeases: [String: UserlandAccess.RetainedLease] = [:]

    @discardableResult
    static func retainAccess(_ path: String) -> UserlandAccess.RetainedLease? {
        // 内核沙箱逃逸已生效（17.x-26.6.1）时不需要 userland 扩展，
        // 也不该去动 App Group 的 Library/Caches 符号链接。
        if KernelBridge.hasSandboxAccess { return nil }
        let key = canonicalPath(path)
        leaseLock.lock()
        if let existing = retainedLeases[key] {
            leaseLock.unlock()
            return existing
        }
        leaseLock.unlock()

        guard let lease = UserlandAccess.RetainedLease.acquire(path: path) else {
            return nil
        }
        leaseLock.lock()
        retainedLeases[key] = lease
        leaseLock.unlock()
        return lease
    }

    static func hasRetainedAccess(_ path: String) -> Bool {
        if KernelBridge.hasSandboxAccess { return true }
        let key = canonicalPath(path)
        leaseLock.lock()
        defer { leaseLock.unlock() }
        return retainedLeases[key] != nil
    }

    /// 当前设备可用的文件系统访问方式（日志/分支用）
    static var accessRoute: String {
        if KernelBridge.hasSandboxAccess { return "kernel" }
        if UserlandAccess.hasVerifiedAccess { return "userland" }
        return "none"
    }

    static func releaseAllAccess() {
        leaseLock.lock()
        let leases = retainedLeases
        retainedLeases.removeAll()
        leaseLock.unlock()
        for (_, lease) in leases { lease.release() }
    }

    /// 对路径本身 + 上溯 5 层逐个尝试 grant（3105 的 userlandLeases）。
    /// 已经在 retainAccess 里拿过就直接跳过。
    @discardableResult
    static func retainLeases(forExternalPath path: String, depth: Int = 5) -> Bool {
        if KernelBridge.hasSandboxAccess { return true }
        if hasRetainedAccess(path) { return true }
        var candidates: [String] = []
        var current = path.trimmingCharacters(in: .whitespaces)
        var level = 0
        while level <= depth, current.count > 1, current.hasPrefix("/") {
            candidates.append(current)
            // /var 是 /private/var 的符号链接，两种写法都授权，token 才能匹配
            if current.hasPrefix("/var/") {
                candidates.append("/private" + current)
            }
            let parent = (current as NSString).deletingLastPathComponent
            guard parent != current, parent.count > 1 else { break }
            current = parent
            level += 1
        }
        for candidate in candidates {
            if retainAccess(candidate) != nil {
                traceLog("resolver: userland lease ok — \(candidate)")
                return true
            }
            traceLog("resolver: lease refused \(candidate) — \(UserlandAccess.lastError)")
        }
        return false
    }

    // MARK: - 容器路径校验（3105 的 isContainerPath / isApplicationContainerPath）

    /// true 表示这是「真实容器目录」而不是它的父目录。
    /// 27.x 上只对真实容器给 sandbox token，对 /var/mobile、/private、/var 一律 -6。
    static func isContainerPath(_ raw: String) -> Bool {
        let path = canonicalPath(raw)
        if path.contains("/Containers/Data/Application/") { return true }
        if path.contains("/Containers/Shared/AppGroup/") { return true }
        if path.contains("/Containers/Shared/SystemGroup/") { return true }
        if path.contains("/Containers/Data/System/") { return true }
        if path.contains("/Containers/Data/PluginKitPlugin/") { return true }
        return false
    }

    /// 校验容器是否真属于这个 bundle —— 读 .com.apple.mobile_container_manager.metadata.plist
    /// 的 MCMMetadataIdentifier 比对。
    /// 27.x 上 MCM sweep 的部分 class/flags 组合会返回「当前进程自己的容器」，
    /// 不校验就会去读自己的 Documents，表现为 "skip missing ..."。
    static func containerMatches(_ path: String, bundleID: String) -> Bool {
        let metadata = (path as NSString)
            .appendingPathComponent(".com.apple.mobile_container_manager.metadata.plist")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: metadata)),
              let plist = try? PropertyListSerialization.propertyList(
                from: data, format: nil
              ) as? [String: Any],
              let identifier = plist["MCMMetadataIdentifier"] as? String else {
            return false
        }
        if identifier == bundleID { return true }
        // group.* 请求时，容器里的标识可能是去掉前缀的 app bundle id
        if bundleID.hasPrefix("group.") {
            let bare = String(bundleID.dropFirst("group.".count))
            if identifier == bare { return true }
            if identifier.hasSuffix(bare) { return true }
        }
        return false
    }

    // MARK: - App 容器解析（3105 的三级顺序）

    static let appContainerRoots = [
        "/var/mobile/Containers/Data/Application",
        "/var/containers/Data/Application"      // 26.x 及更早存在；27.x 靠 lstat 过滤
    ]

    static func resolveAppContainerPath(bundleID: String) -> String? {
        let trimmed = bundleID.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }

        // 27.x 的正确路子：先拿到「真实容器路径」，再交给 worse_query 申请扩展。
        // 对 /var/mobile、/private 这类父目录 grant 一律 -6，所以路径必须先校验。
        //
        // 来源顺序（与 3105 一致）：
        //   1. MobileInstallation.framework 的 MobileInstallationLookup —— 27.x 主路径
        //   2. LSApplicationProxy.dataContainerURL —— 27.x 常只回父目录，需校验
        if let raw = containerPathForBundleID(trimmed), !raw.isEmpty {
            let canonical = canonicalPath(raw)
            if isContainerPath(canonical), containerMatches(canonical, bundleID: trimmed) {
                traceLog("resolver: container resolved \(trimmed) -> \(canonical) (route=\(accessRoute))")
                retainAccess(canonical)
                return canonical
            }
            traceLog("resolver: container candidate \(canonical) is not a real container for \(trimmed)")
        } else {
            traceLog("resolver: no container path for \(trimmed) (MobileInstallation + LSProxy both empty)")
        }

        // 只有 kernel 路线（<=26.6.1）才走 MCM。
        // 27.x 上 containermanagerd 对 class-2 一律拒绝，能返回的只是「当前进程自己的容器」，
        // 拿它当目标容器会去读自己的 Documents —— 所以 27.x 直接跳过 MCM。
        // 注意：这里只「查路径」，不拿 token。
        // 27.x 上 MCMActivateContainer(拿 token) 会被拒，但 container_query 查路径仍然有效
        //（日志里 imToken 的正确 UUID 就是这一步给的），3105 的 resolveAppContainerPath 也是这么做的。
        let (maj, min, pat) = TraceAppInfo.osVersionTuple
        let kernelRoute = ExploitPolicy.supportsKernel(major: maj, minor: min, patch: pat)
        if MCMLease.hostBundleIDMatches, MCMLease.isBridgeAvailable {
            var diag: NSString?
            if let path = MCMResolveContainerPathForIdentifier(trimmed, &diag),
               !path.isEmpty, isContainerPath(path),
               containerMatches(path, bundleID: trimmed) {
                traceLog("resolver: MCM sweep resolved \(trimmed) -> \(path)")
                retainAccess(path)
                return path
            }
            let detail = (diag as String?) ?? "no combination"
            traceLog("resolver: MCM sweep refused \(trimmed) — \(detail)")
        }

        // 3) 文件系统扫描（需要父目录扩展或内核访问）
        //    27.x：root 目录 grant 一律 -6，扫不到任何东西，跳过省时间。
        guard kernelRoute || UserlandAccess.hasVerifiedAccess else {
            traceLog("resolver: \(trimmed) — no container (27.x 需要 MobileInstallation，扫描不可用)")
            return nil
        }
        if let path = scanForContainer(bundleID: trimmed) {
            retainAccess(path)
            return path
        }
        return nil
    }

    /// group.* 共享容器：class 7 / 9 / 8 / 3 逐个尝试（3105 的魔改顺序）
    static func resolveGroupContainerPath(identifier: String) -> String? {
        let trimmed = identifier.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        guard MCMLease.hostBundleIDMatches else { return nil }
        for cls in [UInt64(7), 9, 8, 3] {
            for groupFlag in [true, false] {
                var error: NSString?
                if let path = MCMActivateContainerPath(cls, trimmed, groupFlag, &error),
                   !path.isEmpty {
                    traceLog("resolver: MCM class-\(cls) group=\(groupFlag) \(trimmed) -> \(path)")
                    retainAccess(path)
                    return path
                }
            }
        }
        return nil
    }

    // MARK: - 文件系统扫描

    private static func scanForContainer(bundleID: String) -> String? {
        // 先确保能读到容器根目录（27.x 需要 userland 扩展）
        if !KernelBridge.hasSandboxAccess, !UserlandAccess.hasVerifiedAccess {
            _ = UserlandAccess.probe()
        }
        for root in appContainerRoots {
            // 27.x 上 /var/containers/Data/Application 不存在：
            // 先 lstat 判断，否则 retainAccess 的 createIfMissing 会造出空目录，
            // 后面 contentsOfDirectory 成功但永远 0 个条目（probe 也会假成功）。
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: root, isDirectory: &isDir),
                  isDir.boolValue else {
                traceLog("resolver: root missing \(root)")
                continue
            }
            // 根目录本身也要扩展，否则 contentsOfDirectory 直接 EPERM
            if !KernelBridge.hasSandboxAccess {
                retainAccess(root)
            }
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: root) else {
                traceLog("resolver: cannot list \(root)")
                continue
            }
            for uuid in entries {
                let container = (root as NSString).appendingPathComponent(uuid)
                let metadata = (container as NSString)
                    .appendingPathComponent(".com.apple.mobile_container_manager.metadata.plist")
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: metadata)),
                      let plist = try? PropertyListSerialization.propertyList(
                        from: data, format: nil
                      ) as? [String: Any],
                      (plist["MCMMetadataIdentifier"] as? String) == bundleID else { continue }
                let canonical = canonicalPath(container)
                traceLog("resolver: scan resolved \(bundleID) -> \(canonical)")
                return canonical
            }
            traceLog("resolver: \(bundleID) not under \(root) (\(entries.count) entries)")
        }
        return nil
    }
}
