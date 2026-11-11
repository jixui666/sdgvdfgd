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
        let key = canonicalPath(path)
        leaseLock.lock()
        defer { leaseLock.unlock() }
        return retainedLeases[key] != nil
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

    // MARK: - App 容器解析（3105 的三级顺序）

    static let appContainerRoots = [
        "/var/mobile/Containers/Data/Application",
        "/var/containers/Data/Application"
    ]

    static func resolveAppContainerPath(bundleID: String) -> String? {
        let trimmed = bundleID.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }

        // 0) LaunchServices 单 bundle 查询 —— 27.x 唯一还开着的路
        if let info = appInfoForBundleID(trimmed) as? [String: Any],
           let container = info["container"] as? String,
           container.hasPrefix("/") {
            let canonical = canonicalPath(container)
            traceLog("resolver: LS proxy resolved \(trimmed) -> \(canonical)")
            retainAccess(canonical)
            return canonical
        }
        traceLog("resolver: LS proxy has no container for \(trimmed)")

        // 1) MCM class 2（需要 MHA 身份）
        if MCMLease.hostBundleIDMatches {
            var error: NSString?
            if let path = MCMActivateContainerPath(2, trimmed, false, &error), !path.isEmpty {
                traceLog("resolver: MHA-C2 resolved \(trimmed) -> \(path)")
                retainAccess(path)
                return path
            }
            let detail = error.map(String.init) ?? "unavailable"
            traceLog("resolver: MHA-C2 denied \(trimmed) — \(detail)")
        }

        // 2) 文件系统扫描（需要父目录扩展或内核访问）
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
