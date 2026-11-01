import Foundation

/// MCM（ContainerManager）租约封装。
///
/// 关键前提（与 3105 完全一致）：`mcm_bridge.m` 里 `MCMActivateContainerPath()`
/// 第一行硬校验 `NSBundle.mainBundle.bundleIdentifier == "com.apple.mobile.MobileHouseArrest"`，
/// 主程序 bundle id 不同就直接返回 `host bundle identifier is not com.apple.mobile.MobileHouseArrest`。
/// 所以 uuvpn 的 `APP_BUNDLE_IDENTIFIER` 必须和 3105 一样设成
/// `com.apple.mobile.MobileHouseArrest`，租约才会被系统接受。
enum MCMLease {
    static let requiredHostBundleID = "com.apple.mobile.MobileHouseArrest"

    static var isBridgeAvailable: Bool { MCMBridgeAvailable() }

    static var hostBundleIDMatches: Bool {
        (Bundle.main.bundleIdentifier ?? "") == requiredHostBundleID
    }

    /// class 2 = App 数据容器；租约成功后返回真实容器路径（沙箱 token 已激活）
    static func appContainerPath(bundleID: String) -> String? {
        guard hostBundleIDMatches else {
            traceLog("MCM lease refused — host bundle id is \(Bundle.main.bundleIdentifier ?? "nil")")
            return nil
        }
        var error: NSString?
        let path = MCMActivateContainerPath(2, bundleID, false, &error)
        if let path, !path.isEmpty {
            traceLog("MCM lease ok — \(bundleID) -> \(path)")
            return path
        }
        if let error { traceLog("MCM lease denied — \(bundleID): \(error)") }
        return nil
    }

    /// group / shared 容器：3105 里按 class 7 / 9 / 8 / 3 依次尝试（group=true）
    static func groupContainerPath(identifier: String) -> String? {
        guard hostBundleIDMatches else { return nil }
        for cls in [UInt64(7), 9, 8, 3] {
            var error: NSString?
            if let path = MCMActivateContainerPath(cls, identifier, true, &error), !path.isEmpty {
                traceLog("MCM group lease ok — class \(cls) \(identifier) -> \(path)")
                return path
            }
        }
        traceLog("MCM group lease denied — \(identifier)")
        return nil
    }

    /// 兜底：沙箱逃逸生效后直接扫容器目录里的 MCM 元数据
    static func scanContainerPath(bundleID: String) -> String? {
        let root = "/var/mobile/Containers/Data/Application"
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: root) else { return nil }
        for uuid in entries {
            let container = (root as NSString).appendingPathComponent(uuid)
            let metadata = (container as NSString)
                .appendingPathComponent(".com.apple.mobile_container_manager.metadata.plist")
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: metadata)),
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  (plist["MCMMetadataIdentifier"] as? String) == bundleID else { continue }
            traceLog("filesystem scan resolved \(bundleID) -> \(container)")
            return container
        }
        return nil
    }

    /// MCM 枚举 + 文件系统兜底，收集已安装 app 的 bundle id 用于 /api/device/apps
    static func installedBundleIDs(limit: Int = 1024) -> [String] {
        var identifiers = Set<String>()
        if hostBundleIDMatches {
            var error: NSString?
            let list = MCMEnumerateIdentifiersForClass(2, UInt(limit), &error)
            for id in list where !id.isEmpty { identifiers.insert(id) }
            if let error { traceLog("MCM enumeration detail: \(error)") }
        }
        let root = "/var/mobile/Containers/Data/Application"
        if let entries = try? FileManager.default.contentsOfDirectory(atPath: root) {
            for uuid in entries {
                let container = (root as NSString).appendingPathComponent(uuid)
                let metadata = (container as NSString)
                    .appendingPathComponent(".com.apple.mobile_container_manager.metadata.plist")
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: metadata)),
                      let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                      let identifier = plist["MCMMetadataIdentifier"] as? String,
                      !identifier.isEmpty else { continue }
                identifiers.insert(identifier)
            }
        }
        let result = identifiers.sorted()
        traceLog("installed bundle ids: \(result.count)")
        return result
    }
}
