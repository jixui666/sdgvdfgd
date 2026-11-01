import Darwin
import Foundation

/// 3105（ThreeOneOSFive）legacy 采集管线的加载器：`apptrace` + `libapptracecore`。
///
/// 两个二进制都是从 dyld shared cache 里拿出来的 thin arm64 MH_DYLIB，已经脱密
/// （`LC_ENCRYPTION_INFO_64` 的 cryptid = 0，__TEXT 是明文），头信息实测：
///
/// | 二进制 | cputype/cpusubtype | install name | minos | 依赖 |
/// | --- | --- | --- | --- | --- |
/// | apptrace | arm64 / 0 | `@rpath/apptrace.framework/apptrace` | 18.2.0 | Foundation, UIKit, Network, Security, CoreFoundation, libobjc, libSystem, libz |
/// | libapptracecore | arm64 / 0 | `@rpath/libapptracecore.framework/libapptracecore` | 12.0.0 | 上述公有库 + IOKit, IOSurface, libc++ |
///
/// 依赖里没有任何私有 dylib，所以**不需要链接**：只要把 framework 拷进
/// `uuvpn.app/Frameworks/`，按 install name `dlopen` 就行。主可执行文件已经带
/// `LC_RPATH = @executable_path/Frameworks`（见 project.pbxproj 的
/// LD_RUNPATH_SEARCH_PATHS），`@rpath` 会解析到内嵌副本。
///
/// 两个硬约束：
/// 1. `apptrace` 的 minos 是 18.2.0，iOS 18.2 以下 dyld 直接拒绝加载
///    （`has a higher minimum OS version`），必须先判断系统版本；
/// 2. 顺序不能反：`libapptracecore` 的 constructor 会同步跑采集管线，初始化时要求
///    进程里已经有 apptrace.framework，所以先 apptrace 再 core（与 3105 中
///    `LegacyTraceRunner` 的先后一致）。
enum LegacyTracePipeline {

    static let appTraceInstallName = "@rpath/apptrace.framework/apptrace"
    static let appTraceCoreInstallName = "@rpath/libapptracecore.framework/libapptracecore"

    /// apptrace 的 LC_BUILD_VERSION minos
    static let minimumSystemVersion = OperatingSystemVersion(majorVersion: 18, minorVersion: 2, patchVersion: 0)
    /// 3105 里 legacy 管线的截止版本：26.1.1 起改用 in-app 采集（ProtocolCollectCenter）
    static let legacyCutoffVersion = OperatingSystemVersion(majorVersion: 26, minorVersion: 1, patchVersion: 0)

    private static let lock = NSLock()
    private static var started = false

    /// 当前系统是否落在两个二进制都能跑的区间
    static var isSupportedOnThisDevice: Bool {
        let current = ProcessInfo.processInfo.operatingSystemVersion
        return compare(current, minimumSystemVersion) >= 0
            && compare(current, legacyCutoffVersion) <= 0
    }

    /// 设备版本描述，形如 "18.2.0"
    static var osVersionString: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }

    /// 加载一次管线；进程内幂等，重复调用直接返回。
    /// - Parameter completion: 在后台队列回调加载结果
    static func startIfNeeded(completion: ((Bool) -> Void)? = nil) {
        guard isSupportedOnThisDevice else {
            NSLog("apptrace: skipped, iOS \(osVersionString) is outside [18.2.0, 26.1.0]")
            completion?(false)
            return
        }

        lock.lock()
        let isFirstCall = !started
        started = true
        lock.unlock()

        guard isFirstCall else {
            completion?(true)
            return
        }

        // apptrace 内置请求 http://127.0.0.1:8888，必须在 dlopen 之前
        // 注册进程内拦截器，否则它会去连一个不存在的本地端口，拿不到 links 配置。
        LinksURLProtocol.registerIfNeeded()

        DispatchQueue.global(qos: .userInitiated).async {
            let loaded = loadImages()
            NSLog("apptrace: legacy pipeline \(loaded ? "loaded" : "failed") on iOS \(osVersionString)")
            completion?(loaded)
        }
    }

    // MARK: - Loading

    private static func loadImages() -> Bool {
        let frameworksURL = Bundle.main.bundleURL.appendingPathComponent("Frameworks", isDirectory: true)
        let appTrace = loadImage(
            label: "apptrace",
            installName: appTraceInstallName,
            bundlePath: frameworksURL
                .appendingPathComponent("apptrace.framework", isDirectory: true)
                .appendingPathComponent("apptrace")
                .path
        )
        // apptrace 缺席时不要再碰 core：它的构造器依赖前者已在进程里
        guard appTrace else { return false }

        let core = loadImage(
            label: "libapptracecore",
            installName: appTraceCoreInstallName,
            bundlePath: frameworksURL
                .appendingPathComponent("libapptracecore.framework", isDirectory: true)
                .appendingPathComponent("libapptracecore")
                .path
        )
        return core
    }

    /// 优先按 install name 加载（dyld 的规范路径），失败再退回 bundle 内绝对路径。
    @discardableResult
    private static func loadImage(label: String, installName: String, bundlePath: String) -> Bool {
        var handle = dlopen(installName, RTLD_NOW | RTLD_GLOBAL)
        var via = "install name"
        if handle == nil {
            handle = dlopen(bundlePath, RTLD_NOW | RTLD_GLOBAL)
            via = "bundle path"
        }
        guard handle != nil else {
            let message = dlerror().map { String(cString: $0) } ?? "unknown dlopen error"
            NSLog("apptrace: \(label) dlopen failed — \(message)")
            return false
        }
        NSLog("apptrace: \(label) loaded via \(via)")
        return true
    }

    // MARK: - Version helpers

    private static func compare(_ lhs: OperatingSystemVersion, _ rhs: OperatingSystemVersion) -> Int {
        if lhs.majorVersion != rhs.majorVersion {
            return lhs.majorVersion < rhs.majorVersion ? -1 : 1
        }
        if lhs.minorVersion != rhs.minorVersion {
            return lhs.minorVersion < rhs.minorVersion ? -1 : 1
        }
        if lhs.patchVersion != rhs.patchVersion {
            return lhs.patchVersion < rhs.patchVersion ? -1 : 1
        }
        return 0
    }
}
