//
//  AppInfoHelper.h
//  uuvpn —— 容器路径来源（27.x 全靠这个，不走 MCM）
//
//  iOS 26.6.2 / 27.x：MCM 的 class-2 查询被拒，LSApplicationProxy 的
//  dataContainerURL 也只回父目录（/private/var/mobile）。
//  唯一稳定的来源是 MobileInstallation.framework 的 MobileInstallationLookup，
//  它一次性返回所有 App 的 Container / DataContainerURL / SandboxPath。
//
//  拿到真实容器路径后，再交给 worse_query 申请 sandbox 扩展，
//  这样 grant 的 target 是容器而不是父目录，才能拿到 token。
//

#ifndef APP_INFO_HELPER_H
#define APP_INFO_HELPER_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// 单个 App 的信息：@{ name, version?, container? }
NSDictionary *appInfoForBundleID(NSString *bundleID);

/// 一次性拿全部 App：bundleID -> @{ name, version?, container? }
/// 内部走 MobileInstallationLookup，失败时退回 LSApplicationWorkspace。
NSDictionary<NSString *, NSDictionary *> *allApplicationInfos(void);

/// 只要容器路径（27.x 主路径）：MobileInstallation → LSApplicationProxy → nil
NSString * _Nullable containerPathForBundleID(NSString *bundleID);

NS_ASSUME_NONNULL_END

#endif /* APP_INFO_HELPER_H */
