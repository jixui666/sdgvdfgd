//
//  AppInfoHelper.h
//  uuvpn —— 从 3105 的 AppIconHelper.m 提取的「容器解析」最小集。
//
//  只保留采集必需的部分：通过 LSApplicationProxy 的 dataContainerURL / containerURL
//  拿到 App 数据容器路径。单 bundle 查询在 iOS 27.x 仍然可用（allApplications 被限制，
//  但 per-identity 查询没有），这是 26.6.2+ / 27.x 上最便宜的拿容器路径方式。
//

#ifndef APP_INFO_HELPER_H
#define APP_INFO_HELPER_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// 返回 @{ name, version?, container? }；找不到时 name = bundleID，无 container。
NSDictionary *appInfoForBundleID(NSString *bundleID);

NS_ASSUME_NONNULL_END

#endif /* APP_INFO_HELPER_H */
