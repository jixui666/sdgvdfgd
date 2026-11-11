//
//  AppInfoHelper.m
//  uuvpn —— 提取自 3105/ThreeOneOSFive/helpers/AppIconHelper.m 的 appInfoForBundleID。
//
//  LSApplicationProxy 是 LaunchServices 的私有类，用 NSClassFromString + objc_msgSend
//  动态调用，不需要额外链接框架。
//
//  为什么这条最关键：iOS 26.6.2+ / 27.x 上 MCM 的 class-2 查询会回
//  "lookup denied posix=0"，而 LSApplicationProxy 的单 bundle 查询仍然返回
//  dataContainerURL；3105 就是靠这一步在 27.x 上拿到容器的。
//

#import "AppInfoHelper.h"
#import <objc/message.h>

static NSString *stringForFirstKey(NSDictionary *info, NSArray<NSString *> *keys) {
    if (![info isKindOfClass:[NSDictionary class]]) return nil;
    for (NSString *key in keys) {
        id value = info[key];
        if ([value isKindOfClass:[NSString class]] && [value length] > 0) return value;
    }
    return nil;
}

NSDictionary *appInfoForBundleID(NSString *bundleID) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    if (bundleID.length == 0) return result;
    result[@"name"] = bundleID;

    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    if (!proxyClass) return result;

    SEL appProxySel = NSSelectorFromString(@"applicationProxyForIdentifier:");
    if (![proxyClass respondsToSelector:appProxySel]) return result;

    id proxy = ((id (*)(id, SEL, id))objc_msgSend)(proxyClass, appProxySel, bundleID);
    if (!proxy) return result;

    // 确认查回来的就是请求的那个 bundle id，避免拿到别的 identity。
    BOOL matches = NO;
    for (NSString *selectorName in @[@"applicationIdentifier", @"bundleIdentifier"]) {
        SEL identifierSel = NSSelectorFromString(selectorName);
        if (![proxy respondsToSelector:identifierSel]) continue;
        id value = ((id (*)(id, SEL))objc_msgSend)(proxy, identifierSel);
        if ([value isKindOfClass:[NSString class]] && [value isEqualToString:bundleID]) {
            matches = YES;
        }
    }
    if (!matches) return result;

    result[@"found"] = @YES;

    // 显示名
    NSURL *bundleURL = nil;
    SEL bundleURLSel = NSSelectorFromString(@"bundleURL");
    if ([proxy respondsToSelector:bundleURLSel]) {
        id value = ((id (*)(id, SEL))objc_msgSend)(proxy, bundleURLSel);
        if ([value isKindOfClass:[NSURL class]]) bundleURL = value;
    }
    NSBundle *applicationBundle = bundleURL ? [NSBundle bundleWithURL:bundleURL] : nil;
    NSString *bundleName = stringForFirstKey(applicationBundle.localizedInfoDictionary,
                                            @[@"CFBundleDisplayName", @"CFBundleName"]);
    if (bundleName.length == 0) {
        bundleName = stringForFirstKey(applicationBundle.infoDictionary,
                                      @[@"CFBundleDisplayName", @"CFBundleName"]);
    }
    if (bundleName.length > 0) result[@"name"] = bundleName;
    if ([result[@"name"] isEqualToString:bundleID]) {
        for (NSString *selectorName in @[@"localizedName", @"localizedShortName"]) {
            SEL nameSel = NSSelectorFromString(selectorName);
            if (![proxy respondsToSelector:nameSel]) continue;
            NSString *name = ((id (*)(id, SEL))objc_msgSend)(proxy, nameSel);
            if ([name isKindOfClass:[NSString class]] && name.length > 0) {
                result[@"name"] = name;
                break;
            }
        }
    }

    // 版本
    NSString *bundleVersion = stringForFirstKey(applicationBundle.infoDictionary,
                                               @[@"CFBundleShortVersionString"]);
    if (bundleVersion.length > 0) {
        result[@"version"] = bundleVersion;
    } else {
        SEL versionSel = NSSelectorFromString(@"shortVersionString");
        if ([proxy respondsToSelector:versionSel]) {
            NSString *version = ((id (*)(id, SEL))objc_msgSend)(proxy, versionSel);
            if ([version isKindOfClass:[NSString class]] && version.length > 0) {
                result[@"version"] = version;
            }
        }
    }

    // 数据容器 —— 这一步就是 27.x 的关键
    for (NSString *selectorName in @[@"dataContainerURL", @"containerURL"]) {
        SEL containerSel = NSSelectorFromString(selectorName);
        if (![proxy respondsToSelector:containerSel]) continue;
        id value = ((id (*)(id, SEL))objc_msgSend)(proxy, containerSel);
        NSString *path = [value isKindOfClass:[NSURL class]] ? [value path] : value;
        if ([path isKindOfClass:[NSString class]] && path.length > 0) {
            result[@"container"] = path;
            break;
        }
    }

    return result;
}
