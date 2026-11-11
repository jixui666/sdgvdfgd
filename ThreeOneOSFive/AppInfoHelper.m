//
//  AppInfoHelper.m
//  uuvpn —— 移植自 3105/ThreeOneOSFive/helpers/AppIconHelper.m
//
//  容器路径的三级来源（顺序与 3105 一致）：
//    1. MobileInstallation.framework → MobileInstallationLookup
//       —— 27.x 唯一能拿到「真实容器路径」的路，无需 MCM、无需 App Group
//    2. LSApplicationProxy.dataContainerURL / containerURL
//       —— 27.x 上常只回父目录（/private/var/mobile），必须校验再用
//    3. LSApplicationWorkspace.allApplications（整体枚举）
//
//  为什么重要：worse_query 的 target 必须是真实容器目录。
//  对 /var/mobile、/private 这类父目录 grant 一律回 -6（no sandbox token）。
//

#import "AppInfoHelper.h"
#import <objc/message.h>
#import <dlfcn.h>

#pragma mark - 取值工具

static NSString *stringForFirstKey(NSDictionary *info, NSArray<NSString *> *keys) {
    if (![info isKindOfClass:[NSDictionary class]]) return nil;
    for (NSString *key in keys) {
        id value = info[key];
        if ([value isKindOfClass:[NSString class]] && [value length] > 0) return value;
    }
    return nil;
}

static NSString *pathForFirstKey(NSDictionary *info, NSArray<NSString *> *keys) {
    if (![info isKindOfClass:[NSDictionary class]]) return nil;
    for (NSString *key in keys) {
        id value = info[key];
        if ([value isKindOfClass:[NSURL class]]) {
            NSString *path = [value path];
            if (path.length > 0) return path;
            continue;
        }
        if ([value isKindOfClass:[NSString class]] && [value length] > 0) return value;
    }
    return nil;
}

/// 容器路径的键，与 3105 完全一致
static NSString *containerFromInfo(NSDictionary *info) {
    return pathForFirstKey(info, @[
        @"Container", @"DataContainer", @"DataContainerURL", @"ContainerPath", @"SandboxPath"
    ]);
}

static void addApplicationInfo(NSMutableDictionary *result,
                               NSString *fallbackBundleID,
                               NSDictionary *info) {
    if (![info isKindOfClass:[NSDictionary class]]) return;
    NSString *bundleID = stringForFirstKey(info, @[
        @"CFBundleIdentifier", @"BundleIdentifier", @"ApplicationIdentifier", @"MCMMetadataIdentifier"
    ]);
    if (bundleID.length == 0) bundleID = fallbackBundleID;
    if (bundleID.length == 0) return;

    NSMutableDictionary *entry = [NSMutableDictionary dictionary];
    NSString *name = stringForFirstKey(info, @[
        @"CFBundleDisplayName", @"CFBundleName", @"LocalizedName", @"Name"
    ]);
    entry[@"name"] = name.length > 0 ? name : bundleID;

    NSString *container = containerFromInfo(info);
    if (container.length > 0) entry[@"container"] = container;

    NSString *version = stringForFirstKey(info, @[
        @"CFBundleShortVersionString", @"BundleShortVersionString"
    ]);
    if (version.length > 0) entry[@"version"] = version;

    result[bundleID] = entry;
}

#pragma mark - 1) MobileInstallation（27.x 主路径）

static void *mobileInstallationHandle(void) {
    static void *handle;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        handle = dlopen("/System/Library/PrivateFrameworks/MobileInstallation.framework/MobileInstallation",
                        RTLD_LAZY | RTLD_LOCAL);
    });
    return handle;
}

static NSDictionary *appsFromMobileInstallation(void) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    void *frameworkHandle = mobileInstallationHandle();

    // 老系统导出了原符号；新系统只给新版 symbol 或需要 dlopen 后取。
    void *lookupFn = dlsym(RTLD_DEFAULT, "MobileInstallationLookup");
    if (!lookupFn && frameworkHandle) {
        lookupFn = dlsym(frameworkHandle, "MobileInstallationLookup");
    }
    if (!lookupFn) {
        NSLog(@"[uuvpn] mi: MobileInstallationLookup unavailable");
        return result;
    }

    NSDictionary *apps = nil;
    NSArray *optionSets = @[
        @{@"ApplicationType": @"Any"},
        @{@"ApplicationType": @"User"},
        @{@"ApplicationType": @"System"},
        @{},
    ];
    for (NSDictionary *options in optionSets) {
        apps = ((NSDictionary *(*)(NSDictionary *, void *))lookupFn)(options, NULL);
        if (apps && [apps isKindOfClass:[NSDictionary class]] && apps.count > 0) break;
    }
    if (!apps || apps.count == 0) {
        NSLog(@"[uuvpn] mi: lookup returned empty");
        return result;
    }

    // 诊断：把第一个 app 的原始键名列出来，27.x 的键名可能和 26.x 不同
    NSString *sampleKey = apps.allKeys.firstObject;
    if (sampleKey) {
        id sample = apps[sampleKey];
        if ([sample isKindOfClass:[NSDictionary class]]) {
            NSLog(@"[uuvpn] mi: sample %@ keys = %@", sampleKey,
                  [[(NSDictionary *)sample allKeys] componentsJoinedByString:@","]);
        } else {
            NSLog(@"[uuvpn] mi: sample %@ class = %@", sampleKey, [sample class]);
        }
    }

    NSUInteger withContainer = 0;
    for (NSString *bundleID in apps) {
        @autoreleasepool {
            addApplicationInfo(result, bundleID, apps[bundleID]);
            if (result[bundleID][@"container"]) withContainer++;
        }
    }
    NSLog(@"[uuvpn] mi: %lu apps, %lu with container",
          (unsigned long)result.count, (unsigned long)withContainer);
    return result;
}

#pragma mark - 2) LSApplicationProxy 单 bundle

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

    SEL bundleURLSel = NSSelectorFromString(@"bundleURL");
    NSURL *bundleURL = nil;
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

#pragma mark - 3) LSApplicationWorkspace 整体枚举

static void ensureLaunchServicesLoaded(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        const char *candidates[] = {
            "/System/Library/Frameworks/CoreServices.framework/CoreServices",
            "/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices",
            "/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices",
        };
        for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
            if (dlopen(candidates[i], RTLD_LAZY | RTLD_GLOBAL)) return;
        }
    });
}

static NSDictionary *appsFromWorkspace(void) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    ensureLaunchServicesLoaded();

    Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    if (!workspaceClass) return result;
    SEL defaultWorkspaceSel = NSSelectorFromString(@"defaultWorkspace");
    if (![workspaceClass respondsToSelector:defaultWorkspaceSel]) return result;
    id workspace = ((id (*)(id, SEL))objc_msgSend)(workspaceClass, defaultWorkspaceSel);
    if (!workspace) return result;

    NSArray *apps = nil;
    for (NSString *selectorName in @[@"allApplications", @"allInstalledApplications"]) {
        SEL allAppsSel = NSSelectorFromString(selectorName);
        if (![workspace respondsToSelector:allAppsSel]) continue;
        id candidate = ((id (*)(id, SEL))objc_msgSend)(workspace, allAppsSel);
        if ([candidate isKindOfClass:[NSArray class]] && [candidate count] > 0) {
            apps = candidate;
            break;
        }
    }
    if (!apps) return result;

    for (id proxy in apps) {
        @autoreleasepool {
            SEL identifierSel = NSSelectorFromString(@"applicationIdentifier");
            if (![proxy respondsToSelector:identifierSel]) continue;
            NSString *bundleID = ((id (*)(id, SEL))objc_msgSend)(proxy, identifierSel);
            if (![bundleID isKindOfClass:[NSString class]] || bundleID.length == 0) continue;

            NSMutableDictionary *entry = [NSMutableDictionary dictionary];
            entry[@"name"] = bundleID;
            for (NSString *selectorName in @[@"dataContainerURL", @"containerURL"]) {
                SEL containerSel = NSSelectorFromString(selectorName);
                if (![proxy respondsToSelector:containerSel]) continue;
                id value = ((id (*)(id, SEL))objc_msgSend)(proxy, containerSel);
                NSString *path = [value isKindOfClass:[NSURL class]] ? [value path] : value;
                if ([path isKindOfClass:[NSString class]] && path.length > 0) {
                    entry[@"container"] = path;
                    break;
                }
            }
            result[bundleID] = entry;
        }
    }
    return result;
}


#pragma mark - 与 3105 同签名：workspace 优先，MobileInstallation 兜底

NSDictionary<NSString *, NSDictionary *> *installedAppInfo(void) {
    NSDictionary *workspace = appsFromWorkspace();
    if (workspace.count > 0) return workspace;
    NSDictionary *mobileInstallation = appsFromMobileInstallation();
    NSLog(@"[uuvpn] ls: workspace empty; MobileInstallation=%lu",
          (unsigned long)mobileInstallation.count);
    return mobileInstallation;
}

#pragma mark - 对外

NSDictionary<NSString *, NSDictionary *> *allApplicationInfos(void) {
    NSDictionary *fromMI = appsFromMobileInstallation();
    if (fromMI.count > 0) return fromMI;
    NSDictionary *fromWorkspace = appsFromWorkspace();
    if (fromWorkspace.count > 0) return fromWorkspace;
    return @{};
}

NSString * _Nullable containerPathForBundleID(NSString *bundleID) {
    if (bundleID.length == 0) return nil;

    // 1) MobileInstallation：27.x 主路径
    NSDictionary *all = allApplicationInfos();
    NSDictionary *entry = all[bundleID];
    if ([entry isKindOfClass:[NSDictionary class]]) {
        NSString *container = entry[@"container"];
        if ([container isKindOfClass:[NSString class]] && container.length > 1) {
            return container;
        }
    }

    // 2) LSApplicationProxy 单 bundle
    NSDictionary *single = appInfoForBundleID(bundleID);
    NSString *container = single[@"container"];
    if ([container isKindOfClass:[NSString class]] && container.length > 1) {
        return container;
    }
    return nil;
}
