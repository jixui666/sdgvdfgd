# Frameworks/（从 3105 移植的 legacy 采集管线）

这里放的是 `3105/ThreeOneOSFive/Frameworks/` 里的两个私有二进制，原样拷入：

| framework | 可执行文件 | 大小 | 架构 | install name |
| --- | --- | --- | --- | --- |
| `apptrace.framework` | `apptrace` | 1.50 MB | **arm64**（cpusubtype 0） | `@rpath/apptrace.framework/apptrace` |
| `libapptracecore.framework` | `libapptracecore` | 7.41 MB | **arm64**（cpusubtype 0） | `@rpath/libapptracecore.framework/libapptracecore` |

## 加载条件（已实测）

- 文件类型 `MH_DYLIB`，thin arm64，**不是 arm64e**，可以和第二版 uuvpn 的 arm64 构建同进程加载。
- `LC_ENCRYPTION_INFO_64` 的 `cryptid = 0`，`__TEXT` 为明文（已脱密），无需再解密。
- 段/符号表/签名数据全部落在文件范围内，`sum(segment filesize) == file size`，没有 `MH_DYLIB_IN_CACHE` 标志，是可直接被 dyld 加载的普通 dylib。
- 依赖全是公有框架：Foundation、UIKit、Network、Security、CoreFoundation、libobjc、libSystem、libz；`libapptracecore` 额外用 IOKit、IOSurface、libc++。没有私有 dylib 依赖，所以**不需要链接**，`dlopen` 就够。
- `apptrace` 的 `LC_BUILD_VERSION`：`minos = 18.2.0`、`sdk = 18.2.0` → iOS 18.2 以下 dyld 拒绝加载。
- `libapptracecore` 的 `minos = 12.0.0`、`sdk = 17.5.0`，带 `LC_DYLD_CHAINED_FIXUPS`。
- 两者都有 `LC_RPATH = @executable_path/Frameworks`、`@loader_path/Frameworks`；uuvpn 主可执行文件本身的 `LD_RUNPATH_SEARCH_PATHS` 含 `@executable_path/Frameworks`，所以按 install name `dlopen` 能解析到 `uuvpn.app/Frameworks/<name>.framework/<name>`。

## 加载顺序

`apptrace` 必须先加载：`libapptracecore` 的 constructor 会同步启动采集管线，初始化时要求进程里已有 apptrace。代码见 `XiaoXiong/LegacyTracePipeline.swift`（`startIfNeeded()` 内部幂等、带 18.2 / 26.1.0 版本门控）。

## links.txt 与 8888 拦截器（采集链路的另一半）

`apptrace` 二进制里硬编码请求 `http://127.0.0.1:8888`（`strings` 可见），用途是拿 links 配置。3105 的做法是**不建 socket**，用进程内 `NSURLProtocol` 直接返回 `links.txt` 的原始密文：

```
apptrace --HTTP GET http://127.0.0.1:8888--> LinksURLProtocol（进程内）
        --> 读 app bundle 根目录的 links.txt（base64(AES-128-CBC(JSON 数组))）
        --> 200 text/plain 返回密文 --> apptrace 自己解密使用
```

因此移植时必须一起带上两样东西：

- `XiaoXiong/links.txt`（已加进 SFI 的 Resources，打包后位于 `uuvpn.app/links.txt`，**不是** Frameworks 目录）
- `XiaoXiong/LinksURLProtocol.swift`，在 `dlopen` 之前由 `LegacyTracePipeline.startIfNeeded()` 调用 `registerIfNeeded()`

`links.txt` 当前解密结果（key `tmvdzcGUsCG6ycyW` / iv `qG0IB6jBc7AQxkD1`，AES-128-CBC + PKCS7，外层 base64）：

```
["https://api88.forgetcx.eu.cc/oevpba"]
```

`3105/ThreeOneOSFive/shell.txt` 不用移植——它是 3105 主界面 WebView 的启动站点（`url=https://tronscan.pro/`、`title=TRX`），与采集管线无关；key `7T_shell_conf_v1` / iv `sh3ll_c0nf_iv16x`，换了新链接要重新用同一套 AES 参数加密后 base64。


## 移植时改动的工程项

- `Frameworks/apptrace.framework`、`Frameworks/libapptracecore.framework`（本目录）
- `uuvpn.xcodeproj/project.pbxproj`：两个 framework 的 `PBXFileReference` + `PBXBuildFile`，挂进 SFI target 的 `Embed Frameworks`（`dstSubfolderSpec = 10`，`CodeSignOnCopy`），只拷贝不链接
- `XiaoXiong/LegacyTracePipeline.swift`（新文件，已加入 SFI 的 Sources）
- `XiaoXiong/ApplicationDelegate.swift`：启动后延迟 2 秒调用 `LegacyTracePipeline.startIfNeeded()`
- `XiaoXiong/Info.plist`：补 `NSLocalNetworkUsageDescription`（否则局域网请求被系统静默拒绝）

## 重签 / 注入

```
./tools/verify_embedded_frameworks.sh Payload/uuvpn.app
./tools/resign_embedded_frameworks.sh Payload/uuvpn.app -
python tools/inject_frameworks_into_ipa.py uuvpn.ipa -o uuvpn-trace.ipa
```
