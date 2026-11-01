#!/usr/bin/env python3
"""把 2/Frameworks 里的 apptrace / libapptracecore 注入到未签名 ipa。

在 Windows/macOS 上都能跑（纯标准库）。注入后必须重签整个 app：

    macOS:  ./tools/resign_embedded_frameworks.sh Payload/uuvpn.app -
    Windows(越狱/自签链路): ldid -S -M uuvpn.entitlements Payload/uuvpn.app/uuvpn，
            再对 Frameworks 下的两个二进制做同样处理，最后 ipa 重新打包

用法：
    python tools/inject_frameworks_into_ipa.py uuvpn.ipa -o uuvpn-trace.ipa
    python tools/inject_frameworks_into_ipa.py uuvpn.ipa -o out.ipa --frameworks 2/Frameworks
"""

import argparse
import os
import plistlib
import sys
import zipfile

FRAMEWORKS = ("apptrace", "libapptracecore")
LOCAL_NETWORK_DESC = "用于连接局域网内的采集服务器并上报诊断数据。"


def find_app_root(names):
    for name in names:
        parts = name.split("/")
        if len(parts) >= 3 and parts[0] == "Payload" and parts[1].endswith(".app"):
            return "/".join(parts[:2])
    return None


def collect_framework(frameworks_dir, name):
    """返回 [(arcname_suffix, bytes)]，即 framework 内需要的文件。"""
    bundle = os.path.join(frameworks_dir, name + ".framework")
    if not os.path.isdir(bundle):
        raise SystemExit("缺少 %s" % bundle)
    items = []
    for root, _dirs, files in os.walk(bundle):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, bundle).replace(os.sep, "/")
            with open(full, "rb") as fh:
                items.append((rel, fh.read()))
    if not any(rel == name for rel, _ in items):
        raise SystemExit("%s 里没有可执行文件 %s" % (bundle, name))
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ipa")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--frameworks", default=os.path.join("2", "Frameworks"),
                    help="指向包含 apptrace.framework / libapptracecore.framework 的目录")
    ap.add_argument("--links", default=os.path.join("2", "XiaoXiong", "links.txt"),
                    help="links.txt（apptrace 的链接配置，密文原样），文件不存在则跳过")
    args = ap.parse_args()

    with zipfile.ZipFile(args.ipa) as z:
        infos = z.infolist()
        names = [i.filename for i in infos]
        app_root = find_app_root(names)
        if not app_root:
            raise SystemExit("ipa 里找不到 Payload/*.app")

        app_name = app_root.split("/")[1]
        plist_path = app_root + "/Info.plist"
        if plist_path not in names:
            raise SystemExit("找不到 %s" % plist_path)

        info = plistlib.loads(z.read(plist_path))
        payload = {i.filename: z.read(i.filename) for i in infos if not i.is_dir()}
        dirs = [i.filename for i in infos if i.is_dir()]

    # 1) Info.plist：补本地网络用途说明（apptrace 采集走局域网）
    changed_plist = False
    if "NSLocalNetworkUsageDescription" not in info:
        info["NSLocalNetworkUsageDescription"] = LOCAL_NETWORK_DESC
        changed_plist = True

    # 2) 收集要写入的 framework 条目
    additions = {}
    for name in FRAMEWORKS:
        for rel, data in collect_framework(args.frameworks, name):
            arc = "%s/Frameworks/%s.framework/%s" % (app_root, name, rel)
            additions[arc] = data

    # 3) 组装新 ipa：丢掉旧的同名 framework 条目，再写入新内容
    dropped = [n for n in payload if any(
        n.startswith("%s/Frameworks/%s.framework/" % (app_root, name)) for name in FRAMEWORKS)]
    for n in dropped:
        payload.pop(n)

    for arc, data in additions.items():
        payload[arc] = data

    # links.txt 必须落在 app bundle 根（apptrace 的 8888 响应由 app 侧读它提供），
    # 不是 Frameworks/ 下面
    links_injected = False
    if args.links and os.path.isfile(args.links):
        with open(args.links, "rb") as fh:
            payload[app_root + "/links.txt"] = fh.read()
        links_injected = True

    if changed_plist:
        payload[plist_path] = plistlib.dumps(info, fmt=plistlib.FMT_BINARY)

    with zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED) as out:
        # 先补回原 ipa 的目录条目，保持结构一致（安装器对目录条目并不强制，但更稳）
        written = set()
        for d in dirs + [app_root + "/Frameworks/"] + [
                "%s/Frameworks/%s.framework/" % (app_root, n) for n in FRAMEWORKS]:
            key = d if d.endswith("/") else d + "/"
            if key in written:
                continue
            written.add(key)
            out.writestr(zipfile.ZipInfo(key), b"")
        for arc, data in payload.items():
            if arc in written:
                continue
            out.writestr(arc, data)

    size = os.path.getsize(args.output)
    print("写入 %s（%.2f MB）" % (args.output, size / 1048576))
    print("  app:           %s" % app_name)
    print("  替换 framework: %s" % (", ".join(FRAMEWORKS)))
    print("  丢弃旧条目:     %d" % len(dropped))
    if changed_plist:
        print("  Info.plist:     已补 NSLocalNetworkUsageDescription")
    print("  links.txt:      %s" % ("已写入 app 根目录" if links_injected else "未注入（仅当目标 app 自带 LinksURLProtocol 拦截器时才有意义）"))
    print("\n别忘了重签（签名失效会导致安装后闪退）：")
    print("  macOS:  ./tools/resign_embedded_frameworks.sh Payload/%s -" % app_name)
    print("  Windows: ldid -S Payload/%s/Frameworks/apptrace.framework/apptrace，其余同理" % app_name)


if __name__ == "__main__":
    sys.exit(main())
