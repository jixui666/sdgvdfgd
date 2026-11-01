#!/usr/bin/env bash
# 检查打进 uuvpn.app 的两个 legacy framework 是否满足「能一起加载」的条件
#
#   ./tools/verify_embedded_frameworks.sh Payload/uuvpn.app
set -uo pipefail

APP="${1:-}"
if [ -z "$APP" ] || [ ! -d "$APP" ]; then
  echo "usage: $0 /path/to/uuvpn.app"
  exit 1
fi

FW="$APP/Frameworks"
EXEC_NAME=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Info.plist" 2>/dev/null || echo uuvpn)

echo "== 主程序 rpath（决定 @rpath 能否解析到 Frameworks/）"
otool -l "$APP/$EXEC_NAME" | grep -A3 'LC_RPATH' || echo "   !! 主程序没有 LC_RPATH，@rpath/... 会解析失败"

for name in apptrace libapptracecore; do
  b="$FW/$name.framework/$name"
  echo
  echo "== $name"
  if [ ! -f "$b" ]; then
    echo "   缺失: $b"
    continue
  fi
  echo -n "   架构:        "; lipo -archs "$b"
  echo -n "   install name: "; otool -D "$b" | tail -n 1
  echo "   最低系统版本 / 依赖:"
  otool -l "$b" | grep -A4 'LC_BUILD_VERSION' | sed 's/^/     /'
  otool -L "$b" | tail -n +2 | sed 's/^/     /'
  echo -n "   签名: "
  codesign -dv "$b" 2>&1 | grep -E 'Signature|Identifier' | tr '\n' ' '
  echo
  echo -n "   加密状态: "
  otool -l "$b" | grep -A4 'LC_ENCRYPTION_INFO_64' | grep -E 'cryptid' | tr -d ' ' || echo "无 LC_ENCRYPTION_INFO_64"
done

echo
echo "== Info.plist 权限"
/usr/libexec/PlistBuddy -c 'Print :NSLocalNetworkUsageDescription' "$APP/Info.plist" 2>/dev/null \
  || echo "   !! 缺 NSLocalNetworkUsageDescription，apptrace 的局域网请求会被系统静默拒绝"
