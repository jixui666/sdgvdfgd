#!/usr/bin/env bash
# uuvpn 内嵌的 3105 legacy framework 重签脚本（macOS 上执行）
#
#   ./tools/resign_embedded_frameworks.sh Payload/uuvpn.app -
#   ./tools/resign_embedded_frameworks.sh /path/to/uuvpn.app "Apple Development: xxx (TEAMID)"
#
# 说明：两个 framework 内部二进制是 arm64 thin dylib，cryptid=0（已脱密），
# 只要重新签名即可 dlopen；不需要 --deep（已废弃），逐个签更可靠。
set -euo pipefail

APP="${1:-}"
IDENTITY="${2:--}"

if [ -z "$APP" ] || [ ! -d "$APP" ]; then
  echo "usage: $0 /path/to/uuvpn.app [codesign-identity]"
  exit 1
fi

FW="$APP/Frameworks"

for name in apptrace libapptracecore; do
  bundle="$FW/$name.framework"
  if [ ! -d "$bundle" ]; then
    echo "缺少 $bundle —— 先把 2/Frameworks/$name.framework 放进 app 的 Frameworks 目录"
    exit 1
  fi
  echo "== 重签 $bundle"
  codesign --force --sign "$IDENTITY" --timestamp=none "$bundle"
done

echo "== 重签主程序 $APP"
codesign --force --sign "$IDENTITY" --timestamp=none "$APP"

echo "== 校验签名"
codesign --verify --strict --verbose=2 "$APP"
for name in apptrace libapptracecore; do
  codesign --verify --strict --verbose=2 "$FW/$name.framework"
  echo -n "   $name 架构: "
  lipo -archs "$FW/$name.framework/$name"
done

echo "done"
