#!/usr/bin/env sh
# 在 Zeek 容器里跑 site 脚本的单元测试（本机不需要装 Zeek）。
#
# 用法：tests/zeek/run.sh [镜像]      默认 zeek/zeek:9.0（与 ndr/zeek/Dockerfile 的 ZEEK_BASE 一致）
#
# 为什么要在容器里跑：Zeek 脚本是编译期加载的，语法/字段错误只有在真的跑一次时才会暴露；
# 这里的 site 脚本要配合 Zeek 自带的 base/protocols/*，用官方镜像最省事。
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
IMG=${1:-zeek/zeek:9.0}

OUT=$(
  docker run --rm \
    -v "$ROOT/ndr/zeek/site:/src:ro" \
    -v "$ROOT/tests/zeek:/tests:ro" \
    "$IMG" sh -c '
      set -e
      mkdir -p /work && cd /work
      cp /src/*.zeek . && cp /tests/hb_test.zeek .
      zeek -C hb_test.zeek
    ' 2>&1
)

printf '%s\n' "$OUT"
if printf '%s' "$OUT" | grep -q '^FAILS=0$'; then
  echo "ZEEK TEST: PASS"
else
  echo "ZEEK TEST: FAIL"
  exit 1
fi
