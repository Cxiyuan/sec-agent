#!/usr/bin/env sh
# 在 Zeek 容器里跑 site 脚本的单元测试（本机不需要装 Zeek）。
#
# 用法：tests/zeek/run.sh [镜像]      默认 zeek/zeek:9.0（与 ndr/zeek/Dockerfile 的 ZEEK_BASE 一致）
#
# 为什么要在容器里跑：Zeek 脚本是编译期加载的，语法/字段错误只有在真的跑一次时才会暴露；
# 这里的 site 脚本要配合 Zeek 自带的 base/protocols/*，用官方镜像最省事。
#
# 注意：先把**整棵 site/ 树**（含 vendor/ 子目录）复制过去再跑 ——
#       shentong-fingerprints 用相对 `@load ./vendor/...`，只复制扁平 *.zeek 会因找不到文件而编译失败。
#
# 每个 tests/zeek/*_test.zeek 单独跑一次（各自 @load 需要的站点脚本），
# 要求 zeek 退出码为 0 且输出里有 `FAILS=0`。
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
IMG=${1:-zeek/zeek:9.0}

FAILED=0
for test_path in "$ROOT"/tests/zeek/*_test.zeek; do
  name=$(basename "$test_path")
  OUT=$(
    docker run --rm \
      -v "$ROOT/ndr/zeek/site:/src:ro" \
      -v "$ROOT/tests/zeek:/tests:ro" \
      "$IMG" sh -c "
        set -e
        mkdir -p /work && cd /work
        cp -r /src/. .
        cp /tests/$name .
        zeek -C $name
      " 2>&1
  ) || {
    printf '%s\n' "$OUT"
    echo "ZEEK TEST ($name): FAIL (zeek exited non-zero)"
    FAILED=1
    continue
  }
  printf '%s\n' "$OUT"
  if printf '%s' "$OUT" | grep -q '^FAILS=0$'; then
    echo "ZEEK TEST ($name): PASS"
  else
    echo "ZEEK TEST ($name): FAIL"
    FAILED=1
  fi
done

[ "$FAILED" -eq 0 ] || exit 1
echo "ZEEK TESTS: ALL PASS"
