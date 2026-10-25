#!/usr/bin/env bash
# 本地开发 venv 一键准备（macOS / Linux 通用）。
#
# 为什么要这个脚本（2026-10 换开发机踩到）：原来仓库里的 `.venv` 是 Linux 上建的
# （`pyvenv.cfg` 的 home 指向 /home/...linux-x86_64-gnu），换到 macOS 后**完全用不了**；
# 而项目要求 Python >=3.11,<3.13，macOS 自带的是 3.9。手工重装的步骤又多（依赖要从两个
# pyproject 里拼），所以固化成一条命令，谁换机器都是同一套流程。
#
# 用法：
#   bash scripts/dev-venv.sh          # 建/修 .venv 并装依赖（可重复执行）
#   bash scripts/dev-venv.sh --check  # 只检查 .venv 是否可用，不动它
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VENV="$ROOT/.venv"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

die() { echo "✘ $*" >&2; exit 1; }

# ---------- 1. 判断现有 .venv 能不能用（跨机器 copy 过来的会指向不存在的解释器） ----------
venv_ok() {
  [ -x "$VENV/bin/python" ] || return 1
  "$VENV/bin/python" -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 11) or sys.version_info[:2] == (3, 12) else 1)' 2>/dev/null || return 1
  # pyvenv.cfg 的 home 必须真的存在（Linux→macOS 搬过来时这里就断了）
  local home
  home="$(sed -n 's/^home = //p' "$VENV/pyvenv.cfg" 2>/dev/null || true)"
  [ -n "$home" ] && [ -e "$home" ] || return 1
  return 0
}

if venv_ok; then
  echo "✔ .venv 可用：$("$VENV/bin/python" -V 2>&1)"
  [ "$CHECK_ONLY" = "1" ] && exit 0
else
  [ "$CHECK_ONLY" = "1" ] && die ".venv 不可用（换机器后需重建）：跑 bash scripts/dev-venv.sh"
  echo "… .venv 不可用（或不存在），重建"
  rm -rf "$VENV"
fi

# ---------- 2. 找 Python 3.11/3.12：优先 uv，其次系统里的版本化解释器 ----------
UV="$(command -v uv || true)"
[ -z "$UV" ] && [ -x "$HOME/.local/bin/uv" ] && UV="$HOME/.local/bin/uv"
PY=""
if [ -n "$UV" ]; then
  echo "… 用 uv 准备 Python 3.11"
  "$UV" python install 3.11 >/dev/null 2>&1 || true
  "$UV" venv --python 3.11 "$VENV" >/dev/null
  PY="$VENV/bin/python"
else
  for cand in python3.12 python3.11; do
    if command -v "$cand" >/dev/null 2>&1; then
      PY="$(command -v "$cand")"
      break
    fi
  done
  [ -n "$PY" ] || die "本机没有 Python 3.11/3.12。装一个（brew install python@3.12），或装 uv 后重跑本脚本。"
  echo "… 用 $PY 建 venv"
  "$PY" -m venv "$VENV"
  PY="$VENV/bin/python"
fi

# ---------- 3. 装依赖（清单从 pyproject 读，口径与 CI 一致） ----------
# 2026-10-20 起 agent 侧换成 dsh（TypeScript/pnpm），**不再有 Python 后端**，
# 所以这里只剩 NDR 一份 pyproject；agent 的质量门在它自己目录里用 pnpm 跑。
"$PY" - <<'PY' > /tmp/dev-deps.txt
import pathlib, tomllib
deps: list[str] = []
for path in ("ndr/backend/pyproject.toml",):
    data = tomllib.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    deps += data["project"]["dependencies"]
    deps += data["project"].get("optional-dependencies", {}).get("dev", [])
# pyyaml 不在依赖里但测试要用；pyright/ruff 是检查器本身
deps += ["pyyaml", "pyright", "ruff"]
print("\n".join(dict.fromkeys(deps)))
PY

CONSTRAINT=""
case "$(uname -s)-$(uname -m)" in
  Darwin-x86_64)
    # Intel Mac 上 cryptography 新版没有预编译包（要 Rust 才能本地编译）→ 钉一个有 wheel 的版本
    printf 'cryptography==44.0.3\n' > /tmp/dev-constraints.txt
    CONSTRAINT="--constraint /tmp/dev-constraints.txt"
    ;;
esac

if [ -n "$UV" ]; then
  # shellcheck disable=SC2086
  "$UV" pip install --python "$PY" -q $CONSTRAINT -r /tmp/dev-deps.txt
else
  "$PY" -m pip install -q --upgrade pip
  # shellcheck disable=SC2086
  "$PY" -m pip install -q $CONSTRAINT -r /tmp/dev-deps.txt
fi

# ---------- 4. 自检 ----------
"$PY" -c "import fastapi, sqlalchemy, elasticsearch, redis, pydantic, geoip2, mcp, jwt; print('✔ 依赖导入正常')"
echo "✔ 完成：$("$PY" -V 2>&1)"
echo "  跑门禁："
echo "    .venv/bin/ruff check ndr/backend/app tests/py"
echo "    .venv/bin/pyright ndr/backend/app tests/py"
echo "    .venv/bin/python -m pytest tests/py --stack=ndr -q"
