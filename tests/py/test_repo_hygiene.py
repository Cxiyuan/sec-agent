"""仓库卫生：产品代码 / 测试 / 界面里不得出现「部署环境产生的地址」。

为什么（2026-10 用户口径）：客户环境里的 IP 与域名是**部署时才有**的东西 —— 换一个环境不一定存在，
含义也不一定相同（同一个 IP 在别的环境可能只是普通主机，不是那台授权漏扫设备）。所以：

- 规则判据里一律用**虚拟字段**（`src_internal` / `dst_internal`）表达内外网，不写网段；
- 示例、占位符、测试数据用通用地址：内网 `10.x` / `192.168.x`，公网 `1.1.1.1` / `8.8.8.8`，
  域名 `example.com`；
- 现场真实地址只存在于**配置数据**（PG：中继清单、降噪/排除过滤器），界面可查可撤销。

为了让本文件自己也不带这些地址，下面的模式是**拼装**出来的（不出现完整字符串）。
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

#: 历史环境里出现过的网段前缀 + 客户域名（拼装，避免本文件自己命中）
_NEEDLES: tuple[str, ...] = (
    "172.16." + "19",  # 该站点的那段 /22
    "172.16." + "195",
    "172.16." + "196",
    "10.25" + "0.250",
    "10.9" + "4.10",
    "nc" + "zy.edu.cn",
    "sang" + "for.com.cn",
    "yuns" + "uo.com.cn",
    "360" + "safe.com",
)

#: 只看代码与测试（设计文档里保留调研证据与真实数据，那是另一回事）
_ROOTS = ("ndr", "agent", "tests/py", "packages")
_SKIP_PARTS = {"node_modules", ".next", ".git", "dist", "__pycache__"}
_SKIP_NAMES = {"test_repo_hygiene.py"}
_SUFFIXES = {".py", ".ts", ".tsx", ".yml", ".yaml", ".sh", ".json", ".md"}


def _iter_files() -> list[Path]:
    out: list[Path] = []
    for root in _ROOTS:
        base = ROOT / root
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in _SUFFIXES:
                continue
            if path.name in _SKIP_NAMES or _SKIP_PARTS & set(path.parts):
                continue
            out.append(path)
    return out


def test_no_environment_specific_addresses_in_code() -> None:
    """代码/测试/界面里不得出现部署环境特有的地址或客户域名。"""
    bad: list[str] = []
    for path in _iter_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in _NEEDLES:
            if needle in text:
                line = next((i for i, row in enumerate(text.splitlines(), 1) if needle in row), 0)
                bad.append(f"{path.relative_to(ROOT)}:{line} 出现环境特有内容")
    assert not bad, "把环境特有的 IP/域名写进了代码或测试：\n  " + "\n  ".join(bad)


def test_ui_placeholders_use_generic_addresses() -> None:
    """界面占位符/示例必须用通用地址（用户会照着填，写着某个环境的地址就会被抄进别的环境）。"""
    text = (ROOT / "ndr" / "frontend" / "components" / "relay-nodes-panel.tsx").read_text(
        encoding="utf-8"
    )
    placeholder = re.search(r'placeholder=\{"([^"]+)"\}', text)
    assert placeholder, "中继清单输入框应当有示例占位符"
    for row in placeholder.group(1).split("\\n"):
        ip = row.split("#")[0].strip()
        if not ip:
            continue
        assert re.match(r"^(10\.|192\.168\.)", ip), f"占位符应使用通用内网地址，实际 {ip!r}"
