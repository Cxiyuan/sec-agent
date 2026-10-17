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

import ipaddress
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


#: **允许出现的 IPv4**（只有这些能在仓库里出现）。为什么用白名单而不是黑名单：
#: 2026-10 实机踩到 —— 上一次部署的固定 IP（redis 端口绑定 `10.255.12.4`）被写进 .env 带到了
#: 新环境，docker 起不来（"cannot assign requested address"），normalizer 跟着无限重启。
#: 黑名单只能挡住已知的地址，白名单能挡住**将来任何一个**环境特有的地址。
_ALLOWED_NETS: tuple[str, ...] = (
    "0.0.0.0/8",  # 通配
    "127.0.0.0/8",  # 回环（本地/容器内部地址）
    "169.254.0.0/16",  # 链路本地：含云元数据服务 169.254.169.254（产品常量，规则要判 SSRF）
    "192.0.2.0/24",  # RFC5737 文档保留段（示例地址一律用这些）
    "198.51.100.0/24",
    "203.0.113.0/24",
    "1.2.3.0/24",  # 教科书示例
    "2.2.2.0/24",
    "3.3.3.0/24",
    "1.1.1.0/24",  # 公共 DNS 常量
    "8.8.8.0/24",
    "9.9.9.0/24",
    "100.100.100.0/24",  # 阿里云元数据/DNS 常量（产品要能判这类 SSRF）
    "10.44.77.249/32",  # 智能体侧地址：**产品常量**（换哪部署 NDR 都连它，非环境生成）
    "224.0.0.0/4",  # 组播（mDNS 等）
    "255.255.255.255/32",
    # 通用内网示例（测试/文档里当"某个内网"用，不是任何现场的真实网段）
    "10.0.0.0/24",
    "10.1.0.0/16",
    "10.2.0.0/24",
    "10.3.0.0/16",  # 通用示例（10.3.x.x）
    "10.4.0.0/24",
    "10.9.0.0/16",  # 通用示例（10.9.x.x）
    "10.10.0.0/16",
    "10.100.0.0/16",
    "192.168.0.0/16",
    "172.16.0.0/24",  # 仅通用示例（172.16.0.x / 172.16.1.x / 172.16.5.x 这几个）
    "172.16.1.0/24",
    "172.16.5.0/24",
)
_ALLOWED = tuple(ipaddress.ip_network(n) for n in _ALLOWED_NETS)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IP_SKIP_EXT = {
    ".rules",
    ".map",
    ".lock",
    ".png",
    ".jpg",
    ".ico",
    ".woff",
    ".woff2",
    # 离线地理库（二进制 .mmdb / .gz）：不是文本，也不含"环境地址"这类东西
    ".mmdb",
    ".gz",
}
#: 规则文件里出现现场的地址属"数据"（由开发人员维护），这里只看产品与文档
_IP_ROOTS = ("ndr", "agent", "tests", "docs", "packages", "README.md", "AGENTS.md")


def test_no_environment_specific_ipv4() -> None:
    """全仓（代码/测试/编排/文档）不得出现白名单之外的 IPv4。

    允许清单见 `_ALLOWED_NETS`：通配、回环、文档保留段、云元数据等**产品常量**、以及
    明确标注为"通用示例"的内网段。**任何现场地址**（上一次部署的固定 IP、客户站点网段、
    抓包里出现的公网地址）都不许进仓库 —— 它们会让产品换一个环境就起不来。
    """
    bad: list[str] = []
    for root in _IP_ROOTS:
        base = ROOT / root
        if not base.exists():
            continue
        targets = [base] if base.is_file() else list(base.rglob("*"))
        for path in targets:
            if not path.is_file() or path.suffix in _IP_SKIP_EXT:
                continue
            if _SKIP_PARTS & set(path.parts) or path.name in _SKIP_NAMES:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for no, line in enumerate(text.splitlines(), 1):
                for ip in _IPV4.findall(line):
                    try:
                        addr = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if any(addr in net for net in _ALLOWED):
                        continue
                    bad.append(f"{path.relative_to(ROOT)}:{no} 出现 {ip}")
    assert not bad, "仓库里出现了环境特有的 IPv4（换成通用示例或按环境配置）：\n  " + "\n  ".join(
        bad[:40]
    )
