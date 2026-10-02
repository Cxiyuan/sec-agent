"""批 3：HTTP 正文上限的 Zeek 侧渲染（``entrypoint.sh: render_limits``）。

上限值有两个落点，必须同时改、且必须是同一个数字：

1. ``ndr/zeek/site/shentong-limits.zeek`` —— 镜像内默认值（用户没改过配置时的兜底）；
2. ``/config/interface.conf`` 的 ``body_max_bytes`` / ``resp_body_max_bytes`` ——
   后台改上限时写入，Zeek 看门狗重载前由 ``render_limits`` 重新渲染第 1 项。

因此这里既检查默认值与后端 ``settings`` 一致，也把 ``render_limits`` 抽出来用 bash
真跑一遍（假 conf → 真文件），顺带覆盖非法值回落。
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
from app.config import settings

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "ndr" / "zeek" / "site"
ENTRYPOINT = ROOT / "ndr" / "zeek" / "entrypoint.sh"


def _extract_function(text: str, name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{.*?^\}}", text, re.DOTALL | re.MULTILINE)
    assert m, f"entrypoint.sh 里找不到 {name}()"
    return m.group(0)


def test_shentong_limits_defaults_match_settings() -> None:
    text = (SITE / "shentong-limits.zeek").read_text(encoding="utf-8")
    assert f"redef ShentongHTTP::max_body_len = {settings.http_body_max_chars};" in text
    assert f"redef ShentongHTTP::max_resp_body_len = {settings.http_resp_body_max_chars};" in text


def test_local_zeek_loads_limits_after_httpbody() -> None:
    """``shentong-limits`` 必须排在 ``shentong-httpbody`` 之后（redef 的是它声明的 const）。"""
    loads = [
        line.strip()
        for line in (SITE / "local.zeek").read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("@load")
    ]
    assert "@load ./shentong-httpbody" in loads
    assert loads.index("@load ./shentong-limits") > loads.index("@load ./shentong-httpbody")


@pytest.mark.skipif(shutil.which("bash") is None, reason="需要 bash 执行 entrypoint 片段")
@pytest.mark.parametrize(
    ("conf_text", "want_body", "want_resp"),
    [
        ("body_max_bytes=32768\nresp_body_max_bytes=131072\n", "32768", "131072"),
        ("interface=eth0\n", "16384", "65536"),
        ("body_max_bytes=abc\nresp_body_max_bytes=\n", "16384", "65536"),
    ],
)
def test_render_limits_rewrites_site_script(
    tmp_path: Path, conf_text: str, want_body: str, want_resp: str
) -> None:
    script = ENTRYPOINT.read_text(encoding="utf-8")
    harness = "\n".join(
        [
            "set -euo pipefail",
            "log() { :; }",
            f'IFACE_CONF="{tmp_path}/interface.conf"',
            f'SITE_DIR="{tmp_path}/site"',
            _extract_function(script, "conf_get"),
            _extract_function(script, "render_limits"),
            "render_limits",
        ]
    )
    (tmp_path / "site").mkdir()
    (tmp_path / "interface.conf").write_text(conf_text, encoding="utf-8")
    subprocess.run(["bash", "-c", harness], check=True, capture_output=True, text=True)

    rendered = (tmp_path / "site" / "shentong-limits.zeek").read_text(encoding="utf-8")
    assert "由 entrypoint.sh 自动生成（render_limits）" in rendered
    assert f"redef ShentongHTTP::max_body_len = {want_body};" in rendered
    assert f"redef ShentongHTTP::max_resp_body_len = {want_resp};" in rendered
