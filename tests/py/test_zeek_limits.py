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
import yaml
from app.config import settings

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "ndr" / "zeek" / "site"
ENTRYPOINT = ROOT / "ndr" / "zeek" / "entrypoint.sh"
COMPOSE_DEV = ROOT / "ndr" / "docker-compose.yml"
COMPOSE_DEPLOY = ROOT / "ndr" / "docker-compose.deploy.yml"
DOCKERFILE = ROOT / "ndr" / "zeek" / "Dockerfile"
HEALTHCHECK = ROOT / "ndr" / "zeek" / "healthcheck.sh"


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


# ---------- 2026-10 QA 修复的回归测试（入口脚本行为 / 编排形状）----------


def _run_entrypoint(
    names: list[str], setup: list[str], call: list[str], tmp_path: Path
) -> subprocess.CompletedProcess[str]:
    """把 entrypoint.sh 里指定的函数抽出来，在临时目录里真跑一遍。"""
    script = ENTRYPOINT.read_text(encoding="utf-8")
    harness = "\n".join(
        [
            "set -euo pipefail",
            "log() { :; }",
            *setup,
            *(_extract_function(script, name) for name in names),
            *call,
        ]
    )
    return subprocess.run(["bash", "-c", harness], check=True, capture_output=True, text=True)


def test_render_nets_narrows_zeek_private_space(tmp_path: Path) -> None:
    """配了网段时必须同时关掉 Zeek 的「私有地址自动算本地」，否则 local_nets 收窄不掉。

    2026-10 实测：只 redef Site::local_nets 时 |Site::local_nets| = 自定 + 内置 RFC1918 共 43 条。
    """
    (tmp_path / "site").mkdir()
    (tmp_path / "interface.conf").write_text("local_nets=172.16.196.0/24\n", encoding="utf-8")
    _run_entrypoint(
        ["conf_get", "render_nets"],
        [f'IFACE_CONF="{tmp_path}/interface.conf"', f'SITE_DIR="{tmp_path}/site"'],
        ["render_nets"],
        tmp_path,
    )
    rendered = (tmp_path / "site" / "shentong-nets.zeek").read_text(encoding="utf-8")
    assert "redef Site::private_address_space_is_local = F;" in rendered
    assert "172.16.196.0/24," in rendered


def test_render_nets_empty_keeps_zeek_defaults(tmp_path: Path) -> None:
    (tmp_path / "site").mkdir()
    (tmp_path / "interface.conf").write_text("local_nets=\n", encoding="utf-8")
    _run_entrypoint(
        ["conf_get", "render_nets"],
        [f'IFACE_CONF="{tmp_path}/interface.conf"', f'SITE_DIR="{tmp_path}/site"'],
        ["render_nets"],
        tmp_path,
    )
    rendered = (tmp_path / "site" / "shentong-nets.zeek").read_text(encoding="utf-8")
    assert "private_address_space_is_local" not in rendered
    assert "Site::local_nets" not in rendered


@pytest.mark.parametrize("files", [(), ("aaa.zeek",)])
def test_render_scripts_loader(tmp_path: Path, files: tuple[str, ...]) -> None:
    """scripts.d 为空时的分支也要真的能跑到（否则就是一段没人验证的死逻辑）。"""
    (tmp_path / "site" / "scripts.d").mkdir(parents=True)
    for name in files:
        (tmp_path / "site" / "scripts.d" / name).write_text("", encoding="utf-8")
    _run_entrypoint(
        ["render_scripts_loader"],
        [f'SITE_DIR="{tmp_path}/site"'],
        ["render_scripts_loader"],
        tmp_path,
    )
    rendered = (tmp_path / "site" / "shentong-scripts-d.zeek").read_text(encoding="utf-8")
    if files:
        assert "@load ./scripts.d/aaa.zeek" in rendered
    else:
        assert "# scripts.d 为空" in rendered


def _make_logs(tmp_path: Path) -> Path:
    logs = tmp_path / "logs"
    logs.mkdir()
    old = ["old.2026-09-20.log", "oldts.2026-09-20-10-00-00.log"]
    for name in (*old, "new.2026-10-01.log", "conn.log"):
        (logs / name).write_text("x", encoding="utf-8")
    subprocess.run(["touch", "-d", "5 days ago", *[str(logs / n) for n in old]], check=True)
    subprocess.run(["touch", "-d", "1 day ago", str(logs / "new.2026-10-01.log")], check=True)
    return logs


def test_cleanup_once_deletes_only_old_rotated_files(tmp_path: Path) -> None:
    """保留期按「N 天」字面执行（-mmin），只删轮转命名的归档，活动日志不动。"""
    logs = _make_logs(tmp_path)
    _run_entrypoint(
        ["cleanup_once"],
        [
            f'LOG_DIR="{logs}"',
            # 无 Filebeat 可执行文件 → 存活闸门不介入，只看保留期与命名匹配
            'FILEBEAT_BIN=""',
            "RETENTION_DAYS=3",
            "filebeat_alive() { return 0; }",
        ],
        ["cleanup_once"],
        tmp_path,
    )
    assert sorted(p.name for p in logs.iterdir()) == ["conn.log", "new.2026-10-01.log"]


def test_cleanup_once_skips_when_filebeat_is_down(tmp_path: Path) -> None:
    """发运方不在时不能删：删掉还没上报的归档就是永久丢数据。"""
    logs = _make_logs(tmp_path)
    fake_fb = tmp_path / "filebeat"
    fake_fb.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_fb.chmod(0o755)
    _run_entrypoint(
        ["cleanup_once"],
        [
            f'LOG_DIR="{logs}"',
            f'FILEBEAT_BIN="{fake_fb}"',
            "RETENTION_DAYS=3",
            "filebeat_alive() { return 1; }",
        ],
        ["cleanup_once"],
        tmp_path,
    )
    assert sorted(p.name for p in logs.iterdir()) == [
        "conn.log",
        "new.2026-10-01.log",
        "old.2026-09-20.log",
        "oldts.2026-09-20-10-00-00.log",
    ]


def test_dev_compose_all_services_have_restart_policy() -> None:
    compose = yaml.safe_load(COMPOSE_DEV.read_text(encoding="utf-8"))
    missing = [name for name, svc in compose["services"].items() if not (svc or {}).get("restart")]
    assert not missing, f"dev compose 缺 restart 策略（主机重启后不会自愈）：{missing}"


@pytest.mark.parametrize("path", [COMPOSE_DEV, COMPOSE_DEPLOY])
def test_zeek_service_tz_and_dead_env_removed(path: Path) -> None:
    env = yaml.safe_load(path.read_text(encoding="utf-8"))["services"]["zeek"]["environment"]
    # 与其它服务一致的北京时间（容器内有 tzdata，实测生效）
    assert env["TZ"] == "Asia/Shanghai"
    # 这两个 env 入口脚本从来没读过（路径由 ZEEK_CONF_DIR 推导），2026-10 QA 删除
    assert "ZEEK_IFACE_CONF" not in env
    assert "ZEEK_INTERFACES_JSON" not in env
    # 缺省网卡要与 entrypoint.sh 的 IFACE_DEFAULT 一致
    assert env["ZEEK_IFACE"] == "${ZEEK_IFACE:-ens224}"
    assert 'IFACE_DEFAULT="${ZEEK_IFACE:-ens224}"' in ENTRYPOINT.read_text(encoding="utf-8")


def test_zeek_image_has_healthcheck() -> None:
    """Zeek 反复启动失败/Filebeat 掉线必须能在 docker ps 的 STATUS 里看出来。"""
    df = DOCKERFILE.read_text(encoding="utf-8")
    assert "HEALTHCHECK" in df
    assert "healthcheck.sh" in df
    assert HEALTHCHECK.is_file()
    body = HEALTHCHECK.read_text(encoding="utf-8")
    assert "/tmp/zeek-health" in body


def test_zeek_entrypoint_has_filebeat_supervisor_and_health_sentinel() -> None:
    script = ENTRYPOINT.read_text(encoding="utf-8")
    assert "start_filebeat_supervisor" in script
    assert "start_health_loop" in script
    assert "HEALTH_FILE=" in script
    # 无网段全量抓包要在日志里显式告警
    assert "全量抓包" in script


def test_health_sentinel_flap_and_ok_branches(tmp_path: Path) -> None:
    """抖动（起不来/刚到就退）要能被哨兵标成 unhealthy；正常时是 ok。"""
    log = tmp_path / "restarts"
    now = int(subprocess.run(["date", "+%s"], check=True, capture_output=True, text=True).stdout)
    # 窗口内 9 次启动（> ZEEK_FLAP_MAX=5）
    log.write_text("\n".join(str(now - i) for i in range(9)) + "\n", encoding="utf-8")
    out = _run_entrypoint(
        ["restart_count_window", "health_snapshot"],
        [
            f'PID_FILE="{tmp_path}/zeek.pid"',
            f'ZEEK_RESTART_LOG="{log}"',
            "ZEEK_FLAP_WINDOW=300",
            "ZEEK_FLAP_MAX=5",
            'FILEBEAT_BIN=""',
            "zeek_alive() { return 0; }",
        ],
        ["health_snapshot"],
        tmp_path,
    )
    assert out.stdout.startswith("unhealthy"), out.stdout
    assert "启动 9 次" in out.stdout

    # 窗口外的旧时间戳要丢掉：只剩窗口内 1 次 → ok
    log.write_text("\n".join([str(now - 10_000), str(now)]) + "\n", encoding="utf-8")
    out = _run_entrypoint(
        ["restart_count_window", "health_snapshot"],
        [
            f'PID_FILE="{tmp_path}/zeek.pid"',
            f'ZEEK_RESTART_LOG="{log}"',
            "ZEEK_FLAP_WINDOW=300",
            "ZEEK_FLAP_MAX=5",
            'FILEBEAT_BIN=""',
            "zeek_alive() { return 0; }",
        ],
        ["health_snapshot"],
        tmp_path,
    )
    assert out.stdout.startswith("ok "), out.stdout
    assert "flaps=1" in out.stdout
    assert log.read_text(encoding="utf-8").count("\n") == 1, "窗口外的时间戳应被修剪掉"
