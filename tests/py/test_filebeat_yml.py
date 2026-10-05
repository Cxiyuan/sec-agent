"""``ndr/zeek/filebeat.yml`` 的回归测试。

这一层改错的代价是"采集直接起不来"或"静默丢事件"，而且很难在本地发现
（只有服务器上 Filebeat 真的拉起来才知道），所以把关键形状钉在测试里。

几条实测依据：
- 本镜像的 Filebeat 是 **OSS 构建**：``queue.spool`` 实测报
  ``unrecognized queue type 'spool'``，只能用 ``queue.disk``（8.15.3 实测 Config OK）；
- ``filestream`` 输入只提供 ``log.file.path``（没有 ``log.file.name``），
  且该构建不含 grok 处理器，取文件名只能用 JS script 处理器；
- Zeek 轮转是**同目录平铺改名**（``conn.log`` → ``conn.2026-10-02-09-30-15.log``），不是日期子目录；
  ``ndr/wazuh/filebeat.yml`` 是同一套投递形状（disk queue + 命名卷注册表），单独一组测试；
- 排除名单必须写在 ``prospector.scanner.exclude_files``：写成输入顶层的
  ``exclude_files``（旧 ``log`` 输入选项）8.15.3 实测无效，``stderr.log`` 照样入库。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
FB_PATH = ROOT / "ndr" / "zeek" / "filebeat.yml"
WAZUH_FB_PATH = ROOT / "ndr" / "wazuh" / "filebeat.yml"
WAZUH_COMPOSE_PATH = ROOT / "ndr" / "docker-compose.wazuh.yml"

# 非事件文件（Zeek / Filebeat 自身输出）必须被排除
EXCLUDED = (
    "stderr",
    "stdout",
    "loaded_scripts",
    "debug",
    "prof",
    "telemetry",
    "threading",
    "capture_loss",
)


def cfg() -> dict[str, Any]:
    return yaml.safe_load(FB_PATH.read_text(encoding="utf-8"))


def test_filestream_input() -> None:
    inputs = cfg()["filebeat.inputs"]
    assert len(inputs) == 1
    item = inputs[0]
    assert item["type"] == "filestream"
    assert item["enabled"] is True
    paths = item["paths"]
    # 活动日志 + 子目录布局都要采到
    assert any(p.endswith("*.log") and "*/*" not in p for p in paths), paths
    assert any(p.endswith("*/*.log") for p in paths), paths
    # Zeek 字段必须收进 zeek.*，否则 Filebeat 的 host 会覆盖 http.log 的 Host 头
    assert item["parsers"][0]["ndjson"]["target"] == "zeek"
    assert item["fields"]["source_system"] == "zeek"
    assert item["fields_under_root"] is True


def test_non_event_files_excluded() -> None:
    item = cfg()["filebeat.inputs"][0]
    # 必须写在 prospector.scanner 下：顶层 exclude_files 是旧 log 输入的选项，
    # filestream 会把它当无关字段收下但不生效（8.15.3 实机探针验证过）。
    assert "exclude_files" not in item, "filestream 的排除名单不能写在输入顶层（不生效）"
    patterns = item["prospector"]["scanner"]["exclude_files"]
    assert patterns, "必须有排除名单，否则运行输出会以未知类型混进事件索引"
    joined = " ".join(patterns)
    for name in EXCLUDED:
        assert name in joined, f"{name} 应在排除名单里：{patterns}"
    # 运维类日志要入库当证据，不能被排除
    for name in ("stats", "packet_filter", "reporter"):
        assert f"({name}|" not in joined and f"|{name})" not in joined, f"{name} 不该被排除"


def test_log_type_derived_from_filename() -> None:
    processors = cfg()["processors"]
    scripts = [p["script"] for p in processors if "script" in p]
    assert len(scripts) == 1, processors
    src = scripts[0]["source"]
    assert scripts[0]["lang"] == "javascript"
    assert "log.file.path" in src
    # 去掉 .log 与轮转时间戳；轮转名是 <name>.<YYYY-MM-DD-HH-MM-SS>.log，
    # 历史上还出现过只到天的 <name>.<YYYY-MM-DD>.log，所以两种都要能剥。
    assert r"\.log$" in src
    full = r"\.\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}$"
    date_only = r"\.\d{4}-\d{2}-\d{2}$"
    assert full in src
    assert date_only in src
    # 顺序不能反：先剥「日期+时分秒」，否则 conn.2026-10-02-09-30-15 会被剥成
    # conn.2026-10-02（多留一段日期 → log_type 变成不存在的流，静默漏检测）。
    assert src.index(full) < src.index(date_only), "完整时间戳规则必须排在只到天的规则之前"
    assert 'event.Put("log_type", t)' in src


def test_unknown_filenames_are_not_dropped() -> None:
    """认不出的文件名也要发出去（下游标 log_type_known=false），不能静默丢。"""
    for processor in cfg()["processors"]:
        assert "drop_event" not in processor, "不许在 Filebeat 侧丢事件"


def test_disk_backed_queue() -> None:
    conf = cfg()
    # 注意：Filebeat 的配置用点号路径，YAML 里就是字面 key "queue.disk"
    assert "queue.spool" not in conf, (
        "OSS 版 Filebeat 不支持 queue.spool（实测 unrecognized queue type）"
    )
    disk = conf["queue.disk"]
    # 队列要落在命名卷上（zeek-filebeat:/usr/local/bin/data），容器重建不丢
    assert "/usr/local/bin/data" in disk["path"], disk["path"]
    assert disk["max_size"] == "1GB"
    assert disk["write_ahead"] >= 1


def test_redis_output() -> None:
    out = cfg()["output.redis"]
    assert "shentong:events:collect" in out["key"]
    assert out["data_type"] == "list"
    assert out["hosts"] and "${REDIS_HOST" in out["hosts"][0]


# ---------- Wazuh 线路（与 Zeek 线同一套投递形状，2026-10 QA 后对齐）----------


def wazuh_cfg() -> dict[str, Any]:
    return yaml.safe_load(WAZUH_FB_PATH.read_text(encoding="utf-8"))


def test_wazuh_inputs_and_parsers() -> None:
    inputs = wazuh_cfg()["filebeat.inputs"]
    assert [i["id"] for i in inputs] == ["wazuh-alerts", "wazuh-archives"]
    for item in inputs:
        assert item["type"] == "filestream"
        ndjson = item["parsers"][0]["ndjson"]
        # Wazuh 的 rule/data/agent/full_log 在根；套 target 归一化就读不到
        assert "target" not in ndjson, "Wazuh 输入不能设 ndjson target"
        assert ndjson["overwrite_keys"] is True, (
            "否则 Filebeat 的 ECS agent 会盖掉 Wazuh agent.name"
        )
        assert item["fields"]["source_system"] == "wazuh"
        assert item["fields_under_root"] is True
    # archives 默认关闭：要 .env 里 WAZUH_ARCHIVES_ENABLED=true + enable-logall.sh 两处都开
    assert inputs[1]["enabled"] == "${WAZUH_ARCHIVES_ENABLED:false}"


def test_wazuh_disk_queue_matches_zeek_line() -> None:
    conf = wazuh_cfg()
    assert "queue.spool" not in conf, "OSS 版 Filebeat 不支持 queue.spool（Zeek 线实测）"
    disk = conf["queue.disk"]
    # 队列目录与读取注册表都要落在命名卷上（docker-compose.wazuh.yml 挂载点）
    assert "/usr/share/filebeat/data" in disk["path"], disk["path"]
    assert disk["max_size"] == "1GB"
    assert disk["segment_size"] == "128MiB"
    assert disk["write_ahead"] >= 1


def test_wazuh_registry_volume_persisted() -> None:
    """注册表/队列必须持久化：否则每次重建都从头重读全部 alerts.json（生产踩过）。"""
    compose = yaml.safe_load(WAZUH_COMPOSE_PATH.read_text(encoding="utf-8"))
    svc = compose["services"]["wazuh-filebeat"]
    assert "wazuh-filebeat:/usr/share/filebeat/data" in svc["volumes"]
    assert "wazuh-filebeat" in compose["volumes"]


def test_wazuh_redis_output() -> None:
    out = wazuh_cfg()["output.redis"]
    assert out["data_type"] == "list"
    assert out["key"] == "${REDIS_KEY:shentong:events:collect}"


# ---------- Wazuh 是内置服务：部署编排必须默认带上它 ----------

DEPLOY_COMPOSE_PATH = ROOT / "ndr" / "docker-compose.deploy.yml"


def wazuh_compose() -> dict[str, Any]:
    return yaml.safe_load(WAZUH_COMPOSE_PATH.read_text(encoding="utf-8"))


def _container_paths(svc: dict[str, Any]) -> list[str]:
    paths = []
    for item in svc.get("volumes", []):
        parts = str(item).split(":")
        if len(parts) >= 2 and parts[1].startswith("/"):
            paths.append(parts[1])
    return paths


def test_deploy_compose_includes_wazuh() -> None:
    """部署编排必须 include Wazuh 叠加件：它得随项目一起发布，不是可选外接。"""
    deploy = yaml.safe_load(DEPLOY_COMPOSE_PATH.read_text(encoding="utf-8"))
    include = deploy.get("include") or []
    assert "docker-compose.wazuh.yml" in include, f"deploy 编排没有 include Wazuh：{include}"
    # include 指向的文件必须真有这两个服务，否则部署时才炸
    services = wazuh_compose()["services"]
    assert {"wazuh-manager", "wazuh-filebeat"} <= set(services)


def test_wazuh_manager_volumes_match_official_4_14() -> None:
    """manager 的卷清单按官方 4.14.8 single-node 编排对齐。

    官方把 wodles / agentless 各自挂卷；`etc/shared` 不能单独挂——它就在 etc 卷里，
    对同一容器挂 `/var/ossec/etc` 和 `/var/ossec/etc/shared` 会遮蔽 etc 卷。"""
    svc = wazuh_compose()["services"]["wazuh-manager"]
    paths = set(_container_paths(svc))
    for expected in (
        "/var/ossec/etc",
        "/var/ossec/logs",
        "/var/ossec/queue",
        "/var/ossec/api/configuration",
        "/var/ossec/var/multigroups",
        "/var/ossec/integrations",
        "/var/ossec/active-response/bin",
        "/var/ossec/wodles",
        "/var/ossec/agentless",
    ):
        assert expected in paths, f"manager 少了卷挂载点 {expected}：{sorted(paths)}"
    # 卷路径不许互相嵌套（一个挂载点盖住另一个）
    for outer in paths:
        for inner in paths:
            assert not inner.startswith(outer + "/"), f"挂载点嵌套了：{outer} 盖住 {inner}"


def test_wazuh_manager_api_env_and_ulimits() -> None:
    """API 用户名/口令与 ulimits 必须显式给出（官方编排也只靠这几个环境变量）。"""
    svc = wazuh_compose()["services"]["wazuh-manager"]
    env = svc["environment"]
    assert env["API_USERNAME"] == "${WAZUH_API_USER:-wazuh-wui}"
    assert "API_PASSWORD" in env
    # 默认口令必须是个明显要改的占位，别把弱口令带到生产
    assert "change-me" in env["API_PASSWORD"], env["API_PASSWORD"]
    assert svc["ulimits"]["memlock"]["soft"] == -1
    assert svc["ulimits"]["nofile"]["hard"] == 655360


def test_deploy_backend_points_at_builtin_wazuh() -> None:
    """内置 Wazuh 得让后台知道去哪找：部署编排要给 backend 默认 API 地址与凭据。"""
    deploy = yaml.safe_load(DEPLOY_COMPOSE_PATH.read_text(encoding="utf-8"))
    env = deploy["services"]["backend"]["environment"]
    assert env["ST_WAZUH_API_URL"] == "${WAZUH_API_URL:-https://wazuh-manager:55000}"
    assert env["ST_WAZUH_API_USER"] == "${WAZUH_API_USER:-wazuh-wui}"
    # 口令只从 .env 取（不给弱默认值：没配就让界面显式报"未配置"）
    assert env["ST_WAZUH_API_PASSWORD"] == "${WAZUH_API_PASSWORD:-}"
