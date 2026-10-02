"""``ndr/zeek/filebeat.yml`` 的回归测试。

这一层改错的代价是"采集直接起不来"或"静默丢事件"，而且很难在本地发现
（只有服务器上 Filebeat 真的拉起来才知道），所以把关键形状钉在测试里。

几条实测依据：
- 本镜像的 Filebeat 是 **OSS 构建**：``queue.spool`` 实测报
  ``unrecognized queue type 'spool'``，只能用 ``queue.disk``（8.15.3 实测 Config OK）；
- ``filestream`` 输入只提供 ``log.file.path``（没有 ``log.file.name``），
  且该构建不含 grok 处理器，取文件名只能用 JS script 处理器；
- Zeek 轮转是**同目录平铺改名**（``conn.log`` → ``conn.2026-10-01.log``），不是日期子目录；
- 排除名单必须写在 ``prospector.scanner.exclude_files``：写成输入顶层的
  ``exclude_files``（旧 ``log`` 输入选项）8.15.3 实测无效，``stderr.log`` 照样入库。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
FB_PATH = ROOT / "ndr" / "zeek" / "filebeat.yml"

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
    # 去掉 .log 与两种轮转后缀（YYYY-MM-DD / HH-MM-SS）
    assert r"\.log$" in src
    assert r"\.\d{4}-\d{2}-\d{2}$" in src
    assert r"\.\d{2}-\d{2}-\d{2}$" in src
    assert 'event.Put("log_type", t)' in src


def test_unknown_filenames_are_not_dropped() -> None:
    """认不出的文件名也要发出去（下游标 log_type_known=false），不能静默丢。"""
    for processor in cfg()["processors"]:
        assert "drop_event" not in processor, "不许在 Filebeat 侧丢事件"


def test_disk_backed_queue() -> None:
    conf = cfg()
    # 注意：Filebeat 的配置用点号路径，YAML 里就是字面 key "queue.disk"
    assert "queue.spool" not in conf, "OSS 版 Filebeat 不支持 queue.spool（实测 unrecognized queue type）"
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
