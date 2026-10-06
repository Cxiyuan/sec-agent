"""签名引擎（Suricata）接入契约：归一化、规则、采集编排、关联键。

这一层一次性装好的东西很多（新采集组件 + 新日志来源 + 新字段 + 删掉 48 条重叠规则），
任何一处漏了都不会在本地“看起来”出错：容器起不来、规则没命中、Zeek 与 Suricata 的日志
对不上，全都要等上线才发现。所以把关键形状钉在这里。

两侧差异：归一化/规则/引擎/编排两侧都有（除 catalog 只在 NDR），
只在 NDR 存在的部分放 fixture 里 import，agent 轮次跳过。
"""

from __future__ import annotations

from pathlib import Path
from types import ModuleType

import pytest
import samples
import yaml
from app.ingestion import log_types
from app.ingestion.normalizer import normalize
from app.rules import builtin as builtin_mod
from app.rules.engine import build_rule_index

ROOT = Path(__file__).resolve().parents[2]

SIGNATURE_RULES = ("内置-签名命中(高危)", "内置-签名命中(中危)", "内置-签名命中(低危)")


# ---------- 规则库：删 48 / 加 3 ----------


def test_builtin_rule_count() -> None:
    """80 - 48（交给签名引擎）+ 3（签名命中分档）= 35。"""
    assert len(builtin_mod.BUILTIN_RULES) == 35


def test_deleted_rules_do_not_come_back() -> None:
    """删掉的 48 条必须在 DELETED_RULES 名单里（否则下次启动会被内置定义重新 upsert 回库）。"""
    names = {spec["name"] for spec in builtin_mod.BUILTIN_RULES}
    deleted = set(builtin_mod.DELETED_RULES)
    assert len(deleted) == 52, "4 条历史 + 48 条重叠规则"
    assert not (deleted & names), "删除名单里的规则又回到内置定义了"
    # 抽查几个不同类别的（注入/WebShell/扫描/认证/IOC 名单）
    for name in (
        "内置-SQL注入-基础特征",
        "内置-WebShell上传",
        "内置-WebShell访问",
        "内置-敏感文件与源码泄露探测",
        "内置-Web攻击扫描器UA",
        "内置-登录接口爆破",
        "内置-勒索/僵尸网络域名",
        "内置-弱TLS版本",
    ):
        assert name in deleted, f"{name} 不在删除名单里"


def test_signature_rules_shape() -> None:
    """三条签名规则：按 EVE severity 分档、scope=network、级别/优先级各异。"""
    by_name = {spec["name"]: spec for spec in builtin_mod.BUILTIN_RULES}
    expect = {
        "内置-签名命中(高危)": (1, "high", 12),
        "内置-签名命中(中危)": (2, "medium", 35),
        "内置-签名命中(低危)": (3, "low", 60),
    }
    assert set(expect) <= set(by_name)
    for name, (sev_value, severity, priority) in expect.items():
        spec = by_name[name]
        assert spec["severity"] == severity
        assert spec["priority"] == priority
        assert builtin_mod.rule_scope(spec) == "network"
        conds = {c["field"]: c["value"] for c in spec["conditions"]["rules"]}
        assert conds["event_type"] == "signature_hit"
        assert conds["signature_severity"] == sev_value


def test_signature_rules_are_routed_to_suricata_logs() -> None:
    """签名规则只在这类日志上求值：引用 suricata 专有字段 → 索引挂在 types['suricata']。"""
    index = build_rule_index(builtin_mod.BUILTIN_RULES)
    routed = {r["name"] for r in index["types"].get("suricata", [])}
    assert set(SIGNATURE_RULES) <= routed
    # 反过来：体积类规则（只引用 conn 字段）不能被卷进 suricata 的求值集合（会重复计数）
    assert "内置-大流量外传" not in routed


# ---------- 日志类型闸门与基线隔离 ----------


def test_suricata_is_detectable_but_not_baseline() -> None:
    entry = normalize("suricata", samples.DOCS["suricata_alert"])
    assert entry is not None
    assert log_types.classify_entry(entry) == "event"
    assert log_types.is_detectable(entry) is True
    # 告警是派生产物：进检测与入库，但不进行为基线/画像/资产统计
    assert log_types.is_baseline_eligible(entry) is False


def test_zeek_event_is_baseline_eligible() -> None:
    entry = normalize("zeek", samples.DOCS["conn"])
    assert entry is not None
    assert log_types.is_baseline_eligible(entry) is True


# ---------- 归一化 ----------


def test_suricata_alert_fields() -> None:
    entry = normalize("suricata", samples.DOCS["suricata_alert"])
    assert entry is not None
    assert entry.source_system == "suricata"
    assert entry.log_type == "suricata"
    assert entry.event_type == "signature_hit"
    assert entry.src_ip == "192.0.2.77"
    assert entry.dst_ip == "192.0.2.80"
    assert entry.dst_port == 8081
    assert entry.protocol == "TCP"
    assert entry.signature.startswith("ET WEB_SERVER SQL Injection")
    assert entry.signature_id == "2010935"
    assert entry.signature_severity == 1
    assert entry.signature_category == "Web Application Attack"
    assert entry.community_id == samples.EVE_ALERT["community_id"]
    assert entry.severity == "high"  # 事件级别跟 Suricata 的分档（摘要级别由三条规则定）
    # http 块被映射成与 Zeek 同口径的字段
    assert entry.hostname == "app.example.internal"
    assert entry.method == "GET"
    assert entry.uri_path == "/api/v2/items"
    assert "1%27%20OR%201%3D1" in entry.query_string
    assert entry.user_agent.startswith("Mozilla/5.0")
    assert entry.status_code == 200
    assert entry.referer == "http://app.example.internal/"
    # 体积不映射：流量体积类规则只认 Zeek 的 conn 记录
    assert entry.bytes_in is None


def test_suricata_timestamp_without_colon_offset() -> None:
    """EVE 的时间戳是 +0800（无冒号）：必须真的解析成功（静默回退 now() 会让时间线错）。"""
    entry = normalize("suricata", samples.DOCS["suricata_alert"])
    assert entry is not None
    assert entry.ts.year == 2026 and entry.ts.hour in (4, 5), entry.ts
    offset = entry.ts.utcoffset()
    assert offset is not None and offset.total_seconds() == 8 * 3600


def test_suricata_raw_drops_bulk_payload_fields() -> None:
    """raw 保留可读描述与流计数，但不放整包十六进制/载荷 base64（体积大且与它重复）。"""
    entry = normalize("suricata", samples.DOCS["suricata_alert"])
    assert entry is not None
    assert "packet" not in entry.raw
    assert "payload" not in entry.raw
    assert entry.raw["payload_printable"]
    assert entry.raw["flow"]["bytes_toserver"] == 320
    assert entry.raw["log_type"] == "suricata"
    assert entry.raw["source_file"] == "eve.json"


def test_suricata_non_alert_is_rejected() -> None:
    """非 alert（配置漂移/人工重放）不猜成事件：返回 None，走上层的失败计数。"""
    doc = samples.suricata_envelope({"event_type": "flow", "src_ip": "192.0.2.77"})
    assert normalize("suricata", doc) is None


def test_flat_suricata_sniffing() -> None:
    """没有信封的旧文档也要认出来（靠 alert 块/flow_id 嗅探）。"""
    assert samples.doc_source(samples.DOCS["flat_suricata"]) == "suricata"
    entry = normalize("suricata", samples.DOCS["flat_suricata"])
    assert entry is not None and entry.event_type == "signature_hit"


def test_zeek_conn_carries_community_id() -> None:
    """关联键的另一半：Zeek 的 conn.log 也要带同一个 community_id。"""
    entry = normalize("zeek", samples.DOCS["conn"])
    assert entry is not None
    assert entry.community_id == samples.CONN["community_id"]


# ---------- 采集编排：Filebeat / compose / 容器资产 ----------


def test_filebeat_has_suricata_input() -> None:
    cfg = yaml.safe_load((ROOT / "ndr" / "zeek" / "filebeat.yml").read_text(encoding="utf-8"))
    inputs = {i.get("id"): i for i in cfg["filebeat.inputs"]}
    assert "zeek-logs" in inputs
    sb = inputs.get("suricata-alerts")
    assert sb is not None, "Filebeat 缺少签名引擎的输入"
    # 只扫当前文件，不递归 → 归档目录不会被重读
    assert sb["paths"] == ["${ZEEK_LOG_DIR:/logs}/suricata/*.json"]
    assert sb["fields"]["source_system"] == "suricata"
    assert sb["fields"]["log_type"] == "suricata"
    # EVE 字段进 suricata.* 命名空间（对齐 Zeek 的 zeek.*）
    assert sb["parsers"][0]["ndjson"]["target"] == "suricata"


def test_filebeat_filename_processor_ignores_non_log_files() -> None:
    """取文件名的 JS 处理器只应作用于 *.log，否则会把 EVE 的 log_type 改成 “eve”。"""
    text = (ROOT / "ndr" / "zeek" / "filebeat.yml").read_text(encoding="utf-8")
    assert r"if (!/\.log$/i.test(p)) { return; }" in text


@pytest.mark.parametrize("name", ["docker-compose.yml", "docker-compose.deploy.yml"])
def test_compose_suricata_service(name: str) -> None:
    data = yaml.safe_load((ROOT / "ndr" / name).read_text(encoding="utf-8"))
    svc = data["services"].get("suricata")
    assert svc is not None, f"{name} 里没有签名引擎服务"
    assert svc["network_mode"] == "host"
    assert set(svc["cap_add"]) == {"NET_RAW", "NET_ADMIN"}
    # 不发布任何端口：只抓包写文件，不对外提供服务
    assert not svc.get("ports")
    vols = svc["volumes"]
    assert "zeek-logs:/logs" in vols
    assert "zeek-config:/config:ro" in vols, "采集配置必须只读共用同一份"


def test_suricata_template_shape() -> None:
    text = (ROOT / "ndr" / "suricata" / "suricata.yaml.tmpl").read_text(encoding="utf-8")
    for placeholder in ("%IFACE%", "%HOME_NET%", "%HTTP_PORTS%"):
        assert placeholder in text, f"模板缺少占位符 {placeholder}"
    assert "community-id: yes" in text
    assert "packet: no" in text
    # 只输出 alert：其它类型一个都不能开
    types_block = text.split("types:", 1)[1]
    for kind in ("flow:", "dns:", "http:", "tls:", "stats:", "files:"):
        assert f"- {kind}" not in types_block, f"eve-log 打开了 {kind}"


def test_suricata_entrypoint_renders_and_self_tests() -> None:
    text = (ROOT / "ndr" / "suricata" / "entrypoint.sh").read_text(encoding="utf-8")
    # 三个占位符都要被渲染（网段里有 /，所以必须用非 / 的分隔符）
    assert "s|%IFACE%|" in text
    assert "s|%HOME_NET%|" in text
    assert "s|%HTTP_PORTS%|" in text
    # 共享配置看门狗 + 自检模式（CI 靠它跑 suricata -T）
    assert "interface.conf" in text
    assert "--render-only" in text
    assert "suricata -T" in text
    # 规则必须从镜像同步到运行目录：基础镜像把 /var/lib/suricata 声明成 VOLUME，
    # 匿名卷在容器重建时被保留 ⇒ 不同步的话升级镜像后容器里还是旧规则（实机踩到过）。
    assert "sync_rules" in text
    # 镜像里没有 cmp（实测 MISSING cmp），只能用 sha256 比
    assert "same_file" in text
    assert "sha256sum" in text


def test_suricata_disable_list_keeps_measured_trim() -> None:
    """裁剪清单不能被子孙后代无意清空：上线当天实测裁的两类必须还在（详见 disable.conf 注释）。"""
    text = (ROOT / "ndr" / "suricata" / "disable.conf").read_text(encoding="utf-8")
    assert "1:2210000-2219999" in text, "引擎流异常（占实测告警 93.5%）的裁剪不见了"
    assert "2054407" in text, "banner 类噪音签名的裁剪不见了"
    # 清单里的每一行“非注释非空”都必须是可识别的裁剪写法
    for line in text.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        assert (
            item.startswith(("re:", "group:"))
            or item.split(":")[0].isdigit()
            or item.isdigit()
        ), f"无法识别的裁剪写法：{item}"


def test_zeek_loads_community_id_script() -> None:
    text = (ROOT / "ndr" / "zeek" / "site" / "local.zeek").read_text(encoding="utf-8")
    assert "@load policy/protocols/conn/community-id-logging" in text


def test_ci_builds_and_tests_suricata() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "shentong-suricata:latest" in ci, "CI 没有构建签名引擎镜像"
    assert "sh tests/suricata/run.sh" in ci, "CI 没有跑签名引擎自检"
    assert (ROOT / "tests" / "suricata" / "run.sh").exists()


# ---------- 字段目录（只在 NDR 侧） ----------


@pytest.fixture(scope="module")
def catalog(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("字段目录只在 NDR 侧（智能体经 MCP 取数）")
    import importlib

    return importlib.import_module("app.investigation.catalog")


def test_catalog_exposes_signature_fields(catalog: ModuleType) -> None:
    for field in (
        "community_id",
        "signature",
        "signature_id",
        "signature_severity",
        "signature_category",
    ):
        assert field in catalog.FIELDS, f"字段目录缺少 {field}"
        assert field in catalog.SUMMARY_FIELDS, f"摘要观察字段缺少 {field}"
    # 聚合维度：签名名/SID/类别是低基数，community_id 是每条流一个（不进聚合）
    assert "signature" in catalog.AGG_FIELDS
    assert "community_id" not in catalog.AGG_FIELDS


def test_source_of_recognizes_suricata(catalog: ModuleType) -> None:
    """来源嗅探（只在 NDR 侧有 source_of）：信封形态与旧扁平形态都要认。"""
    import importlib

    normalizer = importlib.import_module("app.ingestion.normalizer")
    assert normalizer.source_of(samples.DOCS["suricata_alert"]) == "suricata"
    assert normalizer.source_of(samples.DOCS["flat_suricata"]) == "suricata"
    assert normalizer.source_of(samples.DOCS["conn"]) == "zeek"
    assert normalizer.source_of({"rule": {"id": "1"}}) == "wazuh"
