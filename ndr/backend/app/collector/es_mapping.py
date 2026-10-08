"""ES 事件索引模板里的 ``mappings``：只声明**自由形态**字段的类型。

为什么必须有这个文件：Logstash 输出用的是 ``manage_template => false``（见
`app/collector/template.py`），索引由 ES 自动创建，字段类型**全靠动态映射推断**。
而 ``raw`` 装的是各来源的原文，同一路径在不同来源里形状并不一样：

    Zeek conn  → raw.id 是对象 {"orig_h": …, "resp_p": …}
    Zeek ocsp  → raw.id 是字符串 "FSMOFV3XzYW6HJTLuc"

动态映射按**先到的形状**把 ``raw.id`` 定成 object，此后所有「raw.id 是字符串」的文档都被
ES 判 ``document_parsing_exception`` 整条 400 丢掉，Logstash 只留一行 WARN —— 采集侧
Filebeat/Redis/归一化三段都是好的。

为什么是 ``enabled: false`` 而不是 ``flattened``（8.15.3 实测，临时索引）：

    flattened（默认参数）      → 单个值 > 32766 字节就**整条 400 丢弃**：
                                 实测一条 LLM 日志 `raw.resp_body` 32,771 字节
                                 → "Flattened field [raw] contains one immense field
                                    whose keyed encoding is longer than the allowed
                                    max length of 32766 bytes"
    flattened + ignore_above  → 可绕过（1024 / 32766 都实测可用，`raw.log_type` 仍可查），
                                 但仍然是「有形状前提的解析」，换个更大的值还会丢
    object + enabled: false   → 不做任何解析，结构上**不可能**再出现文档被拒

代价：``raw.*`` 不进 `_mapping`，所以 term 查询不到这些路径（``mapping_types`` 也列不出，
但 `app/investigation/catalog.py` 的 FIELDS 里本来就没有 `raw.*` 条目，MCP 工具是按字面
路径查询的，不受影响）。**原文本身不丢**：字段仍在 ``_source`` 里原样保留，实测那条
32KB 文档 reindex 后 ``_source.raw`` 仍是 28 个键的完整 dict，`app/mcp/ndr_tools.py` 的原文
取证走的就是 ``_source``。若将来真的要按 `raw.*` 检索，就改回
``{"type": "flattened", "ignore_above": 1024}``（已实测可用）。
"""

from __future__ import annotations

from typing import Any

#: `ensure_retention` 下发进 `put_index_template(template={"mappings": ...})`。
#: 只声明 `raw`：其余字段（归一化后的扁平结构）照旧动态映射，好让新字段无需改代码即可查询。
EVENT_INDEX_MAPPINGS: dict[str, Any] = {
    "properties": {
        "raw": {"type": "object", "enabled": False},
    }
}


def is_safe_raw_mapping(raw: object) -> bool:
    """判断索引里 ``raw`` 的既有映射是否已经不会被动态映射坑到。

    只有 ``enabled: false`` 的对象映射算安全（不解析 ⇒ 形状冲突不可能触发 400）。
    ``flattened`` 虽然能容纳混合形状，但单值超过 32,766 字节仍会整条丢弃，所以**不算安全**
    —— 已建的 flattened 索引需要 reindex 到本模板。

    参数是 `_mapping` 里 ``properties.raw`` 的原始值；没建过 ``raw`` 的索引会拿到
    ``None`` 或 ``{}``（那时 ES 一定会走动态映射，同样不安全）。
    """
    if not isinstance(raw, dict):
        return False
    return raw.get("type") == "object" and raw.get("enabled") is False
