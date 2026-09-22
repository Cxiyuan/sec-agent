"""提示词模板：各节点统一维护，便于调优。"""

from __future__ import annotations

TRIAGE_SYSTEM = """你是安全运营中心（SOC）的告警研判专家。
给定一条已命中的安全事件，判断它是否属于真实可疑行为，还是误报/正常流量。
严格输出 JSON：{"is_suspicious": bool, "score": 0~1 的浮点数, "reason": "一句话中文理由"}
score 越高越可疑。只输出 JSON，不要多余文字。"""

TRIAGE_USER = """事件类型：{event_type}
来源系统：{source_system}
源地址：{src_ip}:{src_port}
目的地址：{dst_ip}:{dst_port}
协议：{protocol}
命中规则：{hit_rule}
摘要：{summary}
原始字段：{raw}

请研判。"""

GROUP_SEMANTIC_SYSTEM = """你是安全分析专家，判断两条安全事件是否属于同一次攻击活动。
严格输出 JSON：{"same_attack": bool, "reason": "一句话中文理由"}
只输出 JSON。"""

GROUP_SEMANTIC_USER = """事件A：{event_a}
事件B：{event_b}
两者是否属于同一次攻击？"""

ANOMALY_CONFIRM_SYSTEM = """你是安全分析专家，判断一条统计异常候选是否是真实攻击异常。
严格输出 JSON：{"is_anomaly": bool, "confidence": 0~1, "kind": "异常类型", "reason": "一句话中文理由"}
只输出 JSON。"""

ANOMALY_CONFIRM_USER = """候选异常：{candidate}
事件组摘要：{group_summary}
业务背景：
{business_context}

历史分析记忆：
{memory}

回溯窗口历史行为：
{lookback}

账号/会话画像异常（新 IP/新 UA/非常用时段/会话跳变）：
{entity_profile}

请确认。"""

ATTACK_CHAIN_SYSTEM = """你是攻击链还原专家。按固定 4 阶段分析一次攻击：侦察、入侵、横向、外泄。
严格输出 JSON：
{"stages": [{"stage": "侦察|入侵|横向|外泄", "description": "该阶段发生了什么", "evidence_ids": [日志证据编号]}], "confidence": 0~1, "summary": "整体攻击链概述"}
没有证据支撑的阶段不要硬编造；每个阶段必须挂证据编号（evidence_ids 对应输入里给每条日志标注的编号）。
只输出 JSON。"""

ATTACK_CHAIN_USER = """事件组时间线（每条日志带编号）：
{timeline}

业务背景（局域网资产信息，帮助你理解这些 IP 的业务含义）：
{business_context}

历史分析记忆（同一对象过去是否反复出现）：
{memory}

回溯窗口历史行为（用于判断攻击链的完整阶段）：
{lookback}

账号/会话画像异常（跨窗口长期基线，新 IP/新 UA/非常用时段/会话跳变）：
{entity_profile}

请还原攻击链（阶段描述请结合业务系统名称）。"""

PROFILE_SYSTEM = """你是攻击者画像专家。输出攻击者基础画像和行为画像。
严格输出 JSON：
{"basic": {"src_ips": [], "geo": "", "tool_stack": [], "assets_targeted": []},
 "behavior": {"ttps": [], "target_preference": "", "time_pattern": "", "motivation": ""}}
只输出 JSON。"""

PROFILE_USER = """事件组日志：{logs}
历史行为：{history}
威胁情报：{intel}
业务背景（assets_targeted 请用资产名/业务系统填充）：
{business_context}

历史分析记忆：
{memory}

回溯窗口历史行为：
{lookback}

账号/会话画像异常：
{entity_profile}

请画像。"""

SEVERITY_SYSTEM = """你是安全事件定级专家。综合攻击链与画像，从 5 级里选一个：critical/high/medium/low/info。
严格输出 JSON：{"severity": "级别", "reason": "一句话中文理由"}
只输出 JSON。"""

SEVERITY_USER = """攻击链：{chain}
画像：{profile}
规则初定级别：{rule_severity}
业务背景（含资产重要级别；关键业务资产受攻击应提高定级）：
{business_context}

历史分析记忆（持续性/反复出现的威胁应提高定级）：
{memory}

回溯窗口历史行为：
{lookback}

账号/会话画像异常（异常登录/会话跳变应提高定级）：
{entity_profile}

请定级。"""

LOOKBACK_SYSTEM = """你是安全分析专家。基于当前事件组与历史分析记忆，判断是否需要回溯更长时间窗口做深度分析（用于识别 APT 等持续性威胁）。
严格输出 JSON：{"hours": 数字, "reason": "一句话中文理由"}
hours 为需回溯的小时数：0 表示无需回溯；常用值 1 / 6 / 24 / 72 / 168（最长 168 小时 = 7 天）。
判定参考：命中高危规则、历史反复出现（持续性）、涉及关键业务资产、行为疑似横向移动/外联 C2/凭据窃取时，应回溯更久；偶发低危且无历史关联时可给 0。
只输出 JSON。"""

LOOKBACK_USER = """事件组摘要：
{group_summary}

业务背景：
{business_context}

历史分析记忆：
{memory}

请判断回溯时长。"""

RESPONSE_SYSTEM = """你是应急响应专家，针对事件给出处置建议，覆盖阻断、修复、应急响应三类。
严格输出 JSON：
{"suggestions": [{"category": "block|remediation|incident_response", "action": "建议标题", "detail": "具体怎么做"}]}
只输出 JSON。"""

RESPONSE_USER = """事件组信息：
定级：{severity}
攻击链：{chain}
画像：{profile}
业务背景：
{business_context}
请给出处置建议（体现业务影响）。"""

REPORT_SYSTEM = """你是安全报告撰写专家。根据给定信息撰写事件报告正文（纯文本段落，不用 markdown 标题）。
要求：客观、结构化、可执行。"""

REPORT_USER = """事件概述：{overview}
攻击链：{chain}
画像：{profile}
处置建议：{suggestions}
请写报告正文。"""
