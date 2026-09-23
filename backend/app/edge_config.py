"""边缘模型（本地 llama-server）连接信息：固化常量 + IP 运行时拼接 + 思考模式开关。

按对接文档固化（写死，环境变量不可覆盖）：
- api_key / 模型名（真实路径）/ 端口 / 路径 均在此固化
- 唯一可变的是 IP：后台「边缘模型」面板输入，存 SystemConfig「edge.model.ip」
- 模型名对外统一映射为「edge」，不暴露真实路径字符串

思考模式（reasoning）：服务端默认关闭，请求级按需开启（chat_template_kwargs.enable_thinking）。
启用场景规则（后台可配，见 edge_thinking_*）：
- 语义关联（判断两个事件组是否同一次攻击）→ 默认开
- triage 复杂研判（Web 攻击/恶意软件/横向移动/协议异常等）→ 默认开
- triage 简单研判（扫描/爆破/常规连接）→ 默认关
"""

from __future__ import annotations

from app.runtime_config import get as runtime_get

# ---------- 固化连接信息（环境变量不可覆盖） ----------
EDGE_API_KEY = "qaz@7410"
EDGE_MODEL_NAME = "/opt/models/Qwen3.8-2B-Q8_0.gguf"
EDGE_PORT = 8080
EDGE_BASE_PATH = "/v1"
EDGE_DEFAULT_IP = "172.16.196.80"
EDGE_MODEL_LABEL = "edge"  # 对外展示名（不暴露真实路径）

# 复杂研判事件类型：triage 里这些类型值得开思考（payload 语义复杂，需多步推理判真伪）
COMPLEX_TRIAGE_EVENT_TYPES = {
    "web_attack",
    "wazuh_web_attack",
    "wazuh_malware",
    "wazuh_vulnerability",
    "wazuh_system_change",
    "file_transfer",
    "http_upload",
    "dns_anomaly",
    "tls_anomaly",
    "protocol_anomaly",
    "smtp_abuse",
}


# ---------- base_url 拼接 ----------


def edge_current_ip() -> str:
    """当前生效的 IP（后台配置优先，默认用文档实测值）。"""
    ip = str(runtime_get("edge.model.ip", EDGE_DEFAULT_IP) or "").strip()
    return ip or EDGE_DEFAULT_IP


def edge_base_url_for(ip: str) -> str:
    """按给定 IP 拼 base_url（测试连接用）。"""
    host = (ip or "").strip()
    return f"http://{host}:{EDGE_PORT}{EDGE_BASE_PATH}"


def edge_base_url() -> str:
    """当前生效的 base_url。"""
    return edge_base_url_for(edge_current_ip())


# ---------- 思考模式开关（后台可配） ----------


def edge_thinking_merge() -> bool:
    """语义关联（判断两个事件组是否同一次攻击）是否开思考。"""
    return bool(runtime_get("edge_thinking.semantic_merge", True))


def edge_thinking_for(event_type: str | None) -> bool:
    """triage 研判是否开思考：复杂类型默认开、简单类型默认关（均可在后台改）。"""
    if event_type in COMPLEX_TRIAGE_EVENT_TYPES:
        return bool(runtime_get("edge_thinking.triage_complex", True))
    return bool(runtime_get("edge_thinking.triage_simple", False))
