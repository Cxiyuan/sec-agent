"""边缘模型（本地 llama-server）连接信息 + 思考模式开关。

连接信息**全部来自部署环境**（`ST_EDGE_*`，见 `agent/backend/app/config.py`）：
- api_key / 模型名 / 端口 / 路径 都是可配置项，默认值与环境无关（空 / 8080 / /v1）
- IP：后台「边缘模型」面板输入，存 SystemConfig「edge.model.ip」；默认回环地址
- 模型名对外统一映射为「edge」，不暴露真实路径字符串

为什么不再写死（2026-10 硬编码审计）：原来 api_key 与模型文件路径是代码里的字面量
（某个客户环境的密钥与 `/opt/models/xxx.gguf`）—— 通用产品发布不能带这些，
客户网络环境产生的内容属于**部署配置/用户数据**，不是代码。

思考模式（reasoning）：服务端默认关闭，请求级按需开启（chat_template_kwargs.enable_thinking）。
启用场景规则（后台可配，见 edge_thinking_*）：
- 语义关联（判断两个事件组是否同一次攻击）→ 默认开
- triage 复杂研判（Web 攻击/恶意软件/横向移动/协议异常等）→ 默认开
- triage 简单研判（扫描/爆破/常规连接）→ 默认关
"""

from __future__ import annotations

from app.config import settings
from app.runtime_config import get as runtime_get

# ---------- 连接信息（由部署环境给，见模块说明） ----------
EDGE_API_KEY = settings.edge_api_key
EDGE_MODEL_NAME = settings.edge_model_name
EDGE_PORT = settings.edge_port
EDGE_BASE_PATH = settings.edge_base_path
EDGE_DEFAULT_IP = settings.edge_default_ip  # 环境无关的回环默认值；部署时在后台填真实地址
EDGE_MODEL_LABEL = "edge"  # 对外展示名（不暴露真实路径）

# 复杂研判事件类型：triage 里这些类型值得开思考（payload 语义复杂，需多步推理判真伪）
COMPLEX_TRIAGE_EVENT_TYPES = {
    "web_attack",
    "file_transfer",
    "http_upload",
    "dns_anomaly",
    "tls_anomaly",
    "protocol_anomaly",
    "smtp_abuse",
}


# ---------- base_url 拼接 ----------


def edge_current_ip() -> str:
    """当前生效的 IP（后台配置优先，未配置时用回环地址）。"""
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
