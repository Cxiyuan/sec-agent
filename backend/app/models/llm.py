"""统一模型封装：按角色（edge / flash / deep）调 OpenAI 兼容接口。

角色 → 模型名由 app.models.registry 解析，支持后台「系统配置」运行时切换。
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import SecretStr

from app.cloud_config import cloud_api_key, cloud_base_url
from app.config import settings
from app.edge_config import EDGE_API_KEY, EDGE_MODEL_NAME, edge_base_url
from app.models.registry import resolve_model


def _edge_llm(temperature: float = 0.0, thinking: bool = False) -> ChatOpenAI:
    """本地边缘模型（初筛降噪）；thinking=True 开启服务端思考模式。"""
    kwargs: dict[str, Any] = {
        "model": EDGE_MODEL_NAME,
        "base_url": edge_base_url(),
        "api_key": SecretStr(EDGE_API_KEY),
        "temperature": temperature,
        "timeout": settings.edge_model_timeout,
        "max_retries": 1,  # 重试会再占一个槽位（服务器 16 槽）；故障时最多重试 1 次
    }
    if thinking:
        # 开启思考：max_tokens 必须调大，否则思考吃光预算导致 content 为空（finish_reason=length）
        kwargs["extra_body"] = {"chat_template_kwargs": {"enable_thinking": True}}
        kwargs["max_tokens"] = settings.edge_max_tokens_thinking
    else:
        # 非思考：收紧输出上限（实测纯 JSON 仅 60~120 token）—— CPU 上 decode 每 token 都要读
        # 一遍权重，少输出即少耗时（实测单次 14.4s 中大头是生成时间）
        kwargs["max_tokens"] = settings.edge_max_tokens
    return ChatOpenAI(**kwargs)


def _cloud_llm(role: str, temperature: float = 0.0) -> ChatOpenAI:
    """云端模型（flash 日常 / deep 深度），共用同一 MiniMax 端点。"""
    return ChatOpenAI(
        model=resolve_model(role),
        base_url=cloud_base_url(),
        api_key=SecretStr(cloud_api_key() or "not-needed"),
        temperature=temperature,
        timeout=settings.cloud_model_timeout,
        max_retries=2,
    )


def _strip_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.removeprefix("json")
        text = text.strip()
    return text


def _try_loads(text: str) -> dict[str, Any] | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _extract_braced(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        parsed = _try_loads(text[start : end + 1])
        if parsed is not None:
            return parsed
    return {}


def _extract_json(text: str) -> dict[str, Any]:
    """从模型输出里稳健地抽取 JSON（容忍 markdown 代码块包裹）。"""
    text = _strip_fence(text)
    parsed = _try_loads(text)
    if parsed is not None:
        return parsed
    return _extract_braced(text)


def _invoke(llm: ChatOpenAI, system: str, user: str) -> str:
    resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
    return str(resp.content)


def edge_invoke_json(
    system: str, user: str, temperature: float = 0.0, thinking: bool = False
) -> dict[str, Any]:
    """边缘模型（本地）返回 JSON；thinking=True 开启思考模式（仅复杂场景使用）。"""
    return _extract_json(_invoke(_edge_llm(temperature, thinking), system, user))


def flash_invoke_json(system: str, user: str, temperature: float = 0.0) -> dict[str, Any]:
    """云端 flash（日常分析）返回 JSON。"""
    return _extract_json(_invoke(_cloud_llm("flash", temperature), system, user))


def deep_invoke_json(system: str, user: str, temperature: float = 0.0) -> dict[str, Any]:
    """云端 deep（深度分析）返回 JSON。"""
    return _extract_json(_invoke(_cloud_llm("deep", temperature), system, user))


def flash_invoke_text(system: str, user: str, temperature: float = 0.0) -> str:
    """云端 flash 返回纯文本。"""
    return _invoke(_cloud_llm("flash", temperature), system, user)
