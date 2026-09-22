"""统一模型封装：按角色（edge / flash / deep）调 OpenAI 兼容接口。

角色 → 模型名由 app.models.registry 解析，支持后台「系统配置」运行时切换。
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import SecretStr

from app.config import settings
from app.models.registry import resolve_model


def _edge_llm(temperature: float = 0.0) -> ChatOpenAI:
    """本地边缘模型（初筛降噪）。"""
    return ChatOpenAI(
        model=resolve_model("edge"),
        base_url=settings.edge_model_base_url,
        api_key=SecretStr(settings.edge_model_api_key or "not-needed"),
        temperature=temperature,
        timeout=settings.edge_model_timeout,
        max_retries=2,
    )


def _cloud_llm(role: str, temperature: float = 0.0) -> ChatOpenAI:
    """云端模型（flash 日常 / deep 深度），共用同一 one-api 端点。"""
    return ChatOpenAI(
        model=resolve_model(role),
        base_url=settings.cloud_model_base_url,
        api_key=SecretStr(settings.cloud_model_api_key or "not-needed"),
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


def edge_invoke_json(system: str, user: str, temperature: float = 0.0) -> dict[str, Any]:
    """边缘模型（本地）返回 JSON。"""
    return _extract_json(_invoke(_edge_llm(temperature), system, user))


def flash_invoke_json(system: str, user: str, temperature: float = 0.0) -> dict[str, Any]:
    """云端 flash（日常分析）返回 JSON。"""
    return _extract_json(_invoke(_cloud_llm("flash", temperature), system, user))


def deep_invoke_json(system: str, user: str, temperature: float = 0.0) -> dict[str, Any]:
    """云端 deep（深度分析）返回 JSON。"""
    return _extract_json(_invoke(_cloud_llm("deep", temperature), system, user))


def flash_invoke_text(system: str, user: str, temperature: float = 0.0) -> str:
    """云端 flash 返回纯文本。"""
    return _invoke(_cloud_llm("flash", temperature), system, user)
