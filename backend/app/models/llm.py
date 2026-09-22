"""统一模型封装：边缘/云端都走 OpenAI 兼容接口，可热切换。"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import SecretStr

from app.config import settings


def _edge_llm(temperature: float = 0.0) -> ChatOpenAI:
    return ChatOpenAI(
        model=settings.edge_model_name,
        base_url=settings.edge_model_base_url,
        api_key=SecretStr(settings.edge_model_api_key or "not-needed"),
        temperature=temperature,
        timeout=settings.edge_model_timeout,
        max_retries=2,
    )


def _cloud_llm(temperature: float = 0.0) -> ChatOpenAI:
    return ChatOpenAI(
        model=settings.cloud_model_name,
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


def edge_invoke_json(system: str, user: str, temperature: float = 0.0) -> dict[str, Any]:
    """调用边缘模型并要求返回 JSON。"""
    llm = _edge_llm(temperature)
    resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
    return _extract_json(str(resp.content))


def cloud_invoke_json(system: str, user: str, temperature: float = 0.0) -> dict[str, Any]:
    """调用云端模型并要求返回 JSON。"""
    llm = _cloud_llm(temperature)
    resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
    return _extract_json(str(resp.content))


def cloud_invoke_text(system: str, user: str, temperature: float = 0.0) -> str:
    """调用云端模型返回纯文本。"""
    llm = _cloud_llm(temperature)
    resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
    return str(resp.content)
