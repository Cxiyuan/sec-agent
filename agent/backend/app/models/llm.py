"""统一模型封装：按角色（edge / flash / deep）调 OpenAI 兼容接口。

角色 → 模型名由 app.models.registry 解析，支持后台「系统配置」运行时切换。

云端调用统一经过 ``_cloud_retry``：**并发闸门 + 限流退避**。
为什么需要：节点里的"逐个事件组"循环会同时发多个云端请求，不限制并发很容易吃
429/5xx，而隐性重试（客户端自带 max_retries）又无法计数、无法统一退避。
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any, TypeVar

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import SecretStr

from app.cloud_config import cloud_api_key, cloud_base_url
from app.config import settings
from app.edge_config import EDGE_API_KEY, EDGE_MODEL_NAME, edge_base_url
from app.models.registry import resolve_model
from app.runtime_config import get as runtime_get
from app.workers.log import get_logger

log = get_logger(__name__)

T = TypeVar("T")


class _CloudLimiter:
    """云端并发闸门（**动态上限**：后台改并发数无需重启）。

    用条件变量而不是 Semaphore：Semaphore 容量在创建时固定，而本项目允许热调并发上限。
    等待带超时轮询：任何异常路径也不会把自己永久卡死。
    """

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._active = 0

    @contextmanager
    def slot(self, limit: int):
        limit = max(1, _as_int(limit, 1))
        with self._cond:
            while self._active >= limit:
                self._cond.wait(timeout=5.0)
            self._active += 1
        try:
            yield
        finally:
            with self._cond:
                self._active -= 1
                self._cond.notify()


_LIMITER = _CloudLimiter()

# 可重试的错误特征（限流 / 网关 / 超时 / **瞬时网络错误**）；401 这类配置错误**不**重试
#
# 为什么要包含连接类错误：api.minimaxi.com 会解析出十几个 CDN 地址，部分地址在客户网络里
# 不通（部署实测），于是会出现"时而成功时而 Connection error"的间歇失败。
# 不重试的话，一次网络抖动就会降级成规则定级（表现为大量事件组都是 info、不出报告）。
_RETRY_HINTS = (
    "429",
    "rate limit",
    "ratelimit",
    "too many requests",
    "timeout",
    "timed out",
    "connection error",
    "connection reset",
    "connection aborted",
    "connection refused",
    "connect timeout",
    "read timeout",
    "temporary failure in name resolution",
    "name or service not known",
    "eof occurred",
    "502",
    "503",
    "504",
    "overload",
    "temporarily",
)


def _is_retryable(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None) or getattr(exc, "http_status", None)
    if isinstance(status, int):
        return status == 429 or 500 <= status < 600
    text = str(exc).lower()
    return any(hint in text for hint in _RETRY_HINTS)


def _as_int(value: Any, default: int) -> int:
    """安全转 int（配置可能是字符串或脏值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _cloud_retry(call: Callable[[], T]) -> T:
    """云端调用：并发闸门 + 限流/超时指数退避。

    只对「可重试」错误退避；401（密钥错）等直接抛出交给上层兜底——
    否则会把一个明确的配置错误重试成几分钟的等待。
    """
    attempts = max(1, _as_int(settings.cloud_max_retries, 3))
    base = max(0.1, _as_float(settings.cloud_retry_base_seconds, 2.0))
    for attempt in range(attempts):
        limit = _as_int(runtime_get("cloud_max_concurrency", settings.cloud_max_concurrency), 4)
        try:
            with _LIMITER.slot(limit):
                return call()
        except Exception as exc:
            if not _is_retryable(exc):
                raise
            if attempt >= attempts - 1:
                raise
            delay = base * (2**attempt)
            log.warning(
                "云端调用失败（第 %d/%d 次，%s），%.1fs 后重试：%s",
                attempt + 1,
                attempts,
                type(exc).__name__,
                delay,
                str(exc)[:160],
            )
            time.sleep(delay)
    raise RuntimeError("云端调用失败（重试耗尽）")


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
    """云端模型（flash 日常 / deep 深度），共用同一 MiniMax 端点。

    ``max_retries=0``：重试统一由 ``_cloud_retry`` 负责（能计数、能统一退避、能受并发闸门约束）。
    ``max_tokens``：**显式设置**。不设时服务端默认值偏小，调查的 ``finish`` 结论 JSON（含 path/
    timeline/iocs）会被截断 → 解析失败 → 整轮白跑（实测就是这个原因）。
    """
    return ChatOpenAI(
        model=resolve_model(role),
        base_url=cloud_base_url(),
        api_key=SecretStr(cloud_api_key() or "not-needed"),
        temperature=temperature,
        timeout=settings.cloud_model_timeout,
        max_retries=0,
        # langchain 该字段对外别名为 max_completion_tokens（运行期 max_tokens 也生效，
        # 但显式关键字会被类型检查器拒绝）
        max_completion_tokens=_cloud_max_tokens(role),
    )


def _cloud_max_tokens(role: str) -> int:
    """云端输出上限（后台可改，即时生效）。deep 要大得多：结论 JSON 体积大。"""
    if role == "deep":
        return max(
            256, _as_int(runtime_get("cloud_max_tokens_deep", settings.cloud_max_tokens_deep), 8192)
        )
    return max(
        256, _as_int(runtime_get("cloud_max_tokens_flash", settings.cloud_max_tokens_flash), 4096)
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


_TRUNCATED_TOTAL = 0


def truncated_total() -> int:
    """本进程内被 max_tokens 截断的云端调用次数（可查，不静默）。"""
    return _TRUNCATED_TOTAL


def json_or_diag(text: str) -> tuple[dict[str, Any], str]:
    """解析 JSON，失败时给出**可回灌给模型**的诊断（用于自纠正，而不是只说“无效”）。

    为什么需要：原来失败只往对话里塞一句“请严格输出 JSON”，模型不知道自己错在哪；
    把“花括号不配对/原文片段”回灌后，模型往往下一次就能纠正。
    """
    raw = (text or "").strip()
    if not raw:
        return {}, "输出为空（没有任何内容）"
    parsed = _try_loads(_strip_fence(raw))
    if parsed is not None:
        return parsed, ""
    braced = _extract_braced(raw)
    if braced:
        return braced, ""
    opens, closes = raw.count("{"), raw.count("}")
    if opens > closes:
        reason = f"花括号不配对（{{ 比 }} 多 {opens - closes} 个），很可能输出被截断"
    elif "{" not in raw:
        reason = "输出里没有 JSON 对象（只有解释性文字或代码块）"
    else:
        reason = "不是合法的 JSON 对象"
    return {}, f"{reason}。你上一条的原文片段：{raw[:400]}"


def _invoke(llm: ChatOpenAI, system: str, user: str) -> tuple[str, str]:
    """调模型，返回 (内容, finish_reason)。"""
    resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
    meta = getattr(resp, "response_metadata", None) or {}
    finish = str(meta.get("finish_reason") or "")
    if finish in ("length", "max_tokens"):
        global _TRUNCATED_TOTAL
        _TRUNCATED_TOTAL += 1
        log.warning(
            "云端输出被 max_tokens 截断（累计 %d 次）——结论 JSON 会被解析失败，"
            "请在系统配置里调大 cloud_max_tokens_deep/flash",
            _TRUNCATED_TOTAL,
        )
    return str(resp.content), finish


def edge_invoke_json(
    system: str, user: str, temperature: float = 0.0, thinking: bool = False
) -> dict[str, Any]:
    """边缘模型（本地）返回 JSON；thinking=True 开启思考模式（仅复杂场景使用）。"""
    return _extract_json(_invoke(_edge_llm(temperature, thinking), system, user)[0])


def flash_invoke_json(system: str, user: str, temperature: float = 0.0) -> dict[str, Any]:
    """云端 flash（日常分析）返回 JSON。"""
    llm = _cloud_llm("flash", temperature)
    return _extract_json(_cloud_retry(lambda: _invoke(llm, system, user))[0])


def deep_invoke_json(system: str, user: str, temperature: float = 0.0) -> dict[str, Any]:
    """云端 deep（深度分析）返回 JSON。"""
    llm = _cloud_llm("deep", temperature)
    return _extract_json(_cloud_retry(lambda: _invoke(llm, system, user))[0])


def invoke_json_diag(
    system: str, user: str, *, role: str = "deep", temperature: float = 0.0
) -> tuple[dict[str, Any], str]:
    """返回 (JSON, 失败诊断)。失败诊断可直接回灌给模型做自纠正（调查循环用）。"""
    llm = _cloud_llm(role, temperature)
    content, _finish = _cloud_retry(lambda: _invoke(llm, system, user))
    return json_or_diag(content)


def flash_invoke_text(system: str, user: str, temperature: float = 0.0) -> str:
    """云端 flash 返回纯文本。"""
    llm = _cloud_llm("flash", temperature)
    return _cloud_retry(lambda: _invoke(llm, system, user))[0]
