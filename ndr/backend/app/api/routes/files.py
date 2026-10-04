"""明文文件提取件的下载（采集批 4）。

Zeek 把明文协议（HTTP / FTP）传输的文件体落到 ``/extract/<fuid>``（见
``ndr/zeek/site/shentong-file-extract.zeek``），files.log 的 ``extracted`` 字段记住磁盘上的
文件名（当前实现 = fuid，于是路径 = ``/extract/<fuid>``），归一化后进 ES。

下载接口的取数与校验口径：

- 只接受客户端给 **fuid**：真正的文件名从 ES 里查（``extracted``），**绝不接受客户端传路径**；
- 拿到的名字必须是不含目录的纯文件名，且 realpath 后仍落在 ``settings.extract_dir`` 内
  （basename + realpath 双重校验，防目录穿越与符号链接逃逸）；
- 文件不在盘上 = 已被清理（非白名单类型或超出容量上限，见 ``ndr/zeek/extract_cleanup.py``），
  返回 404 并把原因说清楚，便于前端提示「提取件已过期」。

MIME 白名单**只在 Zeek 容器的清理助手里**（单一来源，见 ``ndr/zeek/extract_cleanup.py``）；
这里不重复判定，避免两处口径漂移。
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from app.api.deps import get_current_user
from app.config import settings
from app.db.models import User

router = APIRouter(prefix="/api/files", tags=["files"])

#: Zeek fuid 形如 ``Fx8HnP1AbCdEfGhIjK``（base62）。放宽到 URL 安全字符集，长度设上限。
_FUID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

#: 查 ES 时要的字段（省流；文件本体不在 ES 里）
_SOURCE_FIELDS = ("fuid", "extracted", "extracted_size", "extracted_cutoff", "filename", "mime_type")


def _download_name(name: str, fallback: str) -> str:
    """把文件名清洗成可以安全放进 Content-Disposition 的形式。

    去掉路径分隔与控制字符（防响应头注入），限长；空则退回 fallback（fuid）。
    """
    cleaned = re.sub(r"[\x00-\x1f\x7f/\\\"]", "_", str(name or "")).strip(". ")
    cleaned = cleaned[:128]
    return cleaned or fallback


def resolve_extract_path(extract_dir: str | os.PathLike[str], extracted: str) -> Path | None:
    """把 ES 里的 ``extracted`` 字段解析成 ``extract_dir`` 内的绝对路径。

    非法（空名 / 含目录 / 逃出根目录）返回 ``None``。
    """
    name = str(extracted or "").strip()
    # 两种分隔符都拒绝（Windows 风格也一样），避免「名字里带路径」这种歧义
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        return None
    root = Path(extract_dir).resolve()
    try:
        path = (root / name).resolve()
    except OSError:
        return None
    if path.parent != root:
        return None
    return path


def _latest_docs(fuid: str, *, size: int = 5) -> list[dict[str, Any]]:
    """按 fuid 查最新的若干条事件（``@timestamp`` 降序）。

    **不在这里用 ES 的 `exists` 查 `extracted`**：归一化文档里所有字符串字段默认是空串
    （不是缺字段），`exists` 因此几乎恒真 —— 实机量过：`exists ja4` 命中全量 5.7 万条，
    而真正有值的只有 263 条。「有没有提取件」改成在取回的文档上判空串（见 `_has_extracted`），
    与 mapping 无关、不会随字段类型漂移。
    """
    from app.ingestion import es_config
    from app.ingestion.es_client import get_es

    cfg = es_config.current()
    pattern = str(cfg.get("es.events_index") or settings.es_events_index)
    resp = get_es().search(
        index=pattern,
        query={"match": {"fuid": fuid}},
        sort=[{"@timestamp": {"order": "desc"}}],
        size=size,
        source_includes=list(_SOURCE_FIELDS),
    )
    hits = (resp.get("hits") or {}).get("hits") or []
    return [hit.get("_source") or {} for hit in hits if isinstance(hit, dict)]


def _has_extracted(doc: dict[str, Any]) -> bool:
    """这条事件是不是真的有提取件（`extracted` 非空串）。"""
    return bool(str(doc.get("extracted") or "").strip())


def is_valid_fuid(fuid: str) -> bool:
    """fuid 格式校验（MCP 的 file_content 工具复用同一口径，不另写一份正则）。"""
    return bool(_FUID_RE.match(str(fuid or "")))


def lookup_extract(fuid: str) -> dict[str, Any] | None:
    """按 fuid 找回「有提取件」的那条事件（没有则 None）。

    取数与判定口径与下载路由完全一致（`_latest_docs` + `_has_extracted`）：
    MCP 的文件内容工具与 Web 下载入口必须看到同一份事实。
    """
    for doc in _latest_docs(fuid):
        if _has_extracted(doc):
            return doc
    return None


@router.get("/{fuid}")
def download_extracted_file(
    fuid: str,
    _: Annotated[User, Depends(get_current_user)],
) -> FileResponse:
    """下载某个 fuid 的提取件（需登录）。

    **这是给智能体取证用的下载入口**（第 12 期约定的对外能力）：智能体在分析事件时
    拿到 fuid 就能取回文件本体，不要当死路由删掉。同时前端也能用同一个 URL。
    """
    if not is_valid_fuid(fuid):
        raise HTTPException(status_code=400, detail="fuid 格式不合法")

    try:
        docs = _latest_docs(fuid)
        if not docs:
            raise HTTPException(status_code=404, detail="事件库里没有这个文件（fuid）")
        doc = next((d for d in docs if _has_extracted(d)), None)
        if doc is None:
            raise HTTPException(
                status_code=404,
                detail="该文件没有提取件（来源不是 HTTP/FTP 明文，或未开启文件提取）",
            )
    except HTTPException:
        raise
    except Exception as exc:  # ES 不可用 / 索引缺失等
        raise HTTPException(status_code=503, detail=f"查询事件库失败：{str(exc)[:200]}") from exc

    path = resolve_extract_path(settings.extract_dir, str(doc.get("extracted") or ""))
    if path is None:
        raise HTTPException(status_code=400, detail="提取件字段不合法（未通过路径校验）")
    # 这里不用再判 is_symlink：resolve_extract_path() 已经 realpath 过，父目录不是提取根
    # （含指向根外的符号链接）一律提前返回 None。
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail="提取件已被清理（非白名单类型或超出容量上限，见 ndr/zeek/extract_cleanup.py）",
        )

    mime = str(doc.get("mime_type") or "") or "application/octet-stream"
    headers = {}
    if doc.get("extracted_cutoff"):
        # 被单文件上限截断：前端据此提示「只下到前 N 字节」
        headers["X-Extract-Cutoff"] = "1"
        headers["X-Extract-Size"] = str(doc.get("extracted_size") or path.stat().st_size)
    return FileResponse(
        path,
        media_type=mime,
        filename=_download_name(str(doc.get("filename") or ""), path.name),
        headers=headers or None,
    )
