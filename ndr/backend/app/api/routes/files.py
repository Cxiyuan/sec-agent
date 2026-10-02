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


def _search_fuid(fuid: str, *, require_extracted: bool) -> dict[str, Any] | None:
    """按 fuid 查一条最新的事件（``require_extracted`` 时只认有提取件的文档）。"""
    from app.ingestion import es_config
    from app.ingestion.es_client import get_es

    filters: list[dict[str, Any]] = [{"match": {"fuid": fuid}}]
    if require_extracted:
        filters.append({"exists": {"field": "extracted"}})

    cfg = es_config.current()
    pattern = str(cfg.get("es.events_index") or settings.es_events_index)
    resp = get_es().search(
        index=pattern,
        query={"bool": {"filter": filters}},
        sort=[{"@timestamp": {"order": "desc"}}],
        size=1,
        source_includes=list(_SOURCE_FIELDS),
    )
    hits = (resp.get("hits") or {}).get("hits") or []
    if not hits:
        return None
    return hits[0].get("_source") or {}


@router.get("/{fuid}")
def download_extracted_file(
    fuid: str,
    _: Annotated[User, Depends(get_current_user)],
) -> FileResponse:
    """下载某个 fuid 的提取件（需登录）。"""
    if not _FUID_RE.match(fuid):
        raise HTTPException(status_code=400, detail="fuid 格式不合法")

    try:
        doc = _search_fuid(fuid, require_extracted=True)
        if doc is None:
            exists = _search_fuid(fuid, require_extracted=False) is not None
            if exists:
                raise HTTPException(
                    status_code=404,
                    detail="该文件没有提取件（来源不是 HTTP/FTP 明文，或未开启文件提取）",
                )
            raise HTTPException(status_code=404, detail="事件库里没有这个文件（fuid）")
    except HTTPException:
        raise
    except Exception as exc:  # ES 不可用 / 索引缺失等
        raise HTTPException(status_code=503, detail=f"查询事件库失败：{str(exc)[:200]}") from exc

    path = resolve_extract_path(settings.extract_dir, str(doc.get("extracted") or ""))
    if path is None:
        raise HTTPException(status_code=400, detail="提取件字段不合法（未通过路径校验）")
    if path.is_symlink() or not path.is_file():
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
