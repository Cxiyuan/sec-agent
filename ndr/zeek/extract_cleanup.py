#!/usr/bin/env python3
"""深瞳 · 提取件清理（采集批 4）。

Zeek 侧只负责把明文文件提取到 ``/extract/<fuid>``（见 ``site/shentong-file-extract.zeek``）；
Zeek 脚本没有删文件的 BIF，所以「只留白名单类型 + 控制磁盘占用」在这里做：

1. 读 ``<logs>/files.log`` 与 ``<logs>/files.*.log``（轮转件），建 ``fuid -> mime_type`` 索引；
2. 目录里的提取件若在 files.log 里**找不到记录**，或 ``mime_type`` 不在白名单 → 删除；
3. 剩余总量超过 ``--max-bytes`` 时，按 mtime 从最老开始淘汰，直到不超上限。

由 ``entrypoint.sh`` 的 ``start_extract_cleanup_loop`` 周期调用（默认 300 秒）。幂等、可重入；
``--min-age`` 保护仍在写入的文件（默认 120 秒，被跳过的文件下一轮再判）。

白名单是本项目的**唯一来源**：下载接口 ``GET /api/files/{fuid}`` 不重复判定 MIME，
只信「文件在提取目录里」这个事实，因此这里的判定口径即「哪些文件可被下载」。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

# 允许留存的 MIME 类型（文档 / 归档 / 文本类；可执行文件、图片、音视频等一律不留）。
# 以 ".*" 结尾的条目按前缀匹配，覆盖 Office / ODF 家族的一长串具体类型。
DEFAULT_MIME_ALLOW: tuple[str, ...] = (
    # 文本与结构化文本
    "text/plain",
    "text/csv",
    "text/html",
    "text/xml",
    "application/xml",
    "application/json",
    "application/rtf",
    # 文档
    "application/pdf",
    "message/rfc822",
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.*",
    "application/vnd.oasis.opendocument.*",
    # 归档（恶意样本常见投递载体，且调查时需要原文件）
    "application/zip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/x-tar",
    "application/gzip",
    "application/x-gzip",
    "application/x-bzip2",
    "application/x-compress",
)


def normalize_mime(mime: str) -> str:
    """取 MIME 的**主类型**：剥掉 ``; charset=utf-8`` 这类参数、去空白、转小写。

    files.log 里的 ``mime_type`` 直接来自 HTTP 的 ``Content-Type``，实测会带参数
    （``text/html; charset=utf-8``）甚至大小写不一；不归一化就会把正常网页当
    "白名单外"删掉。
    """
    return (mime or "").split(";", 1)[0].strip().lower()


def mime_allowed(mime: str, allow: tuple[str, ...] | list[str]) -> bool:
    """判断 MIME 是否在白名单里（支持 ``application/foo.*`` 前缀条目）。

    比较前先过 :func:`normalize_mime`（剥参数 / 转小写）。``mime`` 为空
    （files.log 没记类型）视为不允许 —— 宁可少留一个可疑文件，
    也不要留一个来源不明的二进制。
    """
    candidate = normalize_mime(mime)
    if not candidate:
        return False
    for item in allow:
        pattern = (item or "").strip().lower()
        if not pattern:
            continue
        if pattern.endswith(".*"):
            if candidate.startswith(pattern[:-1]):
                return True
        elif candidate == pattern:
            return True
    return False


def load_fuid_mime(log_dir: str | os.PathLike[str]) -> dict[str, str]:
    """扫 ``files.*.log``（轮转件，旧）与 ``files.log``（活动日志，新），返回 ``fuid -> mime_type``。

    读取顺序是「轮转件 → 活动日志」，**后读的覆盖先读的**，于是同一 fuid 以活动日志里的
    最新记录为准（文件被轮转走以后仍能查到历史记录）。

    files.log 是 JSON 行格式（shentong-json 保证）；读不动/半行（正在写）就跳过，
    不影响其它记录 —— 被跳过的文件至多在下一轮因为「找不到记录」而删除。
    """
    index: dict[str, str] = {}
    directory = Path(log_dir)
    if not directory.is_dir():
        return index

    paths: list[Path] = sorted(directory.glob("files.*.log"))
    paths.append(directory / "files.log")
    for path in paths:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    try:
                        doc = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(doc, dict):
                        continue
                    fuid = str(doc.get("fuid") or "")
                    if fuid:
                        index[fuid] = str(doc.get("mime_type") or "")
        except OSError as exc:  # 文件被轮转掉 / 权限问题：跳过该文件
            print(f"[extract-cleanup] 读取 {path} 失败：{exc}", file=sys.stderr)
    return index


def cleanup(
    extract_dir: str | os.PathLike[str],
    fuid_mime: dict[str, str],
    max_bytes: int,
    min_age: float,
    allow: tuple[str, ...] | list[str] = DEFAULT_MIME_ALLOW,
    now: float | None = None,
    dry_run: bool = False,
    verbose: bool = False,
) -> dict[str, int]:
    """清理一轮，返回统计字典（keep / drop_no_record / drop_mime / evict / freed_bytes）。

    - ``min_age``：mtime 距今不足这个秒数的文件跳过（可能还在写）；
    - 先按白名单删，再按 mtime 从最老淘汰直到总量 ≤ ``max_bytes``；
    - ``max_bytes <= 0`` 表示不做总量淘汰（只按白名单删）。
    """
    stats = {"keep": 0, "drop_no_record": 0, "drop_mime": 0, "evict": 0, "freed_bytes": 0}
    directory = Path(extract_dir)
    if not directory.is_dir():
        return stats

    current = time.time() if now is None else now
    kept: list[tuple[float, int, Path]] = []  # (mtime, size, path)

    for entry in sorted(directory.iterdir()):
        name = entry.name
        if name.startswith("."):
            continue
        try:
            if entry.is_symlink() or not entry.is_file():
                continue
            info = entry.stat()
        except OSError:
            continue

        if current - info.st_mtime < min_age:
            continue

        fuid = name
        if fuid not in fuid_mime:
            reason = "no_record"
        elif not mime_allowed(fuid_mime[fuid], allow):
            reason = "mime"
        else:
            kept.append((info.st_mtime, info.st_size, entry))
            continue

        stats["drop_no_record" if reason == "no_record" else "drop_mime"] += 1
        stats["freed_bytes"] += info.st_size
        if verbose:
            detail = fuid_mime.get(fuid, "") or "-"
            print(f"[extract-cleanup] 删除 {name}（{reason}: {detail}）")
        if not dry_run:
            try:
                entry.unlink()
            except OSError as exc:
                stats["freed_bytes"] -= info.st_size
                print(f"[extract-cleanup] 删除 {name} 失败：{exc}", file=sys.stderr)

    stats["keep"] = len(kept)

    if max_bytes > 0:
        total = sum(size for _, size, _ in kept)
        # 最老优先淘汰；同 mtime 时按文件名稳定排序
        for mtime, size, path in sorted(kept, key=lambda item: (item[0], item[2].name)):
            if total <= max_bytes:
                break
            stats["evict"] += 1
            stats["freed_bytes"] += size
            total -= size
            stats["keep"] -= 1
            if verbose:
                print(f"[extract-cleanup] 淘汰 {path.name}（超容量上限）")
            if not dry_run:
                try:
                    path.unlink()
                except OSError as exc:
                    stats["freed_bytes"] -= size
                    stats["keep"] += 1
                    print(f"[extract-cleanup] 淘汰 {path.name} 失败：{exc}", file=sys.stderr)

    return stats


def _human(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} TiB"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="深瞳 · Zeek 提取件清理")
    parser.add_argument("--dir", default="/extract", help="提取件目录（默认 /extract）")
    parser.add_argument("--logs", default="/logs", help="Zeek 日志目录（默认 /logs）")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=10 * 1024**3,
        help="提取目录容量上限，超过则按 mtime 淘汰最老的（默认 10 GiB；0 = 不限）",
    )
    parser.add_argument(
        "--min-age",
        type=float,
        default=120.0,
        help="mtime 距今不足该秒数的文件跳过，避免动正在写的文件（默认 120）",
    )
    parser.add_argument(
        "--mime-allow",
        default="",
        help="覆盖默认白名单（逗号分隔；条目可用 application/foo.* 前缀匹配）",
    )
    parser.add_argument("--dry-run", action="store_true", help="只统计不删除")
    parser.add_argument("-v", "--verbose", action="store_true", help="逐个打印被删除的文件")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    allow: tuple[str, ...] = tuple(
        part.strip() for part in args.mime_allow.split(",") if part.strip()
    ) or DEFAULT_MIME_ALLOW

    index = load_fuid_mime(args.logs)
    stats = cleanup(
        args.dir,
        index,
        max_bytes=args.max_bytes,
        min_age=args.min_age,
        allow=allow,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )
    print(
        "[extract-cleanup] "
        f"目录={args.dir} 上限={_human(args.max_bytes) if args.max_bytes > 0 else '不限'} "
        f"files.log 记录={len(index)} "
        f"保留={stats['keep']} 白名单外删除={stats['drop_mime']} "
        f"无记录删除={stats['drop_no_record']} 超限淘汰={stats['evict']} "
        f"释放={_human(stats['freed_bytes'])}"
        + ("（dry-run）" if args.dry_run else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
