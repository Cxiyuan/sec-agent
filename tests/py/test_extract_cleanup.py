"""批 4：提取件清理助手（``ndr/zeek/extract_cleanup.py``）的行为。

Zeek 脚本没有删文件的 BIF，所以「只留白名单类型 + 控制目录容量」全在这个助手里做；
它同时是「哪些提取件可以下载」的唯一口径（下载接口不重复判定 MIME），
因此这里把白名单、无记录、在写保护与容量淘汰都真跑一遍（纯 Python，两个栈都跑）。
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "ndr" / "zeek" / "extract_cleanup.py"
ENTRYPOINT = ROOT / "ndr" / "zeek" / "entrypoint.sh"
DOCKERFILE = ROOT / "ndr" / "zeek" / "Dockerfile"
LOCAL_ZEEK = ROOT / "ndr" / "zeek" / "site" / "local.zeek"

#: 固定"当前时刻"，避免用例依赖真实时钟
NOW = 1_800_000_000.0


def _load_helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("shentong_extract_cleanup", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = _load_helper()


def _write(path: Path, size: int, mtime: float | None = None) -> Path:
    path.write_bytes(b"x" * size)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


def _write_log(log_dir: Path, name: str, entries: list[dict[str, object]]) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(entry) for entry in entries]
    (log_dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_whitelist_excludes_executables_and_unknown() -> None:
    allow = helper.DEFAULT_MIME_ALLOW
    assert "application/pdf" in allow
    assert "application/zip" in allow
    # 可执行体与未知类型绝不下载
    assert not helper.mime_allowed("application/octet-stream", allow)
    assert not helper.mime_allowed("application/x-dosexec", allow)
    assert not helper.mime_allowed("", allow)
    # Office / ODF 家族用前缀条目覆盖
    assert helper.mime_allowed(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document", allow
    )
    assert helper.mime_allowed("application/vnd.oasis.opendocument.text", allow)
    # JSON 的两条常见写法都要在：Zeek 对请求体实测报 text/json
    assert helper.mime_allowed("application/json", allow)
    assert helper.mime_allowed("text/json", allow)


def test_mime_comparison_strips_parameters_and_case() -> None:
    allow = helper.DEFAULT_MIME_ALLOW
    # HTTP 的 Content-Type 实测带参数（还可能有大小写），不归一化会把正常网页删掉
    assert helper.normalize_mime("text/html; charset=utf-8") == "text/html"
    assert helper.mime_allowed("text/html; charset=utf-8", allow)
    assert helper.mime_allowed("Text/HTML", allow)
    assert helper.mime_allowed("application/PDF; version=1.7", allow)
    assert not helper.mime_allowed("application/octet-stream; charset=binary", allow)
    assert not helper.mime_allowed("   ", allow)
    # 自定义白名单也要归一化（命令行传大写/带空格不该失效）
    assert helper.mime_allowed("text/plain; charset=gbk", [" Text/Plain "])


def test_load_fuid_mime_reads_plain_and_rotated_log(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    _write_log(logs, "files.2026-10-01.log", [{"fuid": "FxOld", "mime_type": "application/pdf"}])
    plain = logs / "files.log"
    _write_log(logs, "files.log", [{"fuid": "FxNew", "mime_type": "text/plain"}])
    # 半行（正在写）与非 JSON 噪声都要跳过，不能带崩整轮
    with plain.open("a", encoding="utf-8") as fh:
        fh.write('{"fuid":"FxBrok\n')
        fh.write("not json at all\n")

    index = helper.load_fuid_mime(logs)
    assert index == {"FxOld": "application/pdf", "FxNew": "text/plain"}
    # 后读到的记录（files.log 比轮转件新）覆盖旧值
    _write_log(logs, "files.log", [{"fuid": "FxOld", "mime_type": "application/zip"}])
    assert helper.load_fuid_mime(logs)["FxOld"] == "application/zip"


def test_missing_logs_dir_is_not_fatal(tmp_path: Path) -> None:
    assert helper.load_fuid_mime(tmp_path / "nope") == {}


def test_cleanup_keeps_allowed_and_drops_others(tmp_path: Path) -> None:
    extract = tmp_path / "extract"
    logs = tmp_path / "logs"
    extract.mkdir()
    _write(extract / "FxKeep", 10, NOW - 3600)
    _write(extract / "FxExe", 20, NOW - 3600)
    _write(extract / "FxNone", 30, NOW - 3600)
    _write_log(
        logs,
        "files.log",
        [
            {"fuid": "FxKeep", "mime_type": "application/pdf"},
            {"fuid": "FxExe", "mime_type": "application/x-dosexec"},
        ],
    )

    stats = helper.cleanup(
        extract, helper.load_fuid_mime(logs), max_bytes=0, min_age=0, now=NOW
    )

    assert (extract / "FxKeep").exists()
    assert not (extract / "FxExe").exists()  # 白名单外
    assert not (extract / "FxNone").exists()  # files.log 里没有记录
    assert stats["keep"] == 1
    assert stats["drop_mime"] == 1
    assert stats["drop_no_record"] == 1
    assert stats["freed_bytes"] == 50


def test_min_age_protects_file_still_being_written(tmp_path: Path) -> None:
    extract = tmp_path / "extract"
    logs = tmp_path / "logs"
    extract.mkdir()
    _write(extract / "FxFresh", 10, NOW)  # mtime = 现在
    _write_log(logs, "files.log", [{"fuid": "FxFresh", "mime_type": "application/x-dosexec"}])
    index = helper.load_fuid_mime(logs)

    helper.cleanup(extract, index, max_bytes=0, min_age=120, now=NOW)
    assert (extract / "FxFresh").exists(), "在写文件不该被删"

    helper.cleanup(extract, index, max_bytes=0, min_age=0, now=NOW)
    assert not (extract / "FxFresh").exists(), "过了保护期就该按白名单删掉"


def test_evicts_oldest_when_over_capacity(tmp_path: Path) -> None:
    extract = tmp_path / "extract"
    logs = tmp_path / "logs"
    extract.mkdir()
    _write(extract / "FxOld", 100, NOW - 3000)
    _write(extract / "FxMid", 100, NOW - 2000)
    _write(extract / "FxNew", 100, NOW - 1000)
    _write_log(
        logs,
        "files.log",
        [
            {"fuid": "FxOld", "mime_type": "application/pdf"},
            {"fuid": "FxMid", "mime_type": "application/pdf"},
            {"fuid": "FxNew", "mime_type": "application/pdf"},
        ],
    )

    stats = helper.cleanup(
        extract, helper.load_fuid_mime(logs), max_bytes=150, min_age=0, now=NOW
    )

    assert not (extract / "FxOld").exists()
    assert not (extract / "FxMid").exists()
    assert (extract / "FxNew").exists()
    assert stats["evict"] == 2
    assert stats["keep"] == 1
    assert stats["freed_bytes"] == 200


def test_dry_run_only_counts(tmp_path: Path) -> None:
    extract = tmp_path / "extract"
    extract.mkdir()
    _write(extract / "FxExe", 20, NOW - 60)

    stats = helper.cleanup(extract, {}, max_bytes=0, min_age=0, now=NOW, dry_run=True)

    assert (extract / "FxExe").exists()
    assert stats["drop_no_record"] == 1


def test_cli_runs_end_to_end(tmp_path: Path) -> None:
    # 走真实时钟（CLI 不接受 --now）：mtime 用「刚刚过去」，别用固定 NOW（会落在未来）
    recent = time.time() - 60
    extract = tmp_path / "extract"
    logs = tmp_path / "logs"
    extract.mkdir()
    _write(extract / "FxKeep", 10, recent)
    _write(extract / "FxExe", 20, recent)
    _write_log(
        logs,
        "files.log",
        [
            {"fuid": "FxKeep", "mime_type": "text/plain"},
            {"fuid": "FxExe", "mime_type": "application/x-dosexec"},
        ],
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(HELPER),
            "--dir",
            str(extract),
            "--logs",
            str(logs),
            "--min-age",
            "0",
            "--max-bytes",
            "0",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert "保留=1" in proc.stdout
    assert "白名单外删除=1" in proc.stdout
    assert (extract / "FxKeep").exists()
    assert not (extract / "FxExe").exists()


def test_entrypoint_wires_cleanup_loop() -> None:
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert 'EXTRACT_DIR="${ZEEK_EXTRACT_DIR:-/extract}"' in text
    assert 'EXTRACT_HELPER="${ZEEK_EXTRACT_HELPER:-/usr/local/bin/extract_cleanup.py}"' in text
    assert "extract_cleanup_once" in text
    assert "start_extract_cleanup_loop" in text
    # 主流程里要真的起循环、并把提取目录建出来
    main_body = text.split("main() {", 1)[1]
    assert "start_extract_cleanup_loop" in main_body
    assert '"$EXTRACT_DIR"' in main_body


def test_image_ships_helper_and_extract_volume() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY extract_cleanup.py /usr/local/bin/extract_cleanup.py" in text
    assert 'VOLUME ["/logs", "/config", "/extract"]' in text


def test_local_zeek_loads_file_extract() -> None:
    loads = [
        line.strip()
        for line in LOCAL_ZEEK.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("@load")
    ]
    assert "@load ./shentong-file-extract" in loads
