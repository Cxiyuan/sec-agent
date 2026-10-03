"""批 4：提取件下载接口（``ndr/backend/app/api/routes/files.py``）的路径安全与口径一致性。

这个接口只要「客户端给 fuid」，真实文件名从 ES 里查（``extracted``），因此这里重点验证
**路径不能逃出提取目录**（目录穿越 / 符号链接），以及「Zeek 落盘目录 = 后端读取目录」
这一条跨容器契约。接口本身只在 NDR 侧存在，所以在 ``--stack=agent`` 下跳过。
"""

from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def files_route(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("文件下载接口只在 NDR 侧")
    return importlib.import_module("app.api.routes.files")


def test_zeek_prefix_matches_backend_extract_dir(files_route: ModuleType) -> None:
    from app.config import settings

    zeek_script = (ROOT / "ndr" / "zeek" / "site" / "shentong-file-extract.zeek").read_text(
        encoding="utf-8"
    )
    entrypoint = (ROOT / "ndr" / "zeek" / "entrypoint.sh").read_text(encoding="utf-8")

    assert f'FileExtract::prefix = "{settings.extract_dir}/"' in zeek_script
    assert f'EXTRACT_DIR="${{ZEEK_EXTRACT_DIR:-{settings.extract_dir}}}"' in entrypoint


def test_resolve_accepts_plain_name(files_route: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "Fx8HnP1AbCdEfGhIjK").write_bytes(b"x")
    path = files_route.resolve_extract_path(tmp_path, "Fx8HnP1AbCdEfGhIjK")
    assert path == (tmp_path / "Fx8HnP1AbCdEfGhIjK").resolve()


@pytest.mark.parametrize(
    "bad",
    ["", ".", "..", "a/b", "/etc/passwd", "../outside", "sub/../x", "..\\win"],
)
def test_resolve_rejects_escape(files_route: ModuleType, tmp_path: Path, bad: str) -> None:
    # 含分隔符 / 空名 / 上跳一律不接受（Windows 风格分隔符同样拒绝）
    assert files_route.resolve_extract_path(tmp_path, bad) is None


def test_resolve_rejects_symlink_escape(files_route: ModuleType, tmp_path: Path) -> None:
    root = tmp_path / "extract"
    root.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"top secret")
    (root / "FxFake0000000000000").symlink_to(secret)

    assert files_route.resolve_extract_path(root, "FxFake0000000000000") is None


def test_download_name_is_header_safe(files_route: ModuleType) -> None:
    for raw in ["../../etc/passwd", "a\r\nX-Evil: 1", "\x00\x01", "", "   ", "x" * 500]:
        name = files_route._download_name(raw, "FxFallback00000000")
        assert name
        assert len(name) <= 128
        assert not set(name) & set('/\\\r\n"'), name
        assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name), name


@pytest.mark.parametrize(
    ("fuid", "ok"),
    [
        ("Fx8HnP1AbCdEfGhIjK", True),
        ("C39yDQZbVULnLz9u1", True),
        ("short", False),
        ("has space", False),
        ("../../etc/passwd", False),
        ("x" * 65, False),
    ],
)
def test_fuid_pattern(files_route: ModuleType, fuid: str, ok: bool) -> None:
    assert bool(files_route._FUID_RE.match(fuid)) is ok


@pytest.mark.parametrize(
    ("extracted", "ok"),
    [
        ("Fx8HnP1AbCdEfGhIjK", True),
        (" gotcha", True),
        ("", False),
        (None, False),
        ("   ", False),
    ],
)
def test_has_extracted_selects_by_non_empty_string(
    files_route: ModuleType, extracted: object, ok: bool
) -> None:
    """「有提取件」按空串判，不用 ES 的 exists。

    归一化文档里所有字符串字段默认是空串（不是缺字段），实测 ``exists extracted`` 几乎恒真
    （``exists ja4`` 命中全量 57288 条，真正有值的只有 263 条），所以下载接口改成取回后判空。
    这条测试钉住语义，防止有人改回 ``{"exists": {"field": "extracted"}}``。
    """
    assert files_route._has_extracted({"extracted": extracted}) is ok
