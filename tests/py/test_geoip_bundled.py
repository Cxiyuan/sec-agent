"""离线地理库：构建期现下（不再把 57MB 数据文件放进仓库）。

钉住：
1. 仓库里只有下载脚本 `ndr/backend/geoip/fetch.sh`（不含 .mmdb/.gz 数据文件）；
2. Dockerfile 构建时调用它、并设置 `ST_GEOIP_DB`；
3. 脚本带 CC BY 4.0 归属声明（DB-IP 许可要求）；
4. `app/geoip.py` 的 geoip2 是懒加载，失败返回空串（不影响其它功能）。
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEOIP_DIR = ROOT / "ndr" / "backend" / "geoip"


def test_repo_does_not_carry_the_database() -> None:
    """仓库里不该再有 mmdb / mmdb.gz（用户要求：随 CI 现下）。"""
    assert not list(GEOIP_DIR.glob("*.mmdb")), "仓库里不应有 .mmdb"
    assert not list(GEOIP_DIR.glob("*.mmdb.gz")), "仓库里不应有 .mmdb.gz（改成构建期下载）"
    assert (GEOIP_DIR / "fetch.sh").exists(), "下载脚本必须存在"


def test_fetch_script_downloads_and_decompresses() -> None:
    src = (GEOIP_DIR / "fetch.sh").read_text(encoding="utf-8")
    assert "download.db-ip.com/free/dbip-city-lite" in src, "从 DB-IP 官方地址下载"
    assert any(x in src for x in ("gunzip", "gzip.decompress", "GzipFile")), "要解压成 .mmdb"
    assert "CC BY 4.0" in src and "db-ip.com" in src, "许可要求保留归属"
    assert "不影响其它功能" in src, "下载失败不能阻断构建"
    # DB-IP 会 403 掉 urllib 的默认 UA（实测），必须显式带 UA
    assert "User-Agent" in src, "下载要带 UA（否则 DB-IP 返回 403）"
    assert "python3" in src and "python" in src, "解释器要自动探测（镜像里可能只有 python3）"


def test_dockerfile_fetches_at_build_time() -> None:
    dockerfile = (ROOT / "ndr" / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY backend/geoip ./geoip" in dockerfile, "要复制脚本进镜像（构建上下文是 ndr/）"
    assert "fetch.sh /app/geoip" in dockerfile, "构建时执行下载脚本"
    assert "ST_GEOIP_DB=/app/geoip/ip.mmdb" in dockerfile, "默认路径要设好"


def test_geoip_reader_is_lazy_and_never_raises() -> None:
    src = (ROOT / "ndr" / "backend" / "app" / "geoip.py").read_text(encoding="utf-8")
    module_level = src.split("def _open(")[0]
    assert "from geoip2.database import Reader" not in module_level, "geoip2 必须懒加载"
    assert "from geoip2.database import Reader" in src
    assert 'return ""' in src
    assert "lru_cache" in src
