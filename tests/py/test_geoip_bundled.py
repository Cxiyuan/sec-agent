"""离线地理库随镜像发布（可视化流量的「访问地域 TOP5」）。

钉住三件事，防止哪次重构把这项能力悄悄丢掉：
1. 库文件在仓库里（`ndr/backend/geoip/*.mmdb.gz`）；
2. Dockerfile 解压到镜像里并设置 `ST_GEOIP_DB`；
3. 文件真的是 MaxMind 格式（尾部有 metadata 标记）—— 下错文件（比如下成网页）能立刻发现。
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEOIP_DIR = ROOT / "ndr" / "backend" / "geoip"

#: MaxMind mmdb 的元数据标记（固定 14 字节）
MMDB_MARKER = b"\xab\xcd\xefMaxMind.com"


def test_geoip_db_is_in_repo() -> None:
    files = sorted(GEOIP_DIR.glob("*.mmdb.gz"))
    assert files, "仓库里没有地理库文件（ndr/backend/geoip/*.mmdb.gz）"
    assert files[0].stat().st_size > 1024 * 1024, "库文件太小，八成下错了"


def test_geoip_file_is_real_mmdb() -> None:
    """真的是 MaxMind 格式（尾部有 metadata 标记）—— 下成网页/下错文件能立刻发现。

    注意：不要对 gzip 流做 seek 到结尾再读（zlib 会报错），
    改成**流式读、只留尾部 64KB**。
    """
    import gzip

    files = sorted(GEOIP_DIR.glob("*.mmdb.gz"))
    assert files, "仓库里没有地理库文件"
    tail = b""
    head = b""
    with gzip.open(files[0], "rb") as fh:
        head = fh.read(4)
        chunk = fh.read(1024 * 1024)
        while chunk:
            tail = (tail + chunk)[-65536:]
            chunk = fh.read(1024 * 1024)
    assert head != b"<htm", "下成了网页（HTML）而不是地理库"
    assert MMDB_MARKER in tail, "尾部没有 MaxMind metadata 标记，不是标准 mmdb"


def test_image_ships_geoip_and_env() -> None:
    dockerfile = (ROOT / "ndr" / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY geoip ./geoip" in dockerfile, "Dockerfile 要把地理库复制进镜像"
    assert "gunzip" in dockerfile and "/app/geoip/ip.mmdb" in dockerfile, "构建时解压到镜像内"
    assert "ST_GEOIP_DB=/app/geoip/ip.mmdb" in dockerfile, "要设置默认路径，开箱可用"


def test_geoip_reader_is_lazy() -> None:
    """没配库 / 库坏了不能让流量页挂掉（geoip2 懒加载，失败只记日志）。"""
    src = (ROOT / "ndr" / "backend" / "app" / "geoip.py").read_text(encoding="utf-8")
    # 导入放函数体内（模块级导入会让"没装/没库"直接炸在启动阶段）
    module_level = src.split("def _open(")[0]
    assert "from geoip2.database import Reader" not in module_level, "geoip2 必须懒加载"
    assert "from geoip2.database import Reader" in src, "真要用时得能拿到 Reader"
    # 打开/查询失败都吞掉，返回空串让调用方显示「未知」
    assert "_reader_error" in src
    assert "except Exception" in src
