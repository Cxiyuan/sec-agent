"""前端两处行为守卫（2026-10 用户要求）：

1. **站点强制 HTTPS**：443 是唯一对外入口（自签名证书），80 只做 308 跳转，3000 不再对外；
2. **打开就是登录页**：入口 `/` 是登录闸门（先判登录令牌再决定去总览还是登录页），
   不再「先闪一下主页、2~3 秒后才跳登录」。
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "ndr" / "frontend"


def test_root_is_login_gate() -> None:
    page = (FRONTEND / "app" / "page.tsx").read_text(encoding="utf-8")
    assert "getToken" in page, "入口要先看登录令牌"
    assert "/login" in page and "/admin/status" in page
    assert "正在校验登录" in page, "首屏只渲染这句，不渲染主页内容"
    config = (FRONTEND / "next.config.mjs").read_text(encoding="utf-8")
    assert "redirects" not in config, "不能在配置里把 `/` 无条件重定向到总览（那正是闪烁的根因）"


def test_https_termination_in_container() -> None:
    server = (FRONTEND / "tls-server.mjs").read_text(encoding="utf-8")
    assert "https.createServer" in server and "308" in server, "要 TLS 终结 + HTTP 跳转"
    assert "x-forwarded-proto" in server, "要告诉应用这是 https"
    entry = (FRONTEND / "docker-entrypoint.sh").read_text(encoding="utf-8")
    assert "openssl req -x509" in entry and "/certs" in entry, "自签名证书要生成并持久化"
    dockerfile = (FRONTEND / "Dockerfile").read_text(encoding="utf-8")
    assert "openssl" in dockerfile and "EXPOSE 3000 443 80" in dockerfile
    assert "docker-entrypoint.sh" in dockerfile


def test_compose_publishes_443_and_80_not_3000() -> None:
    for name in ("docker-compose.yml", "docker-compose.deploy.yml"):
        text = (ROOT / "ndr" / name).read_text(encoding="utf-8")
        # 切「frontend」这一节：从它的键头到下一个**顶层服务键**（两个空格 + 字母，后跟非空格）
        start = text.index("  frontend:")
        nxt = re.search(r"\n  [a-z][a-z0-9_-]*:", text[start + 5 :])
        block = text[start : start + 5 + (nxt.start() if nxt else len(text))]
        assert '"443:443"' in block and '"80:80"' in block, f"{name} 前端要暴露 443/80"
        assert "3000:3000" not in block, f"{name} 前端不应再对外暴露明文 3000"
        assert "frontend-certs:/certs" in block, f"{name} 证书卷要挂上"
        assert "frontend-certs:" in text, f"{name} 要声明证书卷"


def test_healthcheck_or_docs_mention_https() -> None:
    """README 的访问地址要写 https（否则运维还在试 http://host:3000）。"""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "https://" in readme, "README 应给出 https 访问方式"
