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


def test_deploy_script_syncs_compose_and_verifies() -> None:
    """部署脚本必须把「编排文件同步」纳入流程，并且每步都校验结果。

    事故背景：改了仓库里的编排（端口 3000→443），服务器上那份没跟着变 → 443 从未对外，
    局域网打开控制台一直「响应时间过长」。所以脚本必须：备份旧文件 → 同步 → **比对校验和** →
    拉取（失败可见、可重试）→ 重建 → **部署后探活**，并给出回滚命令。
    """
    src = (ROOT / "deploy.sh").read_text(encoding="utf-8")
    assert "COMPOSE_FILE" in src and "DEPLOY_HOST" in src
    assert "sha256sum" in src and "校验和" in src, "同步后要比对校验和，证明文件真的落地"
    assert ".bak." in src and "回滚" in src, "要备份并给出回滚办法"
    assert "PULL_RETRIES" in src and "pull" in src, "拉取要能重试（现场 DNS 不稳）"
    assert "up -d --remove-orphans" in src
    assert "curl -sk" in src and "200" in src, "部署后要探活，不只看返回码"
    # 脚本里不许写死任何主机/地址（由环境变量传）
    assert "DEPLOY_HOST:-}" in src, "目标主机必须来自环境变量"


def test_config_audit_lists_source_and_masks_secrets() -> None:
    """配置体检必须**标出来源**并**脱敏**（2026-10：排查时最耗时的是"哪个值生效"）。

    同时钉住一条纪律：智能体地址是**产品常量**（换哪部署 NDR 都连它），
    所以它作为内置默认值是允许的、且只出现一处。
    """
    src = (ROOT / "ndr" / "backend" / "app" / "api" / "routes" / "config_audit.py").read_text(
        encoding="utf-8"
    )
    assert 'DEFAULT_AGENT_HOST = "10.44.77.249"' in src, "智能体地址作为内置默认常量"
    assert "def _mask(" in src and "已配置（长度" in src, "口令/令牌必须脱敏"
    assert "环境变量" in src and "数据库" in src and "编排" in src, "每项都要说明来源"
    assert "_PLACEHOLDER_SECRETS" in src and "change-me-in-production" in src, "占位密钥要报警"
    router = (ROOT / "ndr" / "backend" / "app" / "api" / "router.py").read_text(encoding="utf-8")
    assert "config_audit_router" in router
    page = (ROOT / "ndr" / "frontend" / "app" / "admin" / "config" / "page.tsx").read_text(
        encoding="utf-8"
    )
    assert "/api/config/audit" in page and "来源" in page
    nav = (ROOT / "ndr" / "frontend" / "components" / "nav.tsx").read_text(encoding="utf-8")
    assert "/admin/config" in nav
