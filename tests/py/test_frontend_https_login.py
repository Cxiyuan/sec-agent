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
    # 这条守的是「**根路径**不许被静态重定向」：`/` 一旦在配置里 307 到总览，打开站点
    # 就会先渲染主页再跳登录页，出现闪烁——那正是当初改成客户端登录闸门的根因。
    # 允许的则是「具体路径的别名重定向」（如 `/admin/status` → `/console` 这类历史地址
    # 兼容的 307），两者语义正交。所以这里只禁 `source: "/"`，不要一刀切禁掉 redirects 整个键。
    assert 'source: "/"' not in config, "不能在配置里把 `/` 无条件重定向到总览（那正是闪烁的根因）"


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
    """对接文档的访问地址要写 https（否则运维还在试 http://host:3000）。

    根 README 已按产品要求移除；部署/对接入口以 `docs/api/README.md` 为准。
    """
    docs = (ROOT / "docs" / "api" / "README.md").read_text(encoding="utf-8")
    assert "https://" in docs, "接口文档应给出 https 访问方式"


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
    # 部署前体检（只读）：探测宿主地址 + 证书是否覆盖 + 占位密钥 + 允许来源 + 推送是否配置
    assert "部署前体检" in src
    assert "hostname -I" in src or "ip route get" in src, "要探测宿主地址（证书覆盖用）"
    assert "IP Address:" in src and "证书未覆盖" in src
    assert "change-me-in-production" in src and "登录密钥仍未" not in src
    assert ":3000" in src, "要提示允许来源还带旧写法"
    assert "STRICT" in src


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
    page = (ROOT / "ndr" / "frontend" / "app" / "config" / "health" / "page.tsx").read_text(
        encoding="utf-8"
    )
    assert "/api/config/audit" in page and "来源" in page
    # 2026-10 改版：一级菜单搬到页头，导航结构集中在 lib/nav-config.ts（侧边栏按页面挂）
    nav = (ROOT / "ndr" / "frontend" / "lib" / "nav-config.ts").read_text(encoding="utf-8")
    assert "/config/health" in nav, "「配置管理」分区要能进到配置体检页"
    assert (ROOT / "ndr" / "frontend" / "app" / "config" / "health" / "page.tsx").exists(), (
        "配置体检页在 /config/health（实现已从旧 /admin/config 搬到新地址）"
    )


def test_deploy_script_supports_local_and_check_mode() -> None:
    """部署脚本要能**在部署机上直接跑**（本地模式）与**只体检**（check 模式）。

    为什么：现场用"口令前缀"走 SSH 一直被认证拦（实测多次 Permission denied），
    而在部署机上直接跑最稳（不需要 SSH/口令）；上线前也该能"先只看不动"。
    """
    src = (ROOT / "deploy.sh").read_text(encoding="utf-8")
    assert "DEPLOY_HOST=local" in src or "local|local:*" in src, "要支持本地模式"
    assert 'MODE="${MODE:-deploy}"' in src and "MODE=check" in src, "要支持只体检模式"
    assert "跳过备份（本模式不写任何文件）" in src, "check 模式不能写任何文件"
    # 本地模式下编排按部署目录解析（不是仓库相对路径）——踩过：check 一直在找 ndr/docker-compose…
    assert 'COMPOSE_FILE="$DEPLOY_DIR/docker-compose.deploy.yml"' in src


def test_deploy_script_probe_waits_for_app() -> None:
    """部署后的前端探活必须**带重试**：容器刚 Started 时应用还没起来（实测 Up<1 秒就探会误判失败）。

    失败时还要自动打印前端日志尾部，并把排查方向写出来（证书/入口/端口），
    不能只丢一句"探活失败"。
    """
    src = (ROOT / "deploy.sh").read_text(encoding="utf-8")
    assert "PROBE_RETRIES" in src, "探活要能重试"
    assert 'while [ "$i" -lt' in src and "sleep 5" in src
    assert "docker logs --tail 25 shentong-ndr-frontend-1" in src, "失败要打印前端日志"
    assert "证书是否在" in src, "失败要给出排查方向"
