"""结构化日志：供 worker / 节点统一使用。"""
import logging

_configured = False


def get_logger(name: str) -> logging.Logger:
    global _configured
    if not _configured:
        # 延迟导入避免循环依赖（config 不依赖本模块）
        try:
            from app.config import settings

            level = logging.DEBUG if settings.debug else logging.INFO
        except Exception:  # noqa: BLE001
            level = logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        )
        _configured = True
    return logging.getLogger(name)
