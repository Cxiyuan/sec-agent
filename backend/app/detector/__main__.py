"""入口：python -m app.detector（由 docker compose 的 detector 服务拉起）。"""

from __future__ import annotations

from app.detector.runner import run

if __name__ == "__main__":
    run()
