"""检测器选主（Redis 租约）：同一时刻只有持锁实例消费队列，故障后租约到期自动接管。"""

from __future__ import annotations

import socket
import time
import uuid
from typing import Any

from app.config import settings
from app.workers.log import get_logger

log = get_logger(__name__)

# 原子续约：GET 与 EXPIRE 之间不能被打断，否则可能把已易主的租约续成自己的
_RENEW_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 0
"""


def instance_id() -> str:
    """本实例标识（多实例、同机多容器都能区分）。"""
    return f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"


class Leader:
    """租约式选主：Redis SET NX EX 抢主 + Lua 原子续约。

    前提：``client`` 必须是 ``decode_responses=True`` 的 redis 客户端。
    否则 GET 返回 bytes 与自己写入的 str 比较永远不等 → 本实例会一直自以为丢锁、
    永久待命且只刷 warning（静默失效）。
    """

    def __init__(
        self,
        client: Any,
        key: str | None = None,
        ttl: int | None = None,
        renew_seconds: int | None = None,
        me: str | None = None,
    ) -> None:
        self.r = client
        self.key = key or settings.detector_leader_key
        self.ttl = max(5, _to_int(ttl or settings.detector_leader_ttl_seconds, 30))
        self.renew_seconds = max(
            1, _to_int(renew_seconds or settings.detector_leader_renew_seconds, 10)
        )
        self.me = me or instance_id()
        self.is_leader = False
        self._last_renew = 0.0
        if self.ttl < self.renew_seconds * 2:
            log.warning(
                "选主配置可疑：租约 TTL %ds 不足续约间隔 %ds 的 2 倍，可能在两次续约之间被抢主",
                self.ttl,
                self.renew_seconds,
            )

    def try_acquire(self) -> bool:
        """尝试获取/续约，返回「本轮是否可以干活」。

        - 返回值 = 本轮是否可以消费（续约失败/网络异常返回 False，宁可少干也不重复消费）
        - ``is_leader`` = 我方是否自认为持有租约（供状态展示，被他人接管时置回 False）
        - 未到续约间隔时直接返回当前状态，不打 Redis（否则主循环每轮都多发一次 GET+EXPIRE）
        """
        if self.is_leader:
            now = time.monotonic()
            if now - self._last_renew < self.renew_seconds:
                return True
            renewed = self._renew()
            if renewed:
                self._last_renew = now
            return renewed

        try:
            got = self.r.set(self.key, self.me, nx=True, ex=self.ttl)
        except Exception as exc:  # noqa: BLE001
            log.warning("获取检测器租约失败: %s", exc)
            return False
        if got:
            self.is_leader = True
            self._last_renew = time.monotonic()
            log.info("已成为检测器主实例（%s，租约 %ds）", self.me, self.ttl)
        return self.is_leader

    def _renew(self) -> bool:
        """原子续约：仅当 key 仍是我方标识时才 EXPIRE（Lua 保证）。"""
        try:
            ok = self.r.eval(_RENEW_LUA, 1, self.key, self.me, self.ttl)
        except Exception as exc:  # noqa: BLE001
            # 网络/服务异常：本轮不干活（返回 False），但不立即认定失去租约（TTL 内仍可能是主）
            log.warning("续约检测器租约失败，本轮暂停消费: %s", exc)
            return False
        if not ok:
            log.warning("检测器租约已丢失（可能被其他实例接管），转为待命")
            self.is_leader = False
        return self.is_leader

    def release(self) -> None:
        """主动让位（正常退出时调用）。"""
        if not self.is_leader:
            return
        try:
            if self.r.get(self.key) == self.me:
                self.r.delete(self.key)
        except Exception as exc:  # noqa: BLE001
            log.debug("释放检测器租约失败: %s", exc)
        self.is_leader = False


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default
