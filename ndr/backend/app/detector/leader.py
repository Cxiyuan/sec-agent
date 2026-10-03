"""检测器选主（Redis 租约）：同一时刻只有持锁实例消费队列，故障后租约到期自动接管。"""

from __future__ import annotations

import socket
import threading
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
        # 两个时间戳各有分工：
        # - _last_renew（monotonic）：判断「离上次续约够不够久」，不受系统时间跳变影响
        # - _last_renew_wall（墙上时钟）：判断「租约是不是已经过期」，因为租约 TTL 是 Redis
        #   用自己时钟算的，拿 monotonic 比对没有可比性
        self._last_renew = 0.0
        self._last_renew_wall = 0.0
        self._lock = threading.Lock()
        self._auto_thread: threading.Thread | None = None
        self._stop = threading.Event()
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
        - 起了后台续约线程（``start_auto_renew``）时，这里不再续约，只做「租约是否已过期」
          的兜底：线程卡死而我们仍自认是主 → 双主重复消费/重复投递（QA 应修 7）
        """
        if self.is_leader:
            if self._auto_thread is not None:
                if self._lease_expired():
                    log.warning(
                        "检测器租约疑似已过期（后台续约超过 %ds 未成功），转为待命避免双主",
                        self.ttl,
                    )
                    self.is_leader = False
                    return False
                return True
            now = time.monotonic()
            if now - self._last_renew < self.renew_seconds:
                return True
            with self._lock:
                renewed = self._renew()
                if renewed:
                    self._last_renew = time.monotonic()
            return renewed

        try:
            with self._lock:
                got = self.r.set(self.key, self.me, nx=True, ex=self.ttl)
        except Exception as exc:  # noqa: BLE001
            log.warning("获取检测器租约失败: %s", exc)
            return False
        if got:
            self.is_leader = True
            self._mark_renewed()
            log.info("已成为检测器主实例（%s，租约 %ds）", self.me, self.ttl)
        return self.is_leader

    def start_auto_renew(self) -> None:
        """启动后台续约线程，让租约续期不再依赖主循环节奏（QA 应修 7）。

        主循环一次迭代可能远超 ``renew_seconds``（大批量消费 + Redis/ES 变慢），原来续约
        挂在循环里：单轮超时就丢租约、被别的实例接管，极端情况下两个实例都自认是主。
        """
        if self._auto_thread is not None and self._auto_thread.is_alive():
            return
        self._stop.clear()
        self._auto_thread = threading.Thread(
            target=self._renew_loop, name="detector-lease-renew", daemon=True
        )
        self._auto_thread.start()
        log.info(
            "检测器租约后台续约已启动（间隔 %.1fs，TTL %ds）", self._renew_interval(), self.ttl
        )

    def stop_auto_renew(self) -> None:
        """停掉后台续约线程（退出或测试收尾用）。"""
        thread = self._auto_thread
        self._auto_thread = None
        self._stop.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def _renew_interval(self) -> float:
        """后台续约间隔：不超过 TTL 的 1/3，且至少 1 秒。"""
        return max(1.0, min(float(self.renew_seconds), self.ttl / 3.0))

    def _lease_expired(self) -> bool:
        """租约是否已过 TTL（用墙上时钟，与 Redis 的 TTL 同一量纲）。"""
        return self._last_renew_wall > 0 and time.time() - self._last_renew_wall > self.ttl

    def _mark_renewed(self) -> None:
        """记录「刚刚确认过租约仍在我方」的两个时间戳。"""
        self._last_renew = time.monotonic()
        self._last_renew_wall = time.time()

    def _renew_loop(self) -> None:
        """后台续约循环：只在自己是主时续约，被抢主就安静待命。"""
        while not self._stop.wait(self._renew_interval()):
            if not self.is_leader:
                continue
            with self._lock:
                if self.is_leader:
                    self._renew()

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
        else:
            self._mark_renewed()
        return self.is_leader

    def release(self) -> None:
        """主动让位（正常退出时调用）。"""
        with self._lock:
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
