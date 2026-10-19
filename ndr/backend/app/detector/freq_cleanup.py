"""清理频率规则的**孤儿 `dst` 键**（一次性运维工具，默认 dry-run）。

## 为什么需要它

`FreqWindow.observe()` 原来的写法是「pipeline 里 `expire(dst_key)`，execute **之后**才
`zadd(dst_key)`」——首次插入时键还不存在，`expire` 对空键无效，执行完 `zadd` 建出键却
再没有任何地方补 TTL。于是只有「被命中 ≥2 次」的分组能蹭到下一次 pipeline 的 expire。

2026-10 生产实测：`shentong:freq:*:dst` 共 62,695 个键，抽样 60 个里 **57 个 TTL=-1**
（永久驻留）。Redis 用的是 `noeviction`，键只增不减 → 迟早吃满内存，届时**全链路静默卡死**
（本项目踩过同源事故）。代码侧的顺序问题已在 `frequency.py` 修好，历史遗留的孤儿键由本工具清。

## 判定"孤儿"的两个条件（都要满足）

1. `TTL == -1`（无过期）—— 修复后新写入的键都有 TTL，不会被误删；
2. 最新成员的 score 早于 `older_than_seconds`（默认 2 小时）—— 还在活跃累积的键不动。

只用 `SCAN` + `UNLINK`（非阻塞删除），不用 `KEYS`（百万键会把 Redis 卡住）。

## 用法

```bash
# 只看会删多少（默认，不做任何删除）
python -m app.detector.freq_cleanup
# 真删
python -m app.detector.freq_cleanup --execute
# 只清更老的（默认 7200 秒）
python -m app.detector.freq_cleanup --execute --older-than 86400
```
"""

from __future__ import annotations

import argparse
import time
from collections.abc import Iterator
from typing import Any

_PREFIX = "shentong:freq"
#: 扫描模式：`shentong:freq:<规则名>:<分组>:dst`
_SCAN_MATCH = f"{_PREFIX}:*:dst"


def iter_dst_keys(client: Any, *, batch: int = 500) -> Iterator[str]:
    """只读遍历所有 `dst` 键（SCAN 游标，不阻塞 Redis）。"""
    for key in client.scan_iter(match=_SCAN_MATCH, count=batch):
        yield key.decode() if isinstance(key, bytes) else str(key)


def is_orphan(client: Any, key: str, now: float, older_than_seconds: float) -> bool:
    """无 TTL **且**最新成员已过时 → 孤儿。任一条不满足都不动它。"""
    ttl = int(client.ttl(key) or -1)
    if ttl != -1:
        return False
    newest = client.zrange(key, -1, -1, withscores=True)
    if not newest:
        # 空 ZSET：没有成员就没有价值，也没有 TTL → 直接算孤儿
        return True
    try:
        latest_ts = float(newest[0][1])
    except (TypeError, IndexError, ValueError):
        return False
    return (now - latest_ts) >= older_than_seconds


def cleanup_orphan_dst_keys(
    client: Any,
    *,
    execute: bool = False,
    older_than_seconds: float = 7200.0,
    limit: int | None = None,
    now: float | None = None,
    batch: int = 500,
) -> dict[str, int]:
    """扫一遍 `dst` 键，统计（必要时 `UNLINK`）孤儿键。

    返回 `{"scanned": n, "with_ttl": n, "active": n, "orphans": n, "deleted": n}`；
    `execute=False` 时 `deleted` 恒为 0（dry-run）。
    """
    ts = time.time() if now is None else now
    scanned = with_ttl = active = orphans = deleted = 0
    for key in iter_dst_keys(client, batch=batch):
        scanned += 1
        ttl = int(client.ttl(key) or -1)
        if ttl != -1:
            with_ttl += 1
            continue
        if not is_orphan(client, key, ts, older_than_seconds):
            active += 1
            continue
        orphans += 1
        if execute:
            # UNLINK 是异步释放（不阻塞主线程）；老版本 redis-py/服务端退化成 DEL 也能跑
            unlink = getattr(client, "unlink", None) or client.delete
            unlink(key)
            deleted += 1
        if limit is not None and orphans >= limit:
            break
    return {
        "scanned": scanned,
        "with_ttl": with_ttl,
        "active": active,
        "orphans": orphans,
        "deleted": deleted,
    }


def main(argv: list[str] | None = None) -> int:
    import redis  # 延迟导入：本模块只在手工运维时用，别让它进导入热路径

    from app.config import settings

    parser = argparse.ArgumentParser(description="清理频率规则的孤儿 dst 键（默认 dry-run）")
    parser.add_argument("--execute", action="store_true", help="真的删除（不加只统计）")
    parser.add_argument(
        "--older-than", type=float, default=7200.0, help="最新成员早于这么多秒才算孤儿（默认 7200）"
    )
    parser.add_argument("--limit", type=int, default=None, help="最多处理多少个孤儿键")
    args = parser.parse_args(argv)

    client = redis.Redis.from_url(settings.redis_url)
    stats = cleanup_orphan_dst_keys(
        client,
        execute=bool(args.execute),
        older_than_seconds=float(args.older_than),
        limit=args.limit,
    )
    mode = "已删除" if args.execute else "将删除（dry-run）"
    print(
        f"扫描 dst 键 {stats['scanned']} 个：有 TTL {stats['with_ttl']} 个、"
        f"活跃无 TTL {stats['active']} 个、孤儿 {stats['orphans']} 个"
    )
    print(f"{mode}: {stats['deleted'] if args.execute else stats['orphans']} 个")
    if not args.execute and stats["orphans"]:
        print("确认无误后加 --execute 执行")
    return 0


if __name__ == "__main__":  # pragma: no cover - 手工运维入口
    raise SystemExit(main())
