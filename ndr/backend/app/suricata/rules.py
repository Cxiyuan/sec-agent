"""签名引擎（Suricata）规则集：manifest 拉取、哈希比对、暂存、校验、生效请求。

职责边界（与项目既有架构一致：后端写共享文件、容器执行）：

- 后端只写共享卷（``staging/`` + ``source.json`` + 三个请求标记），**不碰 docker socket**；
- 真正加载规则的是容器：它跑 ``suricata -T`` 校验 ``staging/``，把结果写 ``validation.json``；
  收到生效请求后再把 ``staging/`` 切到 ``active/`` 并热重载，把状态写 ``runtime.json``。
- 规则变更属**检测口径变更** → 定时任务只做「拉取 + 下载 + 校验」，**不自动生效**：
  校验通过后由界面弹确认框、人工点「立即更新」才切换。

目录约定（共享卷 /rules，见 ndr/suricata/README.md）：

    active/     生效中的 *.rules（任何时候至少一个文件：空占位或真实规则）
    staging/    已下载待确认的新版本（*.rules + manifest.json）
    previous/   上一版（回滚用）
    rejected/   最近 5 次校验失败（*.rules + error.txt）
    source.json        后端维护：地址/开关/最近检查/待确认版本/历史
    runtime.json       容器维护：已加载文件、规则条数、引擎版本、存活
    validation.json    容器维护：最近一次 staging 校验结果
    validate.request / activate.request / reset.request   后端写请求 → 容器处理后删除
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import SystemConfig

log = logging.getLogger(__name__)

#: 规则文件名：只允许字母数字与 . _ -，必须以 .rules 结尾（防路径穿越）
_NAME_RE = __import__("re").compile(r"^[A-Za-z0-9._-]{1,64}\.rules$")
_SHA256_RE = __import__("re").compile(r"^[0-9a-fA-F]{64}$")
_HISTORY_MAX = 10
_WAIT_INTERVAL = 2.0

#: 持久化配置键（PG SystemConfig，与 zeek 的键同一套读写口径）
KEY_URL = "suricata.rules_url"
KEY_TOKEN = "suricata.rules_token"
KEY_ENABLED = "suricata.rules_enabled"


class RulesError(RuntimeError):
    """规则集操作失败：消息直接给界面看。``status`` 供接口层选状态码。"""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


# ---------- 路径与文件 ----------


def rules_dir() -> Path:
    return Path(settings.suricata_rules_dir)


def active_dir() -> Path:
    return rules_dir() / "active"


def staging_dir() -> Path:
    return rules_dir() / "staging"


def source_path() -> Path:
    return rules_dir() / "source.json"


def runtime_path() -> Path:
    return rules_dir() / "runtime.json"


def validation_path() -> Path:
    return rules_dir() / "validation.json"


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.loads(fh.read())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _write_json(path: Path, data: dict[str, Any]) -> None:
    """原子写：先写 .tmp 再 rename，避免读者看到半截 JSON。"""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except OSError as exc:
        raise RulesError(f"写入 {path} 失败：{exc.strerror or exc}", 500) from exc


def _write_request(name: str, version: str) -> None:
    path = rules_dir() / name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"{version}\n")
    except OSError as exc:
        raise RulesError(f"写请求标记失败（规则卷没挂上？）：{exc.strerror or exc}", 500) from exc


def load_source() -> dict[str, Any]:
    return _read_json(source_path()) or {}


def save_source(data: dict[str, Any]) -> None:
    _write_json(source_path(), data)


def read_runtime() -> dict[str, Any]:
    return _read_json(runtime_path()) or {}


def read_validation() -> dict[str, Any]:
    return _read_json(validation_path()) or {}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 256), b""):
                digest.update(chunk)
    except OSError as exc:
        raise RulesError(f"读取规则文件 {path.name} 失败：{exc.strerror or exc}", 500) from exc
    return digest.hexdigest()


def active_files() -> list[dict[str, Any]]:
    """生效目录里的规则文件（算本地 sha256，用于和 manifest 比对）。"""
    out: list[dict[str, Any]] = []
    if not active_dir().is_dir():
        return out
    for path in sorted(active_dir().glob("*.rules")):
        if not path.is_file():
            continue
        out.append({"name": path.name, "sha256": sha256_file(path), "size": path.stat().st_size})
    return out


def _as_int(value: Any) -> int | None:
    """容器写的状态文件可能被手改/写坏：非数字一律当「没有」，不让接口 500。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.lstrip("-").isdigit():
        return int(value)
    return None


def active_version() -> str:
    """生效版本：取自 active/manifest.json（空占位状态下没有这个文件 ⇒ 空串）。"""
    data = _read_json(active_dir() / "manifest.json") or {}
    return str(data.get("version") or "")


def active_rule_count() -> int:
    """生效规则条数：优先用容器上报的（它按 Suricata 的口径数），退回自己数文件行。"""
    runtime = read_runtime()
    reported = _as_int(runtime.get("rule_count"))
    if reported is not None:
        return reported
    total = 0
    for item in active_files():
        try:
            with open(active_dir() / item["name"], encoding="utf-8", errors="ignore") as fh:
                total += sum(
                    1
                    for line in fh
                    if line.lstrip().startswith(("alert ", "drop ", "pass ", "reject "))
                )
        except OSError:
            continue
    return total


# ---------- URL 与 manifest ----------


def normalize_url(raw: str) -> str:
    """规范化更新地址：只允许 http/https；不以 .json 结尾则自动补 manifest.json。"""
    text = (raw or "").strip()
    if not text:
        raise RulesError("更新地址为空")
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https"):
        raise RulesError("只支持 http/https 地址")
    if not parsed.netloc:
        raise RulesError("更新地址缺少主机名")
    path = parsed.path or "/"
    if not path.lower().endswith(".json"):
        path = path.rstrip("/") + "/manifest.json"
    return urlunparse(parsed._replace(path=path, params="", query=parsed.query, fragment=""))


def validate_manifest(data: Any) -> tuple[str, list[dict[str, Any]]]:
    """校验 manifest 结构，返回 (版本, 文件列表)。任何不合法都直接拒绝。"""
    if not isinstance(data, dict):
        raise RulesError("manifest 不是 JSON 对象")
    version = str(data.get("version") or "").strip()
    if not version:
        raise RulesError("manifest 缺少 version")
    raw_files = data.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise RulesError("manifest 的 files 必须是非空数组")
    if len(raw_files) > settings.suricata_max_files:
        raise RulesError(f"规则文件数量超过上限（{settings.suricata_max_files}）")
    files: list[dict[str, Any]] = []
    seen: set[str] = set()
    total = 0
    for item in raw_files:
        if not isinstance(item, dict):
            raise RulesError("manifest 的 files 元素必须是对象")
        name = str(item.get("name") or "")
        if not _NAME_RE.match(name):
            raise RulesError(
                f"规则文件名不合法：{name!r}（只允许字母数字与 . _ -，且以 .rules 结尾）"
            )
        if name in seen:
            raise RulesError(f"manifest 里文件名重复：{name}")
        seen.add(name)
        sha = str(item.get("sha256") or "").lower()
        if not _SHA256_RE.match(sha):
            raise RulesError(f"{name} 缺少合法的 sha256")
        size: int | None = None
        raw_size = item.get("size")
        if isinstance(raw_size, int):
            size = raw_size
        elif isinstance(raw_size, str) and raw_size.isdigit():
            size = int(raw_size)
        if size is not None and size > settings.suricata_max_file_bytes:
            raise RulesError(f"{name} 超过单文件上限（{settings.suricata_max_file_bytes} 字节）")
        total += size or 0
        files.append({"name": name, "sha256": sha, "size": size})
    if total > settings.suricata_max_total_bytes:
        raise RulesError(f"规则文件合计超过上限（{settings.suricata_max_total_bytes} 字节）")
    return version, files


def file_url(manifest_url: str, item: dict[str, Any]) -> str:
    """规则文件的下载地址：默认与 manifest 同级；manifest 可用 url 覆盖（必须同源）。"""
    base = urlparse(manifest_url)
    override = str(item.get("url") or "").strip()
    if override:
        target = urlparse(override)
        if (target.scheme, target.netloc) != (base.scheme, base.netloc):
            raise RulesError("规则文件的 url 必须与 manifest 同源")
        return override
    parent = str(Path(base.path).parent)
    if parent == ".":
        parent = ""
    return urlunparse(base._replace(path=f"{parent}/{item['name']}"))


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def fetch_manifest(url: str, token: str = "") -> tuple[str, list[dict[str, Any]]]:
    try:
        with httpx.Client(timeout=settings.suricata_fetch_timeout_seconds) as client:
            resp = client.get(url, headers=_headers(token), follow_redirects=True)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        raise RulesError(f"拉取 manifest 失败：HTTP {exc.response.status_code}", 502) from exc
    except httpx.HTTPError as exc:
        raise RulesError(f"拉取 manifest 失败：{exc.__class__.__name__}", 502) from exc
    except ValueError as exc:
        raise RulesError("manifest 不是合法 JSON", 502) from exc
    return validate_manifest(data)


def download_file(url: str, item: dict[str, Any], token: str = "") -> bytes:
    """下载单个规则文件并校验 sha256/大小：不一致一律拒绝（不写盘）。"""
    try:
        with httpx.Client(timeout=settings.suricata_fetch_timeout_seconds) as client:
            resp = client.get(url, headers=_headers(token), follow_redirects=True)
            resp.raise_for_status()
            body = resp.content
    except httpx.HTTPStatusError as exc:
        raise RulesError(f"下载 {item['name']} 失败：HTTP {exc.response.status_code}", 502) from exc
    except httpx.HTTPError as exc:
        raise RulesError(f"下载 {item['name']} 失败：{exc.__class__.__name__}", 502) from exc
    if len(body) > settings.suricata_max_file_bytes:
        raise RulesError(f"{item['name']} 超过单文件上限")
    actual = hashlib.sha256(body).hexdigest()
    if actual != item["sha256"]:
        raise RulesError(f"{item['name']} 的 sha256 与 manifest 不一致（远端文件可能被改动）")
    if item.get("size") is not None and len(body) != item["size"]:
        raise RulesError(f"{item['name']} 大小与 manifest 不一致（{len(body)} != {item['size']}）")
    return body


def diff_files(remote: list[dict[str, Any]], local: list[dict[str, Any]]) -> dict[str, list[str]]:
    """比较远端 manifest 与本地生效规则：给出新增/更新/删除的文件名。"""
    remote_map = {item["name"]: item["sha256"] for item in remote}
    local_map = {item["name"]: item["sha256"] for item in local}
    added = sorted(name for name in remote_map if name not in local_map)
    updated = sorted(
        name for name, sha in remote_map.items() if name in local_map and local_map[name] != sha
    )
    removed = sorted(name for name in local_map if name not in remote_map)
    return {"added": added, "updated": updated, "removed": removed}


# ---------- 暂存与等待 ----------


def _clear_dir(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for child in directory.iterdir():
        if child.is_file():
            child.unlink()


def stage(version: str, files: list[dict[str, Any]], manifest: dict[str, Any]) -> None:
    """把「完整的一套规则」（含未变化的文件，从 active 复制）写入 staging/。

    staging 必须是**完整集合**：容器校验和切换都以整个目录为单位，缺文件会漏规则。
    """
    local = {item["name"]: item for item in active_files()}
    target = staging_dir()
    _clear_dir(target)
    for item in files:
        name = item["name"]
        src = active_dir() / name
        if name in local and local[name]["sha256"] == item["sha256"] and src.is_file():
            (target / name).write_bytes(src.read_bytes())
            continue
        body = download_file(
            file_url(str(manifest.get("_url") or ""), item), item, str(manifest.get("_token") or "")
        )
        (target / name).write_bytes(body)
    _write_json(
        target / "manifest.json", {k: v for k, v in manifest.items() if not k.startswith("_")}
    )


def _wait(predicate: Any, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(_WAIT_INTERVAL)
    return bool(predicate())


def request_validation(version: str) -> None:
    """请求容器对 staging 跑一次 `suricata -T`（结果写 validation.json）。"""
    _write_json(validation_path(), {})  # 先清空旧结果，避免读到上一版
    _write_request("validate.request", version)


def wait_validation(version: str, timeout: float | None = None) -> dict[str, Any]:
    limit = float(settings.suricata_validate_timeout_seconds if timeout is None else timeout)

    def done() -> bool:
        data = read_validation()
        return bool(data) and str(data.get("version") or "") == version

    if not _wait(done, limit):
        raise RulesError("等待签名引擎校验超时（容器未运行或规则过大）", 504)
    return read_validation()


def request_activate(version: str) -> None:
    _write_request("activate.request", version)


def request_reset() -> None:
    _write_request("reset.request", "reset")


# ---------- 持久化配置（PG） ----------


def _get_value(db: Session, key: str) -> str:
    row = db.get(SystemConfig, key)
    if row is None or not isinstance(row.value, dict):
        return ""
    return str(row.value.get("value") or "")


def _set_value(db: Session, key: str, value: str) -> None:
    row = db.get(SystemConfig, key)
    if row is None:
        row = SystemConfig(key=key, value={})
        db.add(row)
    row.value = {"value": value}


def source_config(db: Session) -> dict[str, Any]:
    """界面配置（URL/令牌/开关）。令牌只回「是否已配置」，不回显明文。"""
    token = _get_value(db, KEY_TOKEN)
    enabled_raw = _get_value(db, KEY_ENABLED)
    return {
        "url": _get_value(db, KEY_URL),
        "token_set": bool(token),
        "enabled": enabled_raw != "0",
    }


def save_source_config(
    db: Session, url: str | None, token: str | None, enabled: bool | None
) -> dict[str, Any]:
    if url is not None:
        text = url.strip()
        _set_value(db, KEY_URL, normalize_url(text) if text else "")
    if token is not None:  # 空串 = 清除
        _set_value(db, KEY_TOKEN, token.strip())
    if enabled is not None:
        _set_value(db, KEY_ENABLED, "1" if enabled else "0")
    db.commit()
    return source_config(db)


def _token(db: Session) -> str:
    return _get_value(db, KEY_TOKEN)


# ---------- 主流程 ----------


def _history_push(source: dict[str, Any], entry: dict[str, Any]) -> None:
    history = source.get("history")
    if not isinstance(history, list):
        history = []
    history.insert(0, entry)
    source["history"] = history[:_HISTORY_MAX]


def check_now(db: Session, *, scheduled: bool = False) -> dict[str, Any]:
    """检查更新：拉 manifest → 比哈希 → 有差异就下载并请求容器校验（**不生效**）。

    scheduled=True 时「没配地址」是正常空转（不报错、不写历史）。
    """
    cfg = source_config(db)
    url = cfg["url"]
    if not url:
        if scheduled:
            return {"configured": False, "has_update": False}
        raise RulesError("还没配置更新地址")
    source = load_source()
    entry: dict[str, Any] = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        version, remote = fetch_manifest(url, _token(db))
        entry["version"] = version
        local = active_files()
        changes = diff_files(remote, local)
        entry["added"] = changes["added"]
        entry["updated"] = changes["updated"]
        entry["removed"] = changes["removed"]
        pending = source.get("pending") if isinstance(source.get("pending"), dict) else None
        same_pending = bool(pending) and str(pending.get("version") or "") == version
        has_update = bool(changes["added"] or changes["updated"] or changes["removed"])
        if same_pending and pending is not None:
            # 同一版本已经下载并校验过：不重复下载、不重复校验，直接复用结果
            validation = read_validation()
            entry["validated"] = bool(validation.get("ok"))
            entry["error"] = str(validation.get("error") or "")
            entry["has_update"] = True
            entry["reused"] = True
        elif has_update:
            manifest = {
                "version": version,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "files": remote,
                "_url": url,
                "_token": _token(db),
            }
            stage(version, remote, manifest)
            request_validation(version)
            validation = wait_validation(version)
            entry["validated"] = bool(validation.get("ok"))
            entry["error"] = str(validation.get("error") or "")
            entry["has_update"] = True
            _write_json(
                source_path(),
                {
                    **source,
                    "pending": {
                        "version": version,
                        "files": remote,
                        "downloaded_at": entry["at"],
                        "validated": bool(validation.get("ok")),
                    },
                },
            )
            source = load_source()
        else:
            entry["has_update"] = False
            entry["validated"] = False
            entry["error"] = ""
    except RulesError as exc:
        entry["error"] = str(exc)
        entry["has_update"] = False
        entry["validated"] = False
    entry["configured"] = True
    entry["scheduled"] = scheduled
    source["last_check"] = entry
    source["last_check_at"] = entry["at"]
    _history_push(source, entry)
    save_source(source)
    return entry


def apply_pending(db: Session) -> dict[str, Any]:
    """把「已下载且校验通过」的待确认版本切到生效（人工确认后才走到这里）。"""
    source = load_source()
    pending = source.get("pending")
    if not isinstance(pending, dict) or not pending.get("version"):
        raise RulesError("没有待确认的新版本（先点「立即检查更新」）", 409)
    version = str(pending["version"])
    validation = read_validation()
    if str(validation.get("version") or "") != version or not validation.get("ok"):
        raise RulesError("待确认版本没有通过校验，不能生效", 409)
    request_activate(version)

    def activated() -> bool:
        return active_version() == version

    if not _wait(activated, float(settings.suricata_validate_timeout_seconds)):
        raise RulesError("等待签名引擎切换规则超时（容器未运行？）", 504)
    source = load_source()
    source.pop("pending", None)
    source["applied"] = {
        "version": version,
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    save_source(source)
    runtime = read_runtime()
    return {
        "activated": True,
        "version": version,
        "rule_count": _as_int(runtime.get("rule_count")) or 0,
    }


def reset_rules(db: Session) -> dict[str, Any]:
    """清空规则（回到空占位 ⇒ 签名引擎不再产生任何告警）。"""
    request_reset()

    def cleared() -> bool:
        return not active_version()

    if not _wait(cleared, float(settings.suricata_validate_timeout_seconds)):
        raise RulesError("等待签名引擎清空规则超时（容器未运行？）", 504)
    source = load_source()
    source.pop("pending", None)
    source["applied"] = {
        "version": "",
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    save_source(source)
    return {"reset": True, "rule_count": _as_int(read_runtime().get("rule_count")) or 0}


def status(db: Session) -> dict[str, Any]:
    """界面用的完整状态：配置 + 生效 + 待确认 + 最近检查 + 历史。"""
    cfg = source_config(db)
    source = load_source()
    runtime = read_runtime()
    validation = read_validation()
    pending = source.get("pending") if isinstance(source.get("pending"), dict) else None
    pending_out = None
    if pending:
        pending_out = {
            "version": str(pending.get("version") or ""),
            "files": [item.get("name") for item in (pending.get("files") or [])],
            "downloaded_at": str(pending.get("downloaded_at") or ""),
            "validated": bool(pending.get("validated")),
            "validation_error": str(validation.get("error") or "")
            if str(validation.get("version") or "") == str(pending.get("version") or "")
            else "",
        }
    return {
        "source": cfg,
        "active": {
            "version": active_version(),
            "files": [item["name"] for item in active_files()],
            "rule_count": active_rule_count(),
        },
        "pending": pending_out,
        "runtime": runtime,
        "last_check": source.get("last_check") or None,
        "last_check_at": source.get("last_check_at") or "",
        "history": source.get("history") or [],
    }
