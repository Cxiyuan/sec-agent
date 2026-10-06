"""签名引擎（Suricata）规则集管理：manifest 校验、哈希比对、暂存、校验与生效请求。

这一层最容易出的不是语法错，而是「口径错」：把不合法的 manifest 放行、哈希不一致还写盘、
或者「检查」直接把规则生效了（用户口径：生效必须人工确认）。所以逐条钉住。
"""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


@pytest.fixture(scope="module")
def rules(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("签名引擎规则集只在 NDR 侧")
    return importlib.import_module("app.suricata.rules")


@pytest.fixture
def rules_dir(rules: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """把规则卷指到临时目录（不碰真实 /rules）。"""
    from app.config import settings

    monkeypatch.setattr(settings, "suricata_rules_dir", str(tmp_path))
    (tmp_path / "active").mkdir(parents=True, exist_ok=True)
    (tmp_path / "staging").mkdir(parents=True, exist_ok=True)
    return tmp_path


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _manifest(files: dict[str, bytes], version: str = "v1") -> dict[str, Any]:
    return {
        "version": version,
        "files": [
            {"name": name, "sha256": _sha(body), "size": len(body)} for name, body in files.items()
        ],
    }


class _FakeDB:
    """最小可用的 DB 替身：够 source_config/save_source_config 用（不连 PG）。"""

    def __init__(self) -> None:
        self.rows: dict[str, Any] = {}

    def get(self, _model: Any, key: str) -> Any:
        return self.rows.get(key)

    def add(self, row: Any) -> None:
        self.rows[row.key] = row

    def commit(self) -> None:  # pragma: no cover - 替身
        return None


# ---------- URL 规范化 ----------


def test_normalize_url_fills_manifest(rules: ModuleType) -> None:
    assert rules.normalize_url("https://x.example/rules") == (
        "https://x.example/rules/manifest.json"
    )
    assert rules.normalize_url("https://x.example/rules/") == (
        "https://x.example/rules/manifest.json"
    )
    assert rules.normalize_url("http://x.example/a/b.json") == "http://x.example/a/b.json"


@pytest.mark.parametrize("bad", ["", "   ", "file:///etc/passwd", "ftp://x/y", "https://"])
def test_normalize_url_rejects(rules: ModuleType, bad: str) -> None:
    with pytest.raises(rules.RulesError):
        rules.normalize_url(bad)


# ---------- manifest 校验 ----------


def test_validate_manifest_ok(rules: ModuleType) -> None:
    version, files = rules.validate_manifest(
        _manifest({"a.rules": b"alert icmp any any -> any any (sid:1;)"})
    )
    assert version == "v1"
    assert files[0]["name"] == "a.rules"
    assert files[0]["sha256"] == _sha(b"alert icmp any any -> any any (sid:1;)")


@pytest.mark.parametrize(
    "patch",
    [
        {"version": ""},
        {"files": []},
        {"files": "x"},
        {"files": [{"name": "../evil.rules", "sha256": "a" * 64}]},
        {"files": [{"name": "x.txt", "sha256": "a" * 64}]},
        {"files": [{"name": "x.rules", "sha256": "zz"}]},
        {
            "files": [
                {"name": "x.rules", "sha256": "a" * 64},
                {"name": "x.rules", "sha256": "a" * 64},
            ]
        },
    ],
)
def test_validate_manifest_rejects(rules: ModuleType, patch: dict[str, Any]) -> None:
    data = {**_manifest({"a.rules": b"x"}), **patch}
    with pytest.raises(rules.RulesError):
        rules.validate_manifest(data)


def test_validate_manifest_enforces_limits(
    rules: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.config import settings

    monkeypatch.setattr(settings, "suricata_max_files", 1)
    with pytest.raises(rules.RulesError):
        rules.validate_manifest(_manifest({"a.rules": b"x", "b.rules": b"y"}))
    monkeypatch.setattr(settings, "suricata_max_file_bytes", 2)
    with pytest.raises(rules.RulesError):
        rules.validate_manifest(_manifest({"a.rules": b"xxx"}))


# ---------- 差异比对 ----------


def test_diff_files(rules: ModuleType) -> None:
    remote = [{"name": "a.rules", "sha256": "1"}, {"name": "b.rules", "sha256": "2"}]
    local = [{"name": "b.rules", "sha256": "old"}, {"name": "c.rules", "sha256": "3"}]
    assert rules.diff_files(remote, local) == {
        "added": ["a.rules"],
        "updated": ["b.rules"],
        "removed": ["c.rules"],
    }
    assert rules.diff_files(remote, remote) == {"added": [], "updated": [], "removed": []}


# ---------- 检查更新（不生效） ----------


def _stub_container_ok(rules: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """把「容器」换成可信替身：校验一律通过。"""
    monkeypatch.setattr(
        rules, "wait_validation", lambda version, timeout=None: {"version": version, "ok": True}
    )


def test_check_now_stages_and_validates(
    rules: ModuleType, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = b'alert dns any any -> any any (msg:"t"; sid:1000001; rev:1;)\n'
    manifest = _manifest({"shentong.rules": body}, version="2026.10.07-1")
    monkeypatch.setattr(
        rules, "fetch_manifest", lambda url, token="": (manifest["version"], manifest["files"])
    )
    monkeypatch.setattr(rules, "download_file", lambda url, item, token="": body)
    _stub_container_ok(rules, monkeypatch)

    db = _FakeDB()
    rules.save_source_config(db, "https://x.example/rules", "", True)
    entry = rules.check_now(db)
    assert entry["has_update"] is True
    assert entry["validated"] is True
    # 暂存目录里是「完整一套」+ manifest
    assert (rules_dir / "staging" / "shentong.rules").read_bytes() == body
    staged_manifest = json.loads(
        (rules_dir / "staging" / "manifest.json").read_text(encoding="utf-8")
    )
    assert staged_manifest["version"] == "2026.10.07-1"
    # 请求标记已下发（容器据此去跑 suricata -T）
    assert (rules_dir / "validate.request").read_text(encoding="utf-8").strip() == "2026.10.07-1"
    # 待确认版本与历史都记下了
    source = json.loads((rules_dir / "source.json").read_text(encoding="utf-8"))
    assert source["pending"]["version"] == "2026.10.07-1"
    assert source["last_check"]["has_update"] is True
    # 关键口径：检查**不生效**
    assert rules.active_version() == ""
    assert not (rules_dir / "active" / "shentong.rules").exists()


def test_check_now_hash_mismatch_keeps_active(
    rules: ModuleType, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = b"alert icmp any any -> any any (sid:1000002; rev:1;)\n"
    (rules_dir / "active" / "old.rules").write_bytes(
        b"alert icmp any any -> any any (sid:1; rev:1;)\n"
    )
    manifest = _manifest({"new.rules": body}, version="v2")
    monkeypatch.setattr(
        rules, "fetch_manifest", lambda url, token="": (manifest["version"], manifest["files"])
    )

    def boom(url: str, item: dict[str, Any], token: str = "") -> bytes:
        raise rules.RulesError("new.rules 的 sha256 与 manifest 不一致")

    monkeypatch.setattr(rules, "download_file", boom)
    _stub_container_ok(rules, monkeypatch)

    db = _FakeDB()
    rules.save_source_config(db, "https://x.example/rules", "", True)
    entry = rules.check_now(db)
    assert entry["has_update"] is False
    assert entry["error"]
    # 生效规则没被动过，也没有待确认版本
    assert rules.active_version() == ""
    assert (rules_dir / "active" / "old.rules").exists()
    assert "pending" not in rules.load_source()


def test_check_now_reuses_validated_pending(
    rules: ModuleType, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """同一版本已下载校验过：再检查不重复下载、不重复校验。"""
    body = b"alert icmp any any -> any any (sid:1000003; rev:1;)\n"
    manifest = _manifest({"a.rules": body}, version="v3")
    monkeypatch.setattr(
        rules, "fetch_manifest", lambda url, token="": (manifest["version"], manifest["files"])
    )
    calls = {"n": 0}

    def download(url: str, item: dict[str, Any], token: str = "") -> bytes:
        calls["n"] += 1
        return body

    monkeypatch.setattr(rules, "download_file", download)
    _stub_container_ok(rules, monkeypatch)
    db = _FakeDB()
    rules.save_source_config(db, "https://x.example/rules", "", True)
    rules._write_json(rules.validation_path(), {"version": "v3", "ok": True})
    rules.save_source(
        {
            "pending": {
                "version": "v3",
                "files": manifest["files"],
                "downloaded_at": "2026-10-07T00:00:00Z",
                "validated": True,
            }
        }
    )
    entry = rules.check_now(db)
    assert entry["reused"] is True
    assert calls["n"] == 0


def test_check_now_without_url_raises(rules: ModuleType, rules_dir: Path) -> None:
    with pytest.raises(rules.RulesError):
        rules.check_now(_FakeDB())
    # 定时任务里没配地址 = 正常空转
    assert rules.check_now(_FakeDB(), scheduled=True) == {"configured": False, "has_update": False}


# ---------- 生效 / 清空 ----------


def test_apply_requires_validated_pending(
    rules: ModuleType, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(rules.RulesError) as excinfo:
        rules.apply_pending(_FakeDB())
    assert excinfo.value.status == 409

    rules.save_source({"pending": {"version": "v9", "files": [], "validated": False}})
    rules._write_json(rules.validation_path(), {"version": "v9", "ok": False, "error": "bad"})
    with pytest.raises(rules.RulesError) as excinfo:
        rules.apply_pending(_FakeDB())
    assert excinfo.value.status == 409


def test_apply_writes_activate_request(
    rules: ModuleType, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules.save_source(
        {"pending": {"version": "v9", "files": [{"name": "a.rules"}], "validated": True}}
    )
    rules._write_json(rules.validation_path(), {"version": "v9", "ok": True})
    monkeypatch.setattr(rules, "_wait", lambda predicate, timeout: True)
    rules._write_json(rules.runtime_path(), {"rule_count": 7})
    result = rules.apply_pending(_FakeDB())
    assert result == {"activated": True, "version": "v9", "rule_count": 7}
    assert (rules_dir / "activate.request").read_text(encoding="utf-8").strip() == "v9"
    assert "pending" not in rules.load_source()


def test_reset_writes_request(
    rules: ModuleType, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rules, "_wait", lambda predicate, timeout: True)
    rules._write_json(rules.runtime_path(), {"rule_count": 0})
    result = rules.reset_rules(_FakeDB())
    assert result["reset"] is True
    assert (rules_dir / "reset.request").exists()


# ---------- 读写与配置 ----------


def test_read_json_tolerates_broken_file(rules: ModuleType, rules_dir: Path) -> None:
    (rules_dir / "source.json").write_text("{ not json", encoding="utf-8")
    assert rules.load_source() == {}
    assert rules.read_runtime() == {}
    assert rules.read_validation() == {}


def test_source_config_roundtrip_and_token_masking(rules: ModuleType, rules_dir: Path) -> None:
    db = _FakeDB()
    cfg = rules.save_source_config(db, "https://x.example/rules", "s3cret", True)
    assert cfg == {
        "url": "https://x.example/rules/manifest.json",
        "token_set": True,
        "enabled": True,
    }
    # 令牌不回显：接口只给 token_set
    assert "s3cret" not in json.dumps(cfg)
    # 不传 token = 保留；空串 = 清除
    assert rules.save_source_config(db, None, None, None)["token_set"] is True
    assert rules.save_source_config(db, None, "", None)["token_set"] is False
    assert rules.save_source_config(db, None, None, False)["enabled"] is False
    assert rules.save_source_config(db, "", None, None)["url"] == ""


def test_active_rule_count_prefers_runtime(rules: ModuleType, rules_dir: Path) -> None:
    (rules_dir / "active" / "a.rules").write_text(
        "alert icmp any any -> any any (sid:1; rev:1;)\n", encoding="utf-8"
    )
    assert rules.active_rule_count() == 1
    rules._write_json(rules.runtime_path(), {"rule_count": 42})
    assert rules.active_rule_count() == 42


def test_status_includes_files_and_runtime(rules: ModuleType, rules_dir: Path) -> None:
    body = b"alert icmp any any -> any any (sid:1000009; rev:1;)\n"
    (rules_dir / "active" / "a.rules").write_bytes(body)
    rules._write_json(
        rules.active_dir() / "manifest.json", {"version": "v5", "files": [{"name": "a.rules"}]}
    )
    rules._write_json(rules.runtime_path(), {"rule_count": 1, "alive": True})
    status = rules.status(_FakeDB())
    assert status["active"]["version"] == "v5"
    assert status["active"]["files"] == ["a.rules"]
    assert status["active"]["rule_count"] == 1
    assert status["pending"] is None


# ---------- 接口接线 ----------


def test_endpoints_registered(rules: ModuleType) -> None:
    route = importlib.import_module("app.api.routes.suricata")
    paths = sorted(r.path for r in route.router.routes)
    assert paths == [
        "/api/suricata/rules",
        "/api/suricata/rules/apply",
        "/api/suricata/rules/check",
        "/api/suricata/rules/reset",
        "/api/suricata/rules/source",
    ]
    # 聚合路由必须真的挂上（漏了 include 就是「接口写好了但访问 404」）
    router_src = (
        Path(__file__).resolve().parents[2] / "ndr" / "backend" / "app" / "api" / "router.py"
    ).read_text(encoding="utf-8")
    assert "from app.api.routes.suricata import router as suricata_router" in router_src
    assert "api_router.include_router(suricata_router)" in router_src
