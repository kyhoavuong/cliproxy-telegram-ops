#!/usr/bin/env python3
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import fcntl
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

BASE_DIR = Path(os.environ.get("CLIPROXY_BASE_DIR", "/opt/cliproxy"))
ENV_FILE = BASE_DIR / ".env"


def strip_simple_quotes(value):
    value = str(value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1].strip()
    return value


def parse_env_file_token(path):
    values = {}
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except Exception:
        return ""
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if name not in {"CLIPROXY_MANAGEMENT_TOKEN", "CPA_MANAGEMENT_KEY"}:
            continue
        value = strip_simple_quotes(value)
        if value:
            values[name] = value
    for name in ("CLIPROXY_MANAGEMENT_TOKEN", "CPA_MANAGEMENT_KEY"):
        if values.get(name):
            return values[name]
    return ""


def load_management_token():
    for name in ("CLIPROXY_MANAGEMENT_TOKEN", "CPA_MANAGEMENT_KEY"):
        value = strip_simple_quotes(os.environ.get(name, ""))
        if value:
            return value
    return parse_env_file_token(ENV_FILE)


QUOTA_CONFIG = BASE_DIR / "quota-enforcer" / "quotas.json"
CLIPROXY_CONFIG = BASE_DIR / "config" / "config.yaml"
USAGE_DB = BASE_DIR / "usage-keeper" / "app.db"
AUTH_DIR = BASE_DIR / "data" / "auth"
MANUAL_BACKUPS_DIR = BASE_DIR / "manual-backups"
LOCK_FILE = BASE_DIR / "quota-enforcer" / "quota_enforcer.lock"
STATE_FILE = BASE_DIR / "quota-enforcer" / "state.json"
CLIPROXY_MANAGEMENT_BASE_URL = os.environ.get("CLIPROXY_MANAGEMENT_BASE_URL", "http://127.0.0.1:3000/v0/management").rstrip("/")
CLIPROXY_MANAGEMENT_TOKEN = load_management_token()
HTTP_TIMEOUT_SECONDS = int(os.environ.get("AUTH_QUOTA_HTTP_TIMEOUT_SECONDS", "8") or 8)
AUTH_QUOTA_ENFORCER_COOLDOWN_SECONDS = int(os.environ.get("AUTH_QUOTA_ENFORCER_COOLDOWN_SECONDS", "300") or 300)
AUTH_QUOTA_LAST_CHECK_KEY = "last_auth_quota_check_at"
AUTH_QUOTA_NEXT_CHECK_KEY = "next_auth_quota_check_at"
AUTH_WEEKLY_AUTO_DISABLED_KEY = "auth_weekly_auto_disabled"
AUTH_REAUTH_AUTO_DISABLED_KEY = "auth_reauth_auto_disabled"
AUTH_WEEKLY_RECENT_TRANSITIONS_KEY = "auth_weekly_recent_transitions"
AUTH_WEEKLY_TRANSITION_TTL_SECONDS = 10 * 60
CODEX_WHAM_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"
CODEX_WHAM_HEADERS = {
    "Authorization": "Bearer $TOKEN$",
    "Content-Type": "application/json",
    "User-Agent": "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
}
MISSING = object()

def log(message):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {message}", flush=True)

def load_quota_config():
    with QUOTA_CONFIG.open("r", encoding="utf-8") as f:
        cfg = json.load(f)

    keys = []
    seen = set()

    for item in cfg.get("keys", []):
        name = str(item.get("name", "")).strip()
        key = str(item.get("key", "")).strip()
        daily_limit = normalize_limit(item.get("daily_token_limit"), "daily_token_limit", name)
        weekly_raw = item.get("weekly_token_limit", MISSING)

        if not key:
            continue
        if key in seen:
            raise ValueError(f"duplicate key in quotas.json: {name}")
        seen.add(key)

        if weekly_raw is MISSING:
            weekly_limit = daily_limit * 4 if daily_limit is not None else None
        else:
            weekly_limit = normalize_limit(weekly_raw, "weekly_token_limit", name)

        normalized = {
            "name": name or key[-8:],
            "key": key,
            "daily_token_limit": daily_limit,
            "weekly_token_limit": weekly_limit,
        }
        if weekly_raw is MISSING:
            normalized["_weekly_token_limit_defaulted"] = True

        keys.append(normalized)

    cfg["keys"] = keys
    cfg["dry_run"] = bool(cfg.get("dry_run", False))
    cfg["timezone"] = cfg.get("timezone", "Asia/Ho_Chi_Minh")
    return cfg


def normalize_limit(value, field, name):
    if value is None:
        return None

    limit = int(value)
    if limit <= 0:
        raise ValueError(f"{field} must be positive for {name}")
    return limit


def save_quota_config(cfg):
    keys = []
    for item in cfg.get("keys", []):
        saved = {
            "name": item.get("name"),
            "key": item.get("key"),
            "daily_token_limit": item.get("daily_token_limit"),
        }
        if not item.get("_weekly_token_limit_defaulted"):
            saved["weekly_token_limit"] = item.get("weekly_token_limit")
        keys.append(saved)

    data = {
        "timezone": cfg.get("timezone", "Asia/Ho_Chi_Minh"),
        "dry_run": bool(cfg.get("dry_run", False)),
        "keys": keys,
    }
    QUOTA_CONFIG.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

def load_quota_state():
    if not STATE_FILE.exists():
        return {}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_quota_state(state):
    data = state if isinstance(state, dict) else {}
    STATE_FILE.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def save_disabled_state(disabled_keys):
    data = load_quota_state()
    data["disabled_by_quota"] = sorted(set(disabled_keys))
    save_quota_state(data)
    return data


# A stale CPA soft-delete first seen while a key is quota-disabled is not enough
# manual-delete evidence later; daily/weekly reset clears disabled_by_quota first.
CPA_DELETED_WHILE_QUOTA_DISABLED_KEY = "cpa_deleted_while_quota_disabled"


def load_cpa_deleted_keys_with_status():
    if not USAGE_DB.exists():
        return set(), False
    deleted = set()
    try:
        conn = sqlite3.connect(f"file:{USAGE_DB}?mode=ro", uri=True, timeout=4)
        try:
            for row in conn.execute(
                """
                SELECT api_key
                FROM cpa_api_keys
                WHERE COALESCE(api_key, '') != ''
                  AND COALESCE(is_deleted, 0) != 0
                """
            ):
                key = str(row[0] or "").strip()
                if key:
                    deleted.add(key)
        finally:
            conn.close()
    except Exception as exc:
        log(f"CPA manual-delete evidence unavailable: {exc.__class__.__name__}")
        return set(), False
    return deleted, True


def quota_state_key_set(state, name):
    return {
        str(key or "").strip()
        for key in list_or_empty(dict_or_empty(state).get(name))
        if str(key or "").strip()
    }


def active_manually_disabled_keys(state):
    manually_disabled = quota_state_key_set(state, "manually_disabled_keys")
    if not manually_disabled:
        return set()
    try:
        if not CLIPROXY_CONFIG.exists():
            return manually_disabled
        _, _, _, proxy_keys = parse_api_keys_block(CLIPROXY_CONFIG.read_text(encoding="utf-8"))
    except Exception as exc:
        log(f"manual-disabled proxy config check unavailable: {exc.__class__.__name__}")
        return manually_disabled
    proxy_key_set = {str(key or "").strip() for key in proxy_keys if str(key or "").strip()}
    return {key for key in manually_disabled if key not in proxy_key_set}


def prune_cpa_deleted_quota_items(cfg, state, cpa_deleted_keys, dry_run=False, cpa_evidence_reliable=True):
    deleted = {str(key or "").strip() for key in (cpa_deleted_keys or []) if str(key or "").strip()}
    disabled_by_quota = quota_state_key_set(state, "disabled_by_quota")
    manually_disabled = active_manually_disabled_keys(state)
    protected_tombstones = quota_state_key_set(state, CPA_DELETED_WHILE_QUOTA_DISABLED_KEY)
    if cpa_evidence_reliable:
        protected_tombstones = {key for key in protected_tombstones if key in deleted}
    if protected_tombstones or CPA_DELETED_WHILE_QUOTA_DISABLED_KEY in dict_or_empty(state):
        state[CPA_DELETED_WHILE_QUOTA_DISABLED_KEY] = sorted(protected_tombstones)
    if not deleted:
        return set()
    items = list(cfg.get("keys", []) or [])
    kept = []
    removed = set()
    skipped_disabled = set()
    skipped_manual = set()
    skipped_protected = set()
    for item in items:
        key = str(item.get("key") or "").strip() if isinstance(item, dict) else ""
        if key and key in deleted:
            if key in disabled_by_quota:
                skipped_disabled.add(key)
                protected_tombstones.add(key)
                kept.append(item)
                continue
            if key in manually_disabled:
                skipped_manual.add(key)
                kept.append(item)
                continue
            if key in protected_tombstones:
                skipped_protected.add(key)
                kept.append(item)
                continue
            removed.add(key)
            continue
        kept.append(item)
    state[CPA_DELETED_WHILE_QUOTA_DISABLED_KEY] = sorted(protected_tombstones)
    if not removed:
        if skipped_disabled:
            log(f"CPA manual-delete sync protected_stale_cpa_tombstone_count={len(skipped_disabled)}")
        if skipped_manual:
            log(f"CPA manual-delete sync skipped_manually_disabled_count={len(skipped_manual)}")
        if skipped_protected:
            log(f"CPA manual-delete sync skipped_protected_stale_cpa_tombstone_count={len(skipped_protected)}")
        return set()
    cfg["keys"] = kept
    disabled = [
        str(key or "").strip()
        for key in list_or_empty(state.get("disabled_by_quota"))
        if str(key or "").strip() and str(key or "").strip() not in removed
    ]
    state["disabled_by_quota"] = sorted(set(disabled))
    if not dry_run:
        save_quota_config(cfg)
    log(f"CPA manual-delete sync removed_quota_count={len(removed)}")
    if skipped_disabled:
        log(f"CPA manual-delete sync protected_stale_cpa_tombstone_count={len(skipped_disabled)}")
    if skipped_manual:
        log(f"CPA manual-delete sync skipped_manually_disabled_count={len(skipped_manual)}")
    if skipped_protected:
        log(f"CPA manual-delete sync skipped_protected_stale_cpa_tombstone_count={len(skipped_protected)}")
    return removed


def default_key_name(key):
    return key.split("-", 1)[0] if "-" in key else key[-8:]


def now_ts():
    return int(datetime.now(timezone.utc).timestamp())


def dict_or_empty(value):
    return value if isinstance(value, dict) else {}


def list_or_empty(value):
    return value if isinstance(value, list) else []


def payload_items(data):
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for key in ("files", "items", "data", "results", "rows"):
        value = data.get(key)
        if isinstance(value, list):
            return value
    return []


def auth_identity_index(item):
    item = dict_or_empty(item)
    return str(
        item.get("identity")
        or item.get("auth_index")
        or item.get("authIndex")
        or item.get("index")
        or item.get("id")
        or ""
    ).strip()


def auth_file_is_codex(item):
    item = dict_or_empty(item)
    provider = str(
        item.get("provider")
        or item.get("type")
        or item.get("auth_type")
        or item.get("authType")
        or ""
    ).strip().lower().replace("_", "-")
    return provider in {"codex", "1"}


def auth_file_name(item):
    item = dict_or_empty(item)
    for key in ("file_name", "filename", "name"):
        raw = str(item.get(key) or "").strip()
        if not raw:
            continue
        name = Path(raw).name
        if name and name.endswith(".json"):
            return name
    return ""


def auth_file_path(name):
    name = Path(str(name or "")).name
    if not name.endswith(".json"):
        return None
    path = (AUTH_DIR / name).resolve()
    try:
        if path.parent != AUTH_DIR.resolve():
            return None
    except FileNotFoundError:
        return None
    return path


def load_auth_json(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def write_json_preserve_inode(path, data):
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    with path.open("r+", encoding="utf-8") as file:
        file.seek(0)
        file.write(text)
        file.truncate()
        file.flush()
        os.fsync(file.fileno())


def auth_quota_ref(name):
    return hashlib.sha256(f"auth-file:{Path(str(name or '')).name}".encode("utf-8")).hexdigest()[:16]


def auth_quota_state_maps(state, ts):
    state = state if isinstance(state, dict) else {}
    auto_disabled = state.setdefault(AUTH_WEEKLY_AUTO_DISABLED_KEY, {})
    if not isinstance(auto_disabled, dict):
        auto_disabled = {}
        state[AUTH_WEEKLY_AUTO_DISABLED_KEY] = auto_disabled
    reauth_auto_disabled = state.setdefault(AUTH_REAUTH_AUTO_DISABLED_KEY, {})
    if not isinstance(reauth_auto_disabled, dict):
        reauth_auto_disabled = {}
        state[AUTH_REAUTH_AUTO_DISABLED_KEY] = reauth_auto_disabled
    recent = state.setdefault(AUTH_WEEKLY_RECENT_TRANSITIONS_KEY, {})
    if not isinstance(recent, dict):
        recent = {}
        state[AUTH_WEEKLY_RECENT_TRANSITIONS_KEY] = recent
    for key, item in list(recent.items()):
        if not isinstance(item, dict) or int(item.get("expires_at", 0) or 0) <= int(ts):
            recent.pop(key, None)
    return auto_disabled, recent, reauth_auto_disabled


def management_request(path, method="GET", payload=None):
    if not CLIPROXY_MANAGEMENT_TOKEN:
        raise RuntimeError("management token unavailable")
    url = urljoin(f"{CLIPROXY_MANAGEMENT_BASE_URL}/", str(path or "").lstrip("/"))
    data = None
    headers = {
        "Authorization": f"Bearer {CLIPROXY_MANAGEMENT_TOKEN}",
        "User-Agent": "cliproxy-quota-enforcer/1.0",
    }
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        body = response.read(1024 * 1024)
        status = getattr(response, "status", 200)
    if status >= 400:
        raise RuntimeError(f"management HTTP {status}")
    text = body.decode("utf-8", errors="replace")
    if not text:
        return {}
    data = json.loads(text)
    return data if isinstance(data, (dict, list)) else {}


def parse_jsonish_body(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            data = json.loads(value)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


class AuthReauthRequired(RuntimeError):
    pass


AUTH_REAUTH_STATUSES = {
    "unauthorized_401",
    "token_revoked",
    "invalid_auth",
    "expired_auth",
    "auth_invalid",
    "needs_reauth",
    "reauth_required",
}
REAUTH_EVIDENCE_PATTERNS = (
    "unauthorized_401",
    "invalidated token",
    "token invalidated",
    "has been invalidated",
    "needs_reauth",
    "invalid_auth",
    "expired_auth",
    "please try signing in again",
)


def is_reauth_status(status):
    status = str(status or "").strip().lower()
    return (
        status in AUTH_REAUTH_STATUSES
        or "unauthorized" in status
        or "reauth" in status
        or status.startswith("invalid_auth")
        or status.startswith("expired_auth")
    )


def auth_item_reauth_text(item):
    item = dict_or_empty(item)
    parts = []
    for key in (
        "status",
        "state",
        "auth_status",
        "authStatus",
        "http_status_code",
        "httpStatusCode",
        "code",
        "error",
        "message",
        "detail",
        "reason",
    ):
        value = item.get(key)
        if isinstance(value, (str, int, float, bool)):
            parts.append(str(value))
    return " | ".join(parts).strip()


def auth_item_has_reauth_evidence(item):
    status = str(dict_or_empty(item).get("status") or dict_or_empty(item).get("state") or "").strip().lower()
    if status in {"", "normal", "ok", "healthy", "available", "completed"}:
        return False
    if is_reauth_status(status):
        return True
    text = auth_item_reauth_text(item).lower()
    if "401" in text or "unauthorized" in text:
        return True
    return any(pattern in text for pattern in REAUTH_EVIDENCE_PATTERNS)


def api_call_response_has_reauth_evidence(data):
    data = dict_or_empty(data)
    status_code = int_state_value(data.get("status_code") or data.get("statusCode"), 0)
    body = parse_jsonish_body(data.get("body") if "body" in data else data)
    text_parts = [str(status_code or "")]
    error = body.get("error") if isinstance(body, dict) else {}
    if isinstance(error, dict):
        text_parts.extend(str(error.get(key) or "") for key in ("code", "message", "type"))
    elif isinstance(error, str):
        text_parts.append(error)
    for key in ("code", "message", "detail", "status"):
        text_parts.append(str(body.get(key) or ""))
    text = " | ".join(text_parts).lower()
    return status_code == 401 or is_reauth_status(body.get("status")) or any(pattern in text for pattern in REAUTH_EVIDENCE_PATTERNS)


def exception_has_reauth_evidence(exc):
    text = str(exc or "").lower()
    if "401" in text or "unauthorized" in text:
        return True
    return any(pattern in text for pattern in REAUTH_EVIDENCE_PATTERNS)


def management_api_call_body(data):
    data = dict_or_empty(data)
    status_code = int(data.get("status_code") or data.get("statusCode") or 0)
    if status_code and (status_code < 200 or status_code >= 300):
        raise RuntimeError(f"management upstream HTTP {status_code}")
    return parse_jsonish_body(data.get("body") if "body" in data else data)


def window_used_percent(quota_data, window_name):
    quota_data = dict_or_empty(quota_data)
    rate_limit = dict_or_empty(quota_data.get("rate_limit") or quota_data.get("rateLimit"))
    window = dict_or_empty(rate_limit.get(f"{window_name}_window") or rate_limit.get(f"{window_name}Window"))
    raw = window.get("usedPercent", window.get("used_percent", window.get("usedPercentage")))
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def auth_remaining_percents(auth_index):
    response = management_request(
        "api-call",
        method="POST",
        payload={
            "authIndex": auth_index,
            "method": "GET",
            "url": CODEX_WHAM_USAGE_URL,
            "header": dict(CODEX_WHAM_HEADERS),
        },
    )
    if api_call_response_has_reauth_evidence(response):
        raise AuthReauthRequired("reauth required")
    body = management_api_call_body(response)
    values = {}
    for source, target in (("primary", "daily"), ("secondary", "weekly")):
        used = window_used_percent(body, source)
        if used is None:
            return None
        values[target] = max(0.0, min(100.0, 100.0 - used))
    return values


def auth_quota_result():
    return {
        "management_token_present": int(bool(CLIPROXY_MANAGEMENT_TOKEN)),
        "auth_files_count": 0,
        "codex_candidate_count": 0,
        "checked_auth_count": 0,
        "auto_disabled_count": 0,
        "auto_enabled_count": 0,
        "reauth_auto_disabled_count": 0,
        "reauth_auto_enabled_count": 0,
        "skipped_manual_disabled_count": 0,
        "quota_check_failed_count": 0,
    }


def log_auth_quota_result(result):
    log(
        "auth quota enforcer "
        f"management_token_present={int(result.get('management_token_present', 0) or 0)} "
        f"auth_files_count={int(result.get('auth_files_count', 0) or 0)} "
        f"codex_candidate_count={int(result.get('codex_candidate_count', 0) or 0)} "
        f"checked_auth_count={int(result.get('checked_auth_count', 0) or 0)} "
        f"auto_disabled_count={int(result.get('auto_disabled_count', 0) or 0)} "
        f"auto_enabled_count={int(result.get('auto_enabled_count', 0) or 0)} "
        f"reauth_auto_disabled_count={int(result.get('reauth_auto_disabled_count', 0) or 0)} "
        f"reauth_auto_enabled_count={int(result.get('reauth_auto_enabled_count', 0) or 0)} "
        f"skipped_manual_disabled_count={int(result.get('skipped_manual_disabled_count', 0) or 0)} "
        f"quota_check_failed_count={int(result.get('quota_check_failed_count', 0) or 0)}"
    )


def find_auth_file_by_ref(ref):
    target = str(ref or "").strip()
    if not target or not AUTH_DIR.exists():
        return None
    for path in sorted(AUTH_DIR.glob("*.json")):
        if auth_quota_ref(path.name) == target:
            return path
    return None


def auth_weekly_migration_result():
    result = {
        "total_codex_auth_count": 0,
        "disabled_codex_count": 0,
        "migrated_enabled_count": 0,
        "backup_path": "",
        "backup_skipped_count": 0,
    }
    result.update(auth_quota_result())
    return result


def log_auth_weekly_migration_result(result):
    log(
        "auth weekly migration "
        f"total_codex_auth_count={int(result.get('total_codex_auth_count', 0) or 0)} "
        f"disabled_codex_count={int(result.get('disabled_codex_count', 0) or 0)} "
        f"migrated_enabled_count={int(result.get('migrated_enabled_count', 0) or 0)} "
        f"checked_auth_count={int(result.get('checked_auth_count', 0) or 0)} "
        f"auto_disabled_count={int(result.get('auto_disabled_count', 0) or 0)} "
        f"auto_enabled_count={int(result.get('auto_enabled_count', 0) or 0)} "
        f"skipped_manual_disabled_count={int(result.get('skipped_manual_disabled_count', 0) or 0)} "
        f"quota_check_failed_count={int(result.get('quota_check_failed_count', 0) or 0)}"
    )


def backup_auth_files_for_migration(ts):
    stamp = datetime.fromtimestamp(int(ts), timezone.utc).astimezone().strftime("%Y%m%d-%H%M%S")
    backup_dir = MANUAL_BACKUPS_DIR / f"auth-weekly-manual-disabled-migration-{stamp}"
    candidate = backup_dir
    suffix = 1
    while candidate.exists():
        candidate = MANUAL_BACKUPS_DIR / f"auth-weekly-manual-disabled-migration-{stamp}-{suffix}"
        suffix += 1
    candidate.mkdir(parents=True, exist_ok=False)
    skipped = 0
    if AUTH_DIR.exists():
        for path in sorted(AUTH_DIR.glob("*.json")):
            if not path.is_file():
                continue
            try:
                shutil.copy2(path, candidate / path.name)
            except Exception:
                skipped += 1
                continue
    return candidate, skipped


def auth_file_is_codex_data(path, data):
    if not isinstance(data, dict):
        return False
    value = str(data.get("type") or "").strip().lower().replace("_", "-")
    if not value:
        value = path.stem.split("-", 1)[0].strip().lower().replace("_", "-")
    return value == "codex"


def migration_candidate_paths(state):
    auto_disabled = dict_or_empty((state if isinstance(state, dict) else {}).get(AUTH_WEEKLY_AUTO_DISABLED_KEY))
    candidates = []
    total_codex = 0
    disabled_codex = 0
    if not AUTH_DIR.exists():
        return candidates, total_codex, disabled_codex
    for path in sorted(AUTH_DIR.glob("*.json")):
        data = load_auth_json(path)
        if not auth_file_is_codex_data(path, data):
            continue
        total_codex += 1
        if not bool(data.get("disabled")):
            continue
        disabled_codex += 1
        ref = auth_quota_ref(path.name)
        if isinstance(auto_disabled.get(ref), dict):
            continue
        candidates.append((path, data))
    return candidates, total_codex, disabled_codex


def run_auth_weekly_manual_disabled_migration(state, dry_run=False, ts=None):
    result = auth_weekly_migration_result()
    ts = now_ts() if ts is None else int(ts)
    state = state if isinstance(state, dict) else {}
    candidates, total_codex, disabled_codex = migration_candidate_paths(state)
    result["total_codex_auth_count"] = total_codex
    result["disabled_codex_count"] = disabled_codex
    backup_dir = None
    if candidates and not dry_run:
        backup_dir, skipped_backup_count = backup_auth_files_for_migration(ts)
        result["backup_path"] = str(backup_dir)
        result["backup_skipped_count"] = int(skipped_backup_count or 0)
    for path, data in candidates:
        if dry_run:
            result["migrated_enabled_count"] += 1
            continue
        try:
            updated = dict(data)
            updated["disabled"] = False
            write_json_preserve_inode(path, updated)
            result["migrated_enabled_count"] += 1
        except Exception:
            continue
    auth_result = enforce_auth_weekly_quota(state, dry_run=dry_run, ts=ts)
    result.update(auth_result)
    log_auth_weekly_migration_result(result)
    return result


def auth_quota_block_reasons(quota_remaining):
    quota_remaining = dict_or_empty(quota_remaining)
    reasons = []
    try:
        daily = float(quota_remaining.get("daily"))
    except (TypeError, ValueError):
        daily = None
    try:
        weekly = float(quota_remaining.get("weekly"))
    except (TypeError, ValueError):
        weekly = None
    if daily is not None and daily <= 0:
        reasons.append("daily")
    if weekly is not None and weekly <= 0:
        reasons.append("weekly")
    return reasons


def auth_quota_marker(auth_index, reasons, ts):
    marker = {"auth_index": auth_index, "disabled_at": ts, "last_seen_at": ts}
    if reasons:
        marker["reasons"] = list(reasons)
    return marker


def update_auth_quota_marker(marker, auth_index, reasons, ts):
    marker["last_seen_at"] = ts
    if auth_index:
        marker["auth_index"] = auth_index
    marker["reasons"] = list(reasons)


def auth_reauth_marker(auth_index, ts):
    return {"auth_index": auth_index, "disabled_at": ts, "last_seen_at": ts}


def update_auth_reauth_marker(marker, auth_index, ts):
    marker["last_seen_at"] = ts
    if auth_index:
        marker["auth_index"] = auth_index


def auth_quota_recovery_ready(quota_remaining):
    quota_remaining = dict_or_empty(quota_remaining)
    try:
        daily = float(quota_remaining.get("daily"))
        weekly = float(quota_remaining.get("weekly"))
    except (TypeError, ValueError):
        return False
    return daily > 0 and weekly > 0


def process_auth_reauth_failed_account(state_maps, result, ref, path, auth_index, dry_run, ts):
    _quota_auto_disabled, recent, reauth_auto_disabled = state_maps
    data = load_auth_json(path)
    if not data:
        return
    result["checked_auth_count"] += 1
    marker = reauth_auto_disabled.get(ref)
    result["reauth_auto_disabled_count"] += 1
    if not dry_run:
        if not bool(data.get("disabled")):
            data["disabled"] = True
            write_json_preserve_inode(path, data)
        if isinstance(marker, dict):
            update_auth_reauth_marker(marker, auth_index, ts)
        else:
            reauth_auto_disabled[ref] = auth_reauth_marker(auth_index, ts)
        recent[ref] = {"status": "disabled", "expires_at": ts + AUTH_WEEKLY_TRANSITION_TTL_SECONDS, "reasons": ["reauth"]}


def process_auth_reauth_recovery_account(state_maps, result, ref, path, auth_index, quota_remaining, dry_run, ts):
    quota_auto_disabled, recent, reauth_auto_disabled = state_maps
    marker = reauth_auto_disabled.get(ref)
    if not isinstance(marker, dict):
        return False
    data = load_auth_json(path)
    if not data:
        return True
    result["checked_auth_count"] += 1
    if not auth_quota_recovery_ready(quota_remaining):
        if not dry_run:
            if not bool(data.get("disabled")):
                data["disabled"] = True
                write_json_preserve_inode(path, data)
            update_auth_reauth_marker(marker, auth_index, ts)
        return True
    result["reauth_auto_enabled_count"] += 1
    if not dry_run:
        data["disabled"] = False
        write_json_preserve_inode(path, data)
        reauth_auto_disabled.pop(ref, None)
        quota_auto_disabled.pop(ref, None)
        recent[ref] = {"status": "enabled", "expires_at": ts + AUTH_WEEKLY_TRANSITION_TTL_SECONDS, "reasons": ["reauth"]}
    return True


def process_auth_weekly_quota_account(state_maps, result, ref, path, auth_index, quota_remaining, dry_run, ts):
    # Quota evidence owns the disabled flag for Codex auth accounts. A disabled
    # account with exhausted quota is adopted into quota tracking so it can
    # recover automatically later; a disabled account with healthy quota is
    # re-enabled even if it was toggled off manually.
    auto_disabled, recent, reauth_auto_disabled = state_maps
    if isinstance(reauth_auto_disabled.get(ref), dict):
        if process_auth_reauth_recovery_account(state_maps, result, ref, path, auth_index, quota_remaining, dry_run, ts):
            return
    data = load_auth_json(path)
    if not data:
        return
    result["checked_auth_count"] += 1
    disabled = bool(data.get("disabled"))
    marker = auto_disabled.get(ref)
    reasons = auth_quota_block_reasons(quota_remaining)
    if reasons:
        if disabled:
            if isinstance(marker, dict):
                update_auth_quota_marker(marker, auth_index, reasons, ts)
            elif not dry_run:
                auto_disabled[ref] = auth_quota_marker(auth_index, reasons, ts)
                recent[ref] = {"status": "disabled", "expires_at": ts + AUTH_WEEKLY_TRANSITION_TTL_SECONDS, "reasons": list(reasons)}
            result["auto_disabled_count"] += 1
            return
        result["auto_disabled_count"] += 1
        if not dry_run:
            data["disabled"] = True
            write_json_preserve_inode(path, data)
            auto_disabled[ref] = auth_quota_marker(auth_index, reasons, ts)
            recent[ref] = {"status": "disabled", "expires_at": ts + AUTH_WEEKLY_TRANSITION_TTL_SECONDS, "reasons": list(reasons)}
        return
    if disabled:
        result["auto_enabled_count"] += 1
        if not dry_run:
            data["disabled"] = False
            write_json_preserve_inode(path, data)
            auto_disabled.pop(ref, None)
            marker_reasons = marker.get("reasons") if isinstance(marker, dict) else []
            recent[ref] = {"status": "enabled", "expires_at": ts + AUTH_WEEKLY_TRANSITION_TTL_SECONDS, "reasons": list(marker_reasons or [])}
        return
    if isinstance(marker, dict):
        auto_disabled.pop(ref, None)


def int_state_value(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def auth_quota_cooldown_seconds():
    try:
        return max(0, int(AUTH_QUOTA_ENFORCER_COOLDOWN_SECONDS))
    except (TypeError, ValueError):
        return 300


def auth_quota_next_check_at(state):
    state = state if isinstance(state, dict) else {}
    next_at = int_state_value(state.get(AUTH_QUOTA_NEXT_CHECK_KEY), 0)
    if next_at > 0:
        return next_at
    last_at = int_state_value(state.get(AUTH_QUOTA_LAST_CHECK_KEY), 0)
    if last_at > 0:
        return last_at + auth_quota_cooldown_seconds()
    return 0


def enforce_auth_quota_if_due(state, dry_run=False, ts=None, force=False):
    # The systemd timer may run every minute, but backend quota checks can hit
    # management/ChatGPT quota APIs; persisted cooldown keeps that boundary quiet.
    result = auth_quota_result()
    ts = now_ts() if ts is None else int(ts)
    state = state if isinstance(state, dict) else {}
    next_at = auth_quota_next_check_at(state)
    if not force and next_at > 0 and ts < next_at:
        log(f"auth quota enforcer auth_quota_skipped_cooldown=1 next_auth_quota_check_at={next_at}")
        return result
    if not dry_run:
        state[AUTH_QUOTA_LAST_CHECK_KEY] = ts
        state[AUTH_QUOTA_NEXT_CHECK_KEY] = ts + auth_quota_cooldown_seconds()
    return enforce_auth_weekly_quota(state, dry_run=dry_run, ts=ts)


def auth_files_payload_reliable(data):
    if not isinstance(data, (dict, list)):
        return False
    if isinstance(data, list):
        return True
    for key in ("running", "partial", "incomplete", "cache_incomplete", "cacheIncomplete", "refreshing"):
        if data.get(key):
            return False
    files = payload_items(data)
    for key in ("expected_count", "expectedCount", "total", "total_count", "totalCount"):
        if key not in data:
            continue
        expected = int_state_value(data.get(key), 0)
        if expected > len(files):
            return False
    return True


def enforce_auth_weekly_quota(state, dry_run=False, ts=None):
    result = auth_quota_result()
    ts = now_ts() if ts is None else int(ts)
    state = state if isinstance(state, dict) else {}
    state_maps = auth_quota_state_maps(state, ts)
    auto_disabled, _recent, reauth_auto_disabled = state_maps
    if not CLIPROXY_MANAGEMENT_TOKEN:
        log_auth_quota_result(result)
        return result
    seen_refs = set()

    try:
        auth_files_payload = management_request("auth-files")
        auth_files = payload_items(auth_files_payload)
        result["auth_files_count"] = len(auth_files)
        auth_files_reliable = auth_files_payload_reliable(auth_files_payload)
    except Exception:
        auth_files = []
        auth_files_reliable = False

    if auth_files_reliable:
        for item in auth_files:
            try:
                item = dict_or_empty(item)
                if not auth_file_is_codex(item):
                    continue
                result["codex_candidate_count"] += 1
                auth_index = auth_identity_index(item)
                name = auth_file_name(item)
                path = auth_file_path(name)
                if not auth_index or path is None or not path.exists():
                    continue
                ref = auth_quota_ref(path.name)
                seen_refs.add(ref)
                if auth_item_has_reauth_evidence(item):
                    process_auth_reauth_failed_account(state_maps, result, ref, path, auth_index, dry_run, ts)
                    continue
                try:
                    quota_remaining = auth_remaining_percents(auth_index)
                except AuthReauthRequired:
                    process_auth_reauth_failed_account(state_maps, result, ref, path, auth_index, dry_run, ts)
                    continue
                except Exception as exc:
                    if exception_has_reauth_evidence(exc):
                        process_auth_reauth_failed_account(state_maps, result, ref, path, auth_index, dry_run, ts)
                    else:
                        result["quota_check_failed_count"] += 1
                    continue
                if quota_remaining is None:
                    result["quota_check_failed_count"] += 1
                    continue
                process_auth_weekly_quota_account(state_maps, result, ref, path, auth_index, quota_remaining, dry_run, ts)
            except Exception:
                result["quota_check_failed_count"] += 1
                continue

    recovery_refs = set(auto_disabled.keys()) | set(reauth_auto_disabled.keys())
    for ref in sorted(recovery_refs):
        # Auto-disabled accounts hidden from /auth-files are still rechecked;
        # omission is partial inventory, not proof that quota recovered.
        try:
            if ref in seen_refs:
                continue
            marker = reauth_auto_disabled.get(ref)
            if not isinstance(marker, dict):
                marker = auto_disabled.get(ref)
            if not isinstance(marker, dict):
                continue
            auth_index = str(marker.get("auth_index") or "").strip()
            if not auth_index:
                continue
            path = find_auth_file_by_ref(ref)
            if path is None or not path.exists():
                continue
            try:
                quota_remaining = auth_remaining_percents(auth_index)
            except AuthReauthRequired:
                process_auth_reauth_failed_account(state_maps, result, ref, path, auth_index, dry_run, ts)
                continue
            except Exception as exc:
                if exception_has_reauth_evidence(exc):
                    process_auth_reauth_failed_account(state_maps, result, ref, path, auth_index, dry_run, ts)
                else:
                    result["quota_check_failed_count"] += 1
                continue
            if quota_remaining is None:
                result["quota_check_failed_count"] += 1
                continue
            process_auth_weekly_quota_account(state_maps, result, ref, path, auth_index, quota_remaining, dry_run, ts)
        except Exception:
            result["quota_check_failed_count"] += 1
            continue
    log_auth_quota_result(result)
    return result


def sync_quota_config_with_config_keys(cfg):
    if not CLIPROXY_CONFIG.exists():
        return

    config_text = CLIPROXY_CONFIG.read_text(encoding="utf-8")
    _, _, _, config_keys = parse_api_keys_block(config_text)

    existing_items = cfg.get("keys", [])
    new_items = []
    seen = set()
    added = 0

    # Keep all existing quota-managed items. Absence from config.yaml is not
    # manual-delete evidence: quota-disabled keys are intentionally removed from
    # config.yaml to block traffic, and disabled_by_quota state may be stale.
    for item in existing_items:
        key = item.get("key")
        if not key or key in seen:
            continue
        new_items.append(item)
        seen.add(key)

    # Still adopt newly-present config keys as unmanaged/unlimited quotas.
    for key in config_keys:
        if not key or key in seen:
            continue
        new_items.append({
            "name": default_key_name(key),
            "key": key,
            "daily_token_limit": None,
            "weekly_token_limit": None,
            "_weekly_token_limit_defaulted": True,
        })
        seen.add(key)
        added += 1

    if added or len(new_items) != len(existing_items):
        cfg["keys"] = new_items
        save_quota_config(cfg)
        log(f"quotas.json synced with config.yaml: added={added}, removed=0")


def today_window_utc(tz_name):
    tz = ZoneInfo(tz_name)
    now_local = datetime.now(tz)
    start_local = datetime.combine(now_local.date(), time.min, tzinfo=tz)
    end_local = datetime.combine(now_local.date() + timedelta(days=1), time.min, tzinfo=tz)
    start_utc = start_local.astimezone(timezone.utc)
    end_utc = end_local.astimezone(timezone.utc)
    return start_utc, end_utc


def week_window_utc(tz_name):
    tz = ZoneInfo(tz_name)
    now_local = datetime.now(tz)
    start_date = now_local.date() - timedelta(days=now_local.weekday())
    start_local = datetime.combine(start_date, time.min, tzinfo=tz)
    end_local = datetime.combine(start_date + timedelta(days=7), time.min, tzinfo=tz)
    start_utc = start_local.astimezone(timezone.utc)
    end_utc = end_local.astimezone(timezone.utc)
    return start_utc, end_utc


def get_tokens_by_key_for_window(keys, start_utc, end_utc):
    if not USAGE_DB.exists():
        raise FileNotFoundError(f"Usage Keeper DB not found: {USAGE_DB}")

    start_s = start_utc.strftime("%Y-%m-%d %H:%M:%S")
    end_s = end_utc.strftime("%Y-%m-%d %H:%M:%S")

    result = {}

    conn = sqlite3.connect(f"file:{USAGE_DB}?mode=ro", uri=True)
    try:
        for item in keys:
            key = item["key"]
            row = conn.execute(
                """
                SELECT
                  COALESCE(SUM(total_tokens), 0) AS total_tokens,
                  COUNT(*) AS requests
                FROM usage_events
                WHERE TRIM(api_group_key) = ?
                  AND datetime(timestamp) >= datetime(?)
                  AND datetime(timestamp) < datetime(?)
                """,
                (key, start_s, end_s),
            ).fetchone()

            result[key] = {
                "tokens": int(row[0] or 0),
                "requests": int(row[1] or 0),
            }
    finally:
        conn.close()

    return result


def get_usage_by_key(keys, tz_name):
    today_usage = get_tokens_by_key_for_window(keys, *today_window_utc(tz_name))
    weekly_usage = get_tokens_by_key_for_window(keys, *week_window_utc(tz_name))

    result = {}
    all_keys = set(today_usage) | set(weekly_usage)
    for key in all_keys:
        result[key] = {
            "today_tokens": today_usage.get(key, {}).get("tokens", 0),
            "requests_today": today_usage.get(key, {}).get("requests", 0),
            "week_tokens": weekly_usage.get(key, {}).get("tokens", 0),
            "requests_week": weekly_usage.get(key, {}).get("requests", 0),
        }

    return result

def parse_api_keys_block(config_text):
    lines = config_text.splitlines()
    start = None
    end = None

    for i, line in enumerate(lines):
        if line.startswith("api-keys:"):
            start = i
            break

    if start is None:
        return lines, None, None, []

    end = start + 1
    while end < len(lines):
        line = lines[end]

        if line.startswith("  ") or line.strip() == "":
            end += 1
            continue

        break

    existing_keys = []
    for line in lines[start + 1:end]:
        m = re.match(r'^\s*-\s*["\']?([^"\']+)["\']?\s*$', line.strip())
        if m:
            existing_keys.append(m.group(1).strip())

    return lines, start, end, existing_keys

def render_api_keys_block(keys):
    if not keys:
        return ["api-keys: []"]

    out = ["api-keys:"]
    for key in keys:
        out.append(f'  - "{key}"')
    return out

def write_config_preserve_inode(path, content):
    # Important: config.yaml is bind-mounted as a file into Docker.
    # Write in-place to preserve inode; do not atomic-rename over it.
    with path.open("r+", encoding="utf-8") as f:
        f.seek(0)
        f.write(content)
        f.truncate()
        f.flush()
        os.fsync(f.fileno())

def update_config_api_keys(active_limited_keys, all_limited_keys, dry_run):
    old_text = CLIPROXY_CONFIG.read_text(encoding="utf-8")
    lines, start, end, existing_keys = parse_api_keys_block(old_text)

    limited_set = set(all_limited_keys)

    # Keep all keys not managed by quota-enforcer as unlimited.
    unmanaged_keys = [k for k in existing_keys if k not in limited_set]

    # Add back active limited keys in quotas.json order.
    new_keys = unmanaged_keys + active_limited_keys

    # Deduplicate while preserving order.
    deduped = []
    seen = set()
    for key in new_keys:
        if key not in seen:
            deduped.append(key)
            seen.add(key)

    if existing_keys == deduped:
        log("config unchanged")
        return False

    new_block = render_api_keys_block(deduped)

    if start is None:
        new_lines = lines + [""] + new_block
    else:
        new_lines = lines[:start] + new_block + lines[end:]

    new_text = "\n".join(new_lines) + "\n"

    removed = [k for k in existing_keys if k not in deduped]
    added = [k for k in deduped if k not in existing_keys]

    log(f"config change needed: active_keys={len(deduped)}, added={len(added)}, removed={len(removed)}")

    if dry_run:
        log("dry_run=true, not writing config.yaml")
        return False

    write_config_preserve_inode(CLIPROXY_CONFIG, new_text)
    log("config.yaml updated; CLIProxyAPI file watcher should hot-reload")
    return True


def quota_status_text(prefix, today_used, daily_limit, week_used, weekly_limit):
    daily = "daily=unlimited" if daily_limit is None else f"daily={today_used}/{daily_limit}"
    weekly = "weekly=unlimited" if weekly_limit is None else f"weekly={week_used}/{weekly_limit}"
    return f"{prefix} {daily}, {weekly}"


def main():
    with LOCK_FILE.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

        args = sys.argv[1:]
        force_auth_quota_check = "--force-auth-quota-check" in args

        if "--migrate-auth-weekly-manual-disabled" in args:
            state = load_quota_state()
            run_auth_weekly_manual_disabled_migration(state, dry_run=False)
            save_quota_state(state)
            return 0

        cfg = load_quota_config()
        sync_quota_config_with_config_keys(cfg)
        limited_items = cfg["keys"]
        dry_run = cfg["dry_run"]
        tz_name = cfg["timezone"]

        if not limited_items:
            log("no limited keys configured; nothing to enforce")
            return 0

        usage = get_usage_by_key(limited_items, tz_name)

        active_limited_keys = []
        all_limited_keys = []
        disabled_limited_keys = []

        for item in limited_items:
            name = item["name"]
            key = item["key"]
            daily_limit = item["daily_token_limit"]
            weekly_limit = item["weekly_token_limit"]
            today_used = usage.get(key, {}).get("today_tokens", 0)
            week_used = usage.get(key, {}).get("week_tokens", 0)
            requests = usage.get(key, {}).get("requests_today", 0)

            all_limited_keys.append(key)

            over_daily = daily_limit is not None and today_used >= daily_limit
            over_weekly = weekly_limit is not None and week_used >= weekly_limit

            if daily_limit is None and weekly_limit is None:
                active = True
                status = "unlimited"
            elif not over_daily and not over_weekly:
                active = True
                status = quota_status_text("active", today_used, daily_limit, week_used, weekly_limit)
            else:
                active = False
                reason = "daily" if over_daily else "weekly"
                if over_daily and over_weekly:
                    reason = "daily+weekly"
                status = quota_status_text(f"disabled_by_{reason}", today_used, daily_limit, week_used, weekly_limit)

            log(f"{name}: {status}, requests_today={requests}")

            if active:
                active_limited_keys.append(key)
            else:
                disabled_limited_keys.append(key)

        if dry_run:
            log("dry_run=true, not modifying config.yaml api-keys or state.json")
        else:
            state = save_disabled_state(disabled_limited_keys)
            cpa_deleted_keys, cpa_evidence_reliable = load_cpa_deleted_keys_with_status()
            manual_deleted_keys = prune_cpa_deleted_quota_items(
                cfg,
                state,
                cpa_deleted_keys,
                dry_run=False,
                cpa_evidence_reliable=cpa_evidence_reliable,
            )
            if manual_deleted_keys:
                active_limited_keys = [key for key in active_limited_keys if key not in manual_deleted_keys]
                disabled_limited_keys = [key for key in disabled_limited_keys if key not in manual_deleted_keys]
            update_config_api_keys(active_limited_keys, all_limited_keys, dry_run)
            enforce_auth_quota_if_due(state, dry_run=False, force=force_auth_quota_check)
            save_quota_state(state)

        return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BlockingIOError:
        log("another quota_enforcer process is running; exiting")
        raise SystemExit(0)
    except Exception as e:
        log(f"ERROR: {e}")
        raise SystemExit(1)
