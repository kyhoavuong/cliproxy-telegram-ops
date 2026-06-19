"""Quota/config file helpers used by Telegram actions and usage snapshots."""

from __future__ import annotations
from contextlib import contextmanager
from typing import Any

import fcntl
import json
import os
import re
import secrets
import shutil
import sqlite3
import string
import threading
import time
from datetime import datetime, time as dtime, timedelta, timezone
from zoneinfo import ZoneInfo

from .settings import (
    ACTION_BACKUP_INCLUDE_USAGE_DB,
    ACTION_BACKUP_KEEP,
    ACTION_BACKUP_MAX_AGE_DAYS,
    BASE_DIR,
    CLIPROXY_CONFIG,
    QUOTA_CONFIG,
    QUOTA_STATE,
    STATE_FILE,
    USAGE_DB,
)
from .utils import fmt_limit, log, log_timing, mask_key, monotonic_ms, normalize_limit
from .storage import fsync_parent, load_json

QUOTA_RUNTIME_LOCK = BASE_DIR / "quota-enforcer" / "quota_enforcer.lock"


@contextmanager
def quota_runtime_lock():
    QUOTA_RUNTIME_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with QUOTA_RUNTIME_LOCK.open("w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)

def parse_api_keys_block(config_text):
    lines = config_text.splitlines()
    start = None
    end = None

    for i, line in enumerate(lines):
        if line.startswith("api-keys:"):
            start = i
            break

    if start is None:
        return []

    end = start + 1
    while end < len(lines):
        line = lines[end]
        if line.startswith("  ") or line.strip() == "":
            end += 1
            continue
        break

    existing_keys = []
    for line in lines[start + 1:end]:
        match = re.match(r'^\s*-\s*["\']?([^"\']+)["\']?\s*$', line.strip())
        if match:
            existing_keys.append(match.group(1).strip())

    return existing_keys

def render_api_keys_block(keys):
    if not keys:
        return ["api-keys: []"]
    lines = ["api-keys:"]
    for key in keys:
        lines.append(f'  - "{key}"')
    return lines

# config.yaml is bind-mounted into the cliproxy container as a single file.
# Rewrite it in place instead of using os.replace(), otherwise Docker can keep
# the old inode mounted and cliproxy may not see updated API keys.
def write_text_preserve_inode(path: Any, content: str) -> None:
    """Rewrite a bind-mounted text file without replacing its inode.
    
    This is required for cliproxy config hot updates because Docker may keep the old
    inode mounted if the file is swapped with os.replace()."""
    with path.open("r+", encoding="utf-8") as file:
        file.seek(0)
        file.write(content)
        file.truncate()
        file.flush()
        os.fsync(file.fileno())

def write_json_preserve_inode(path: Any, data: Any, *, sort_keys: bool = True) -> None:
    """Rewrite a bind-mounted JSON file without replacing its inode.

    quota-enforcer/quotas.json and quota-enforcer/state.json are host runtime
    files also written from telegram-alerts inside Docker. Existing installs
    should keep them host-user-owned; when they already exist, in-place writes
    preserve owner, mode, and inode instead of recreating them as the container
    user. Missing files are created directly without an atomic rename.
    """
    text = json.dumps(data, indent=2, sort_keys=sort_keys, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("r+", encoding="utf-8") as file:
            file.seek(0)
            file.write(text)
            file.truncate()
            file.flush()
            os.fsync(file.fileno())
    except FileNotFoundError:
        with path.open("x", encoding="utf-8") as file:
            file.write(text)
            file.flush()
            os.fsync(file.fileno())
        fsync_parent(path)

def write_config_api_keys(keys):
    old_text = CLIPROXY_CONFIG.read_text(encoding="utf-8")
    lines = old_text.splitlines()
    start = None
    end = None
    for i, line in enumerate(lines):
        if line.startswith("api-keys:"):
            start = i
            break

    if start is None:
        new_lines = lines + [""] + render_api_keys_block(keys)
    else:
        end = start + 1
        while end < len(lines):
            line = lines[end]
            if line.startswith("  ") or line.strip() == "":
                end += 1
                continue
            break
        new_lines = lines[:start] + render_api_keys_block(keys) + lines[end:]

    write_text_preserve_inode(CLIPROXY_CONFIG, "\n".join(new_lines) + "\n")

def slugify_name(name):
    slug = re.sub(r"[^a-z0-9_-]+", "-", str(name or "").strip().lower())
    slug = re.sub(r"-+", "-", slug).strip("-_")
    if not slug:
        raise ValueError("name must contain at least one letter or number")
    if len(slug) > 24:
        slug = slug[:24].strip("-_")
    return slug

def generate_api_key(name):
    suffix = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(17))
    return f"{slugify_name(name)}-{suffix}"

def display_key_for_api_key(key):
    key = str(key or "")
    if len(key) <= 9:
        return mask_key(key)
    return f"{key[:3]}*********{key[-6:]}"

def parse_limit(value, allow_default=False):
    raw = str(value or "").strip().lower().replace("_", "")
    if raw in {"none", "null", "unlimited", "off"}:
        return None
    if allow_default and raw in {"default", "auto"}:
        return "default"
    match = re.match(r"^(\d+(?:\.\d+)?)([kmb])?$", raw)
    if not match:
        raise ValueError(f"invalid limit '{value}', use integer, 4m, 500k, none, or default")
    amount = float(match.group(1))
    unit = match.group(2)
    multiplier = {"k": 1_000, "m": 1_000_000, "b": 1_000_000_000}.get(unit, 1)
    limit = int(amount * multiplier)
    if limit <= 0:
        raise ValueError("limit must be positive or none")
    return limit

def parse_key_create_answer(text):
    parts = [part.strip() for part in str(text or "").split(",")]
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError("Use: alias, name, 100M or alias, name for unlimited.")
    alias = parts[0]
    name = slugify_name(parts[1])
    daily = None
    if len(parts) > 2 and parts[2]:
        daily = parse_limit(parts[2])
    if len(parts) > 3 and any(part.strip() for part in parts[3:]):
        raise ValueError("Only enter alias, name, tokens/day.")
    return alias, name, daily

def format_limit_for_reply(limit):
    if limit == "default":
        return "default"
    return fmt_limit(limit)


def format_operator_quota_limit(limit):
    if limit == "default":
        return "default"
    if limit is None:
        return "unlimited"
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return fmt_limit(limit)
    if value >= 1_000_000_000:
        amount = f"{value / 1_000_000_000:.1f}".rstrip("0").rstrip(".")
        return f"{amount}B"
    for unit, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
        if value and value % unit == 0:
            return f"{value // unit}{suffix}"
    return fmt_limit(value)


def default_weekly_limit_for_daily(daily):
    if daily is None or daily == "default":
        return None
    return int(daily) * 4


def effective_weekly_limit(daily, weekly):
    if weekly == "default":
        return default_weekly_limit_for_daily(daily)
    return weekly


def format_effective_weekly_for_reply(daily, weekly):
    if weekly is None:
        return "unlimited"
    return format_operator_quota_limit(effective_weekly_limit(daily, weekly))

def preferred_quota_alias(key, item_name, cpa_alias):
    key = str(key or "")
    name = str(item_name or "").strip()
    alias = str(cpa_alias or "").strip()
    if name and alias and len(name) > len(alias) and name.lower().endswith(alias.lower()):
        return name
    return alias or name or key.split("-", 1)[0]


def format_weekly_behavior(daily, weekly):
    if weekly == "default":
        default_weekly = default_weekly_limit_for_daily(daily)
        if default_weekly is None:
            return "default = unlimited"
        return f"default = {format_limit_for_reply(default_weekly)}"
    return format_limit_for_reply(weekly)


def load_quotas_json():
    data = load_json(QUOTA_CONFIG, {}, strict=True)
    if not isinstance(data, dict):
        raise ValueError("quotas.json is not an object")
    data.setdefault("timezone", "Asia/Ho_Chi_Minh")
    data.setdefault("dry_run", False)
    data.setdefault("keys", [])
    if not isinstance(data["keys"], list):
        raise ValueError("quotas.json keys is not a list")
    return data

def save_quotas_json(data):
    write_json_preserve_inode(QUOTA_CONFIG, data, sort_keys=True)

def save_quota_state_json(data):
    write_json_preserve_inode(QUOTA_STATE, data, sort_keys=True)

# Weekly quota semantics are intentional: absent means the enforcer computes
# 4 * daily_token_limit, while explicit null disables the weekly cap.
def apply_weekly_limit(item, weekly):
    if weekly == "default":
        item.pop("weekly_token_limit", None)
    else:
        item["weekly_token_limit"] = weekly

def action_backup_root():
    return STATE_FILE.parent / "action-backups"

def prune_action_backups():
    root = action_backup_root()
    if not root.exists():
        return
    try:
        backups = []
        for child in root.iterdir():
            if child.is_dir() and not child.is_symlink():
                backups.append((child.stat().st_mtime, child))
        backups.sort(key=lambda item: item[0], reverse=True)
        cutoff = time.time() - max(1, ACTION_BACKUP_MAX_AGE_DAYS) * 86400
        keep = max(1, ACTION_BACKUP_KEEP)
        for index, (mtime, child) in enumerate(backups):
            if index >= keep or mtime < cutoff:
                shutil.rmtree(child)
                log(f"pruned action backup {child}")
    except Exception as exc:
        log(f"failed to prune action backups: {exc}")

def backup_action_files(action_type: str, include_usage_db: bool = False, cpa_api_keys: list[str] | None = None) -> Any:
    """Create a short-lived rollback bundle before Telegram-triggered mutations.
    
    Always backs up mutable config/quota files when present; optionally includes CPA
    rows or a full Usage Keeper DB copy for key-create rollback."""
    started = monotonic_ms()
    backup_dir = action_backup_root() / f"{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}-{threading.get_ident()}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for source in (CLIPROXY_CONFIG, QUOTA_CONFIG, QUOTA_STATE):
        if source.exists():
            shutil.copy2(source, backup_dir / f"{action_type}-{source.name}")
            copied += 1
    db_ms = None
    db_status = "skipped"
    cpa_rows = 0
    cpa_keys = [str(key or "").strip() for key in (cpa_api_keys or []) if str(key or "").strip()]
    if cpa_keys and USAGE_DB.exists():
        db_started = monotonic_ms()
        placeholders = ",".join("?" for _ in cpa_keys)
        con = sqlite3.connect(f"file:{USAGE_DB}?mode=ro", uri=True, timeout=8)
        con.row_factory = sqlite3.Row
        try:
            rows = [dict(row) for row in con.execute(
                f"SELECT * FROM cpa_api_keys WHERE api_key IN ({placeholders})",
                cpa_keys,
            )]
        finally:
            con.close()
        (backup_dir / f"{action_type}-cpa_api_keys.json").write_text(
            json.dumps({"api_keys": cpa_keys, "rows": rows}, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        cpa_rows = len(rows)
        db_ms = monotonic_ms() - db_started
        db_status = "cpa_rows"
    if include_usage_db and ACTION_BACKUP_INCLUDE_USAGE_DB and USAGE_DB.exists():
        db_started = monotonic_ms()
        source = sqlite3.connect(f"file:{USAGE_DB}?mode=ro", uri=True, timeout=8)
        try:
            dest = sqlite3.connect(backup_dir / f"{action_type}-app.db", timeout=8)
            try:
                source.backup(dest)
            finally:
                dest.close()
        finally:
            source.close()
        db_ms = monotonic_ms() - db_started
        db_status = "full_db"
    prune_started = monotonic_ms()
    prune_action_backups()
    prune_ms = monotonic_ms() - prune_started
    log_timing(
        "backup_action_files",
        started,
        action=action_type,
        files=copied,
        db=db_status,
        db_ms=db_ms,
        cpa_rows=cpa_rows,
        prune_ms=prune_ms,
    )
    return backup_dir

def cpa_now():
    try:
        tz = ZoneInfo("Asia/Ho_Chi_Minh")
    except Exception:
        tz = timezone(timedelta(hours=7))
    return datetime.now(tz).isoformat()

def quota_managed_aliases():
    aliases = {}
    data = load_quotas_json()
    for item in data.get("keys", []):
        if not isinstance(item, dict):
            continue
        key = str(item.get("key", "")).strip()
        if not key:
            continue
        aliases[key] = str(item.get("name") or "").strip()
    return aliases


def quota_disabled_keys():
    state = load_json(QUOTA_STATE, {})
    return quota_state_key_set(state, "disabled_by_quota")


def quota_state_key_set(state, field):
    keys = set()
    if not isinstance(state, dict):
        return keys
    values = state.get(field)
    if isinstance(values, dict):
        source = values.keys()
    elif isinstance(values, list):
        source = values
    else:
        source = []
    for item in source:
        if isinstance(item, str):
            key = item.strip()
        elif isinstance(item, dict):
            key = str(item.get("key") or "").strip()
        else:
            key = ""
        if key:
            keys.add(key)
    return keys


def manually_disabled_keys():
    state = load_json(QUOTA_STATE, {})
    return quota_state_key_set(state, "manually_disabled_keys")


def active_manually_disabled_keys(keys=None):
    if keys is None:
        keys = manually_disabled_keys()
    else:
        keys = {str(key or "").strip() for key in keys if str(key or "").strip()}
    if not keys:
        return set()
    try:
        config_keys = set(parse_api_keys_block(CLIPROXY_CONFIG.read_text(encoding="utf-8"))) if CLIPROXY_CONFIG.exists() else set()
    except Exception:
        return keys
    return {key for key in keys if key not in config_keys}


def quota_disabled_cpa_tombstone_keys():
    state = load_json(QUOTA_STATE, {})
    tombstones = state.get("cpa_deleted_while_quota_disabled", [])
    keys = set()
    if isinstance(tombstones, dict):
        source = tombstones.keys()
    elif isinstance(tombstones, list):
        source = tombstones
    else:
        source = []
    for item in source:
        if isinstance(item, str):
            key = item.strip()
        elif isinstance(item, dict):
            key = str(item.get("key") or "").strip()
        else:
            key = str(item or "").strip()
        if key:
            keys.add(key)
    return keys


def load_cpa_alias_map():
    aliases = {}
    all_db_aliases = {}
    deleted_db_keys = set()
    if USAGE_DB.exists():
        con = sqlite3.connect(f"file:{USAGE_DB}?mode=ro", uri=True, timeout=4)
        try:
            for api_key, key_alias, is_deleted in con.execute(
                """
                SELECT api_key, key_alias, COALESCE(is_deleted, 0)
                FROM cpa_api_keys
                WHERE COALESCE(api_key, '') != ''
"""
            ):
                key = str(api_key or "").strip()
                if not key:
                    continue
                alias = str(key_alias or "").strip()
                all_db_aliases[key] = alias
                if is_deleted:
                    deleted_db_keys.add(key)
                else:
                    aliases[key] = alias
        finally:
            con.close()

    try:
        quota_aliases = quota_managed_aliases()
    except Exception as exc:
        log(f"failed to load quota-managed CPA aliases: {exc}")
        quota_aliases = {}

    for key, quota_alias in quota_aliases.items():
        if key in deleted_db_keys:
            continue
        aliases.setdefault(key, all_db_aliases.get(key) or quota_alias or key[:8])
    return aliases


def sync_cpa_registry_from_quotas():
    if not USAGE_DB.exists():
        return 0
    quota_aliases = quota_managed_aliases()
    disabled_by_quota = quota_disabled_keys()
    manual_disabled_markers = manually_disabled_keys()
    protected_tombstone_keys = quota_disabled_cpa_tombstone_keys()
    proxy_config_keys = set()
    proxy_config_available = False
    try:
        if CLIPROXY_CONFIG.exists():
            config_text = CLIPROXY_CONFIG.read_text(encoding="utf-8")
            if any(line.startswith("api-keys:") for line in config_text.splitlines()):
                proxy_config_keys = set(parse_api_keys_block(config_text))
                proxy_config_available = True
            else:
                log("skipping CPA registry soft-delete sync: proxy config api-keys block unavailable")
        else:
            log("skipping CPA registry soft-delete sync: proxy config unavailable")
    except Exception as exc:
        log(f"skipping CPA registry soft-delete sync: proxy config unavailable: {exc.__class__.__name__}")

    if proxy_config_available:
        manual_disabled = {key for key in manual_disabled_markers if key not in proxy_config_keys}
    else:
        manual_disabled = manual_disabled_markers

    now = cpa_now()
    changed = 0
    con = sqlite3.connect(USAGE_DB, timeout=8)
    try:
        for key, quota_alias in quota_aliases.items():
            display_key = display_key_for_api_key(key)
            row = con.execute(
                """
                SELECT id, key_alias, COALESCE(display_key, ''), COALESCE(is_deleted, 0)
                FROM cpa_api_keys
                WHERE api_key = ?
                """,
                (key,),
            ).fetchone()
            if row:
                row_is_deleted = bool(row[3])
                if row_is_deleted and key in manual_disabled:
                    continue
                protected_deleted_key = (
                    key in disabled_by_quota
                    or key in protected_tombstone_keys
                    or (proxy_config_available and key in proxy_config_keys)
                )
                if row_is_deleted and not protected_deleted_key:
                    continue
                alias = quota_alias or key[:8]
                if not row_is_deleted:
                    alias = str(row[1] or "").strip() or alias
                cursor = con.execute(
                    """
                    UPDATE cpa_api_keys
                    SET display_key = ?,
                        key_alias = ?,
                        is_deleted = 0,
                        last_synced_at = ?,
                        updated_at = ?
                    WHERE api_key = ?
                      AND (
                        COALESCE(display_key, '') != ?
                        OR COALESCE(key_alias, '') != ?
                        OR COALESCE(is_deleted, 0) != 0
                      )
                    """,
                    (display_key, alias, now, now, key, display_key, alias),
                )
                changed += max(0, cursor.rowcount or 0)
            else:
                if key in manual_disabled:
                    continue
                alias = quota_alias or key[:8]
                con.execute(
                    """
                    INSERT INTO cpa_api_keys
                      (api_key, display_key, key_alias, is_deleted, last_synced_at, created_at, updated_at)
                    VALUES (?, ?, ?, 0, ?, ?, ?)
                    """,
                    (key, display_key, alias, now, now, now),
                )
                changed += 1

        if proxy_config_available:
            active_rows = con.execute(
                """
                SELECT api_key
                FROM cpa_api_keys
                WHERE COALESCE(api_key, '') != ''
                  AND COALESCE(is_deleted, 0) = 0
                """
            ).fetchall()
            for row in active_rows:
                key = str(row[0] or "").strip()
                if not key or key in quota_aliases or key in proxy_config_keys:
                    continue
                if key in disabled_by_quota or key in manual_disabled:
                    continue
                cursor = con.execute(
                    """
                    UPDATE cpa_api_keys
                    SET is_deleted = 1,
                        last_synced_at = ?,
                        updated_at = ?
                    WHERE api_key = ?
                      AND COALESCE(is_deleted, 0) = 0
                    """,
                    (now, now, key),
                )
                changed += max(0, cursor.rowcount or 0)
        con.commit()
    finally:
        con.close()
    return changed

def upsert_cpa_api_key_alias(api_key, alias):
    now = cpa_now()
    display_key = display_key_for_api_key(api_key)
    con = sqlite3.connect(USAGE_DB, timeout=8)
    try:
        row = con.execute("SELECT id FROM cpa_api_keys WHERE api_key = ?", (api_key,)).fetchone()
        if row:
            con.execute(
                """
                UPDATE cpa_api_keys
                SET display_key = ?,
                    key_alias = ?,
                    is_deleted = 0,
                    last_synced_at = ?,
                    updated_at = ?
                WHERE api_key = ?
                """,
                (display_key, alias, now, now, api_key),
            )
        else:
            con.execute(
                """
                INSERT INTO cpa_api_keys
                  (api_key, display_key, key_alias, is_deleted, last_synced_at, created_at, updated_at)
                VALUES (?, ?, ?, 0, ?, ?, ?)
                """,
                (api_key, display_key, alias, now, now, now),
            )
        con.commit()
    finally:
        con.close()


def soft_delete_cpa_api_key(api_key):
    key = str(api_key or "").strip()
    if not key or not USAGE_DB.exists():
        return 0
    now = cpa_now()
    con = sqlite3.connect(USAGE_DB, timeout=8)
    try:
        cursor = con.execute(
            """
            UPDATE cpa_api_keys
            SET is_deleted = 1,
                last_synced_at = ?,
                updated_at = ?
            WHERE api_key = ?
              AND COALESCE(is_deleted, 0) = 0
            """,
            (now, now, key),
        )
        con.commit()
        return max(0, cursor.rowcount or 0)
    finally:
        con.close()


def describe_quota_match(item):
    key = str(item.get("key", ""))
    alias = load_cpa_alias_map().get(key) or item.get("name") or "unknown"
    return f"{alias} ({mask_key(key)})"

def key_accounts_for_picker():
    accounts = []
    seen = set()
    for key, alias in load_cpa_alias_map().items():
        key = str(key or "").strip()
        if not key or key in seen:
            continue
        accounts.append({"key": key, "alias": str(alias or key[:8]).strip() or key[:8]})
        seen.add(key)
    accounts.sort(key=lambda item: item["alias"].lower())
    return accounts

def quota_accounts_for_picker():
    data = load_quotas_json()
    alias_by_key = load_cpa_alias_map()
    accounts = []
    for item in data.get("keys", []):
        key = str(item.get("key", "")).strip()
        if not key:
            continue
        alias = preferred_quota_alias(key, item.get("name"), alias_by_key.get(key))
        daily = normalize_limit(item.get("daily_token_limit"))
        weekly = normalize_limit(item.get("weekly_token_limit")) if "weekly_token_limit" in item else "default"
        accounts.append({"key": key, "alias": alias, "daily": daily, "weekly": weekly})
    accounts.sort(key=lambda item: item["alias"].lower())
    return accounts

def quota_account_by_key(key):
    target = str(key or "")
    for account in quota_accounts_for_picker():
        if account["key"] == target:
            return account
    return None

def short_button_label(text, limit=28):
    text = str(text or "").strip() or "Unnamed"
    if len(text) <= limit:
        return text
    return text[:limit - 1].rstrip() + "…"

def quota_update_summary(account, daily, weekly="default"):
    return "\n".join([
        "Pending quota update",
        "",
        f"User: {account['alias']}",
        f"Daily quota: {format_operator_quota_limit(account.get('daily'))} -> {format_operator_quota_limit(daily)}",
        f"Weekly quota: {format_effective_weekly_for_reply(account.get('daily'), account.get('weekly'))} -> {format_effective_weekly_for_reply(daily, weekly)}",
    ])

def load_quota_data() -> tuple[str, list[dict[str, Any]], set[str], set[str]]:
    """Load normalized quota rows with disabled and active proxy membership.
    
    Absent weekly_token_limit becomes 4x daily, while explicit null remains a disabled
    weekly cap in the returned rows."""
    cfg = load_json(QUOTA_CONFIG, {}, strict=True)
    state = load_json(QUOTA_STATE, {})
    timezone_name = cfg.get("timezone", "Asia/Ho_Chi_Minh")
    items = []
    for raw in cfg.get("keys", []):
        if not isinstance(raw, dict):
            continue
        key = str(raw.get("key", "")).strip()
        if not key:
            continue
        daily_limit = normalize_limit(raw.get("daily_token_limit"))
        if "weekly_token_limit" in raw:
            weekly_limit = normalize_limit(raw.get("weekly_token_limit"))
        else:
            weekly_limit = daily_limit * 4 if daily_limit is not None else None
        items.append({
            "name": str(raw.get("name") or key[-8:]),
            "key": key,
            "daily_token_limit": daily_limit,
            "weekly_token_limit": weekly_limit,
        })

    config_keys = set()
    if CLIPROXY_CONFIG.exists():
        config_keys = set(parse_api_keys_block(CLIPROXY_CONFIG.read_text(encoding="utf-8")))
    disabled = set()
    disabled = quota_state_key_set(state, "disabled_by_quota")
    manual_disabled = quota_state_key_set(state, "manually_disabled_keys")
    for item in items:
        item["manually_disabled"] = item["key"] in manual_disabled and item["key"] not in config_keys

    return timezone_name, items, disabled, config_keys

def window_utc(tz_name, kind):
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone(timedelta(hours=7))

    now_local = datetime.now(tz)
    if kind == "daily":
        start_local = datetime.combine(now_local.date(), dtime.min, tzinfo=tz)
        end_local = datetime.combine(now_local.date() + timedelta(days=1), dtime.min, tzinfo=tz)
    else:
        start_date = now_local.date() - timedelta(days=now_local.weekday())
        start_local = datetime.combine(start_date, dtime.min, tzinfo=tz)
        end_local = datetime.combine(start_date + timedelta(days=7), dtime.min, tzinfo=tz)

    return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)

def load_cpa_key_records():
    records = {}
    if not USAGE_DB.exists():
        return records
    con = sqlite3.connect(f"file:{USAGE_DB}?mode=ro", uri=True, timeout=4)
    try:
        for api_key, key_alias, is_deleted in con.execute(
            """
            SELECT api_key, key_alias, COALESCE(is_deleted, 0)
            FROM cpa_api_keys
            WHERE COALESCE(api_key, '') != ''
            """
        ):
            key = str(api_key or "").strip()
            if not key:
                continue
            records[key] = {
                "alias": str(key_alias or "").strip(),
                "cpa_deleted": bool(is_deleted),
            }
    finally:
        con.close()
    return records
