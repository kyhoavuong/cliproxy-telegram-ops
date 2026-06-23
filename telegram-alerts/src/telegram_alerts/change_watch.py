"""Logical change detector for shared keys, quotas, and proxy auth accounts."""

from __future__ import annotations
from typing import Any
from .contracts import ChangeEvent

import hashlib
import json
import re
from pathlib import Path

from .settings import (
    AUTH_DIR,
    CHANGE_NOTIFICATION_DEBOUNCE_SECONDS,
    CHANGE_REMOVAL_DEBOUNCE_SECONDS,
    CHANGE_WATCH_INTERVAL_SECONDS,
    CLIPROXY_CONFIG,
    QUOTA_STATE,
)
from .utils import key_ref, log, mask_key, normalize_limit, now_ts, short_code
from .storage import load_json
from .provider_labels import infer_provider_from_values, provider_display_label
from .quota_config import format_effective_weekly_for_reply, format_limit_for_reply, format_operator_quota_limit, load_cpa_key_records, load_quotas_json, parse_api_keys_block, preferred_quota_alias
from .telegram_client import send_telegram

# Backend/source labels are internal evidence only. Operators receive logical
# key/account notifications, not one message per storage backend.
CHANGE_SOURCE_ORDER = ("proxy config", "web management", "quota config", "auth files")
ACTION_CHANGE_SUPPRESSION_SECONDS = 2 * 60
REMOVAL_HOLDBACK_SECONDS = 12
RECENT_LOGICAL_REMOVAL_SECONDS = 2 * 60
KNOWN_ACTIVE_KEY_TTL_SECONDS = 24 * 60 * 60
QUOTA_DISABLED_CPA_TOMBSTONE_TTL_SECONDS = 10 * 60
DETAILED_CHANGE_NOTIFICATION_LIMIT = 20
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
SECRET_LABEL_RE = re.compile(r"(?i)\b(bearer|api[_ -]?key|cookie|management[_ -]?token|access[_ -]?token|refresh[_ -]?token|token|secret)\b")


def load_quota_state_key_set(name):
    values = set()
    try:
        state = load_json(QUOTA_STATE, {})
        for item in state.get(name, []):
            if isinstance(item, str):
                key = item.strip()
            elif isinstance(item, dict):
                key = str(item.get("key") or "").strip()
            else:
                key = ""
            if key:
                values.add(key)
    except Exception as exc:
        log(f"failed to load quota state {name} for change watch: {exc}")
    return values


def load_quota_disabled_keys():
    return load_quota_state_key_set("disabled_by_quota")


def load_cpa_deleted_while_quota_disabled_keys():
    return load_quota_state_key_set("cpa_deleted_while_quota_disabled")


def load_manually_disabled_keys():
    return load_quota_state_key_set("manually_disabled_keys")


def load_auth_account_records():
    records = {}
    if not AUTH_DIR.exists():
        return records
    for path in sorted(AUTH_DIR.glob("*.json")):
        key = f"auth:{path.name}"
        record = {
            "kind": "auth_account",
            "file_name": path.name,
            "alias": path.stem,
            "type": "",
            "disabled": False,
        }
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                email = str(data.get("email") or "").strip()
                record["alias"] = email or path.stem
                record["type"] = str(data.get("type") or "").strip()
                record["disabled"] = bool(data.get("disabled"))
        except Exception as exc:
            record["read_error"] = str(exc)
        records[key] = record
    return records


def change_watch_snapshot() -> dict[str, dict[str, Any]]:
    """Read CPA, auth-file, quota, quota-state, and proxy-config evidence into one snapshot.
    
    The returned records are internal change-watch evidence; later formatting decides
    which logical details are safe to show operators."""
    records = load_cpa_key_records()
    for key, record in load_auth_account_records().items():
        records[key] = record
    disabled_keys = load_quota_disabled_keys()
    manually_disabled_keys = load_manually_disabled_keys()
    protected_cpa_tombstones = load_cpa_deleted_while_quota_disabled_keys()
    try:
        quotas = load_quotas_json()
        for item in quotas.get("keys", []):
            key = str(item.get("key", "")).strip()
            if not key:
                continue
            record = records.setdefault(key, {"alias": "", "cpa_deleted": False})
            record["alias"] = preferred_quota_alias(key, item.get("name"), record.get("alias"))
            record.setdefault("cpa_deleted", False)
            record["in_quota"] = True
            record["daily"] = normalize_limit(item.get("daily_token_limit"))
            record["weekly"] = normalize_limit(item.get("weekly_token_limit")) if "weekly_token_limit" in item else "default"
    except Exception as exc:
        records["__quota_error__"] = {"error": str(exc)}

    try:
        proxy_keys = set(parse_api_keys_block(CLIPROXY_CONFIG.read_text(encoding="utf-8"))) if CLIPROXY_CONFIG.exists() else set()
    except Exception as exc:
        proxy_keys = set()
        records["__config_error__"] = {"error": str(exc)}
    for key in proxy_keys:
        records.setdefault(key, {"alias": "", "cpa_deleted": False})["in_proxy_config"] = True

    for key, record in list(records.items()):
        if key.startswith("__"):
            continue
        record.setdefault("alias", "")
        record.setdefault("cpa_deleted", False)
        record.setdefault("in_quota", False)
        record.setdefault("in_proxy_config", False)
        record["disabled_by_quota"] = key in disabled_keys
        record["manual_marker"] = key in manually_disabled_keys
        record["manually_disabled"] = record["manual_marker"] and key not in proxy_keys
        record["cpa_deleted_while_quota_disabled"] = key in protected_cpa_tombstones
        record.setdefault("daily", None)
        record.setdefault("weekly", "default")
    return records


def change_watch_fingerprint(snapshot):
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def is_change_event_suppressed(state, event):
    """Suppress internal-noise transitions while preserving external changes."""
    return is_auth_status_only_transition_suppressed(event)


def matching_recent_bot_action(state: dict[str, Any] | None, event: ChangeEvent, ts: int) -> bool:
    """Return true when a real snapshot event matches a recent bot-confirmed action."""
    expected_action = {
        "key_added": "key_create",
        "quota_changed": "quota_set",
        "key_manually_disabled": "key_disable",
        "key_manually_enabled": "key_enable",
        "key_removed": "key_delete",
    }.get(logical_type_for_event(event))
    if not expected_action or not isinstance(state, dict):
        return False
    event_key = str((event or {}).get("key") or "").strip()
    if not event_key:
        return False
    audit = state.get("action_audit")
    if not isinstance(audit, list):
        return False
    for item in reversed(audit):
        if not isinstance(item, dict):
            continue
        if item.get("type") != expected_action:
            continue
        item_key = str(item.get("key") or "").strip()
        item_key_ref = str(item.get("key_ref") or "").strip()
        if item_key != event_key and item_key_ref != key_ref(event_key):
            continue
        try:
            action_at = int(item["at"])
        except (KeyError, TypeError, ValueError):
            try:
                suppress_until = int(item.get("suppress_change_until"))
            except (TypeError, ValueError):
                continue
            if ts <= suppress_until:
                return True
            continue
        if 0 <= ts - action_at <= ACTION_CHANGE_SUPPRESSION_SECONDS:
            return True
    return False


def auth_status_transition(event):
    changes = [str(change or "").strip() for change in (event or {}).get("changes") or [] if str(change or "").strip()]
    if changes == ["Status: enabled -> disabled"]:
        return "disabled"
    if changes == ["Status: disabled -> enabled"]:
        return "enabled"
    return ""


def is_auth_status_only_transition_suppressed(event):
    # Current contract: auth status-only flips are operational noise, whether
    # quota-driven or manual; alias/type/read-error changes still notify.
    if logical_type_for_event(event) != "auth_account_changed":
        return False
    return bool(auth_status_transition(event))




def change_watch_label(key, record):
    return str(record.get("alias") or "").strip() or str(key)[:8]


def safe_email_from_account_label(value):
    text = str(value or "").strip()
    if not text:
        return ""
    candidates = [text]
    if text.lower().startswith("auth:"):
        candidates.insert(0, text.split(":", 1)[1])
    if text.lower().endswith(".json"):
        candidates.insert(0, text[:-5])
    for candidate in candidates:
        match = EMAIL_RE.search(candidate)
        if match:
            return match.group(0)
    return ""


def is_codex_account_label(value):
    email = safe_email_from_account_label(value)
    return bool(email and email.split("@", 1)[0].lower().startswith("codex-"))


def preferred_proxy_account_email(values):
    emails = []
    for value in values:
        email = safe_email_from_account_label(value)
        if email:
            emails.append(email)
    for email in emails:
        if is_codex_account_label(email):
            return email
    return emails[0] if emails else ""


def safe_proxy_account_label(event):
    event = event or {}
    candidates = [
        event.get("account"),
        event.get("key"),
    ]
    email = preferred_proxy_account_email(candidates)
    if email:
        return email

    account = str(event.get("account") or "unknown").strip() or "unknown"
    if account.lower().startswith("auth:"):
        account = account.split(":", 1)[1]
    if account.lower().endswith(".json") or "/" in account or "\\" in account:
        account = Path(account).stem if "/" in account or "\\" in account else account[:-5]
    if SECRET_LABEL_RE.search(account) or re.match(r"(?i)^sk-[A-Za-z0-9_-]{8,}$", account) or len(account) > 80:
        return mask_key(account)
    return account


def proxy_account_provider_label(event):
    event = event or {}
    evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
    account_type = str(evidence.get("account_type") or "").strip()
    change_type = ""
    for change in event.get("changes") or []:
        text = str(change or "").strip()
        if text.lower().startswith("type: "):
            change_type = text.split(":", 1)[1].strip()
            break
    provider = infer_provider_from_values(account_type, change_type, event.get("account"), event.get("key"))
    if not provider and (is_codex_account_label(event.get("account")) or is_codex_account_label(event.get("key"))):
        provider = "codex"
    return provider_display_label(provider, fallback="Proxy")


def format_change_value(value):
    return format_limit_for_reply(value)


def quota_change_lines(old, new):
    changes = []
    if old.get("daily") != new.get("daily"):
        changes.append(f"Daily: {format_change_value(old.get('daily'))} -> {format_change_value(new.get('daily'))}")
    if old.get("weekly") != new.get("weekly"):
        changes.append(f"Weekly: {format_change_value(old.get('weekly'))} -> {format_change_value(new.get('weekly'))}")
    return changes


def ordered_sources(sources):
    seen = []
    for source in sources or []:
        source = str(source or "").strip()
        if source and source not in seen:
            seen.append(source)
    return sorted(seen, key=lambda source: CHANGE_SOURCE_ORDER.index(source) if source in CHANGE_SOURCE_ORDER else len(CHANGE_SOURCE_ORDER))


def source_change_line(prefix, sources):
    values = ordered_sources(sources)
    if not values:
        return ""
    return f"{prefix}{', '.join(values)}"


def is_auth_record(record):
    return isinstance(record, dict) and record.get("kind") == "auth_account"


def has_auth_records(snapshot):
    return any(is_auth_record(record) for record in (snapshot or {}).values())


def strip_auth_records(snapshot):
    if not isinstance(snapshot, dict):
        return {}
    return {key: value for key, value in snapshot.items() if not is_auth_record(value)}


def auth_account_status(record):
    if record.get("read_error"):
        return "unreadable"
    if record.get("disabled"):
        return "disabled"
    return "enabled"


# Quota enforcer removes/restores keys automatically when limits are crossed or
# reset. Those transitions are intentionally silent; manual deletes still notify
# because alias/CPA/quota membership changes fail this narrow predicate.
def is_quota_enforcer_only_change(old, new):
    stable_fields = ("alias", "cpa_deleted", "in_quota", "daily", "weekly", "manually_disabled")
    if any(old.get(field) != new.get(field) for field in stable_fields):
        return False
    proxy_changed = old.get("in_proxy_config") != new.get("in_proxy_config")
    disabled_changed = old.get("disabled_by_quota") != new.get("disabled_by_quota")
    if not (proxy_changed or disabled_changed):
        return False
    return bool(old.get("disabled_by_quota") or new.get("disabled_by_quota"))


def manual_key_state_transition(old, new):
    stable_fields = ("alias", "cpa_deleted", "in_quota", "daily", "weekly", "disabled_by_quota")
    if any(old.get(field) != new.get(field) for field in stable_fields):
        return ""
    old_manually_disabled = api_key_manually_disabled(old)
    new_manually_disabled = api_key_manually_disabled(new)
    manual_changed = old_manually_disabled != new_manually_disabled
    if not manual_changed:
        return ""
    if new_manually_disabled:
        return "disabled"
    if new.get("manual_marker"):
        return ""
    return "enabled"


# Logical key presence is stricter than "seen in any backend". CPA/web rows and
# quota/config writes can lag each other, so source-only tails must not create
# add/remove oscillations after one real key lifecycle.
def api_key_presence_state(record):
    if record.get("in_proxy_config") and record.get("in_quota") and not record.get("cpa_deleted"):
        return "present"
    if record.get("in_proxy_config") or record.get("in_quota") or not record.get("cpa_deleted"):
        return "tail"
    return "removed"


def api_key_logically_present(record):
    return api_key_presence_state(record) == "present"


def api_key_quota_managed_tail(record):
    return (
        isinstance(record, dict)
        and bool(record.get("in_quota"))
        and not bool(record.get("cpa_deleted"))
        and not bool(record.get("in_proxy_config"))
    )


def api_key_quota_disabled_cpa_tombstone(record):
    return (
        isinstance(record, dict)
        and bool(record.get("cpa_deleted"))
        and bool(record.get("in_quota"))
        and bool(record.get("disabled_by_quota"))
    )


def api_key_manually_disabled(record):
    return isinstance(record, dict) and bool(record.get("manually_disabled")) and not bool(record.get("in_proxy_config"))


def api_key_protected_quota_disabled_tombstone(record):
    return isinstance(record, dict) and (
        bool(record.get("cpa_deleted_while_quota_disabled"))
        or api_key_quota_disabled_cpa_tombstone(record)
    )


def api_key_active_with_protected_quota_tombstone(record):
    return (
        isinstance(record, dict)
        and bool(record.get("cpa_deleted_while_quota_disabled"))
        and bool(record.get("in_quota"))
        and bool(record.get("in_proxy_config"))
        and not bool(record.get("disabled_by_quota"))
    )


def api_key_quota_enforcer_silent_state(record):
    return isinstance(record, dict) and (
        bool(record.get("disabled_by_quota"))
        or api_key_manually_disabled(record)
        or bool(record.get("cpa_deleted_while_quota_disabled"))
        or api_key_quota_managed_tail(record)
    )


def known_active_keys(watch):
    known = watch.get("known_active_keys")
    if not isinstance(known, dict):
        known = {}
        watch["known_active_keys"] = known
    return known


def prune_known_active_keys(watch, ts):
    known = known_active_keys(watch)
    cutoff = int(ts) - KNOWN_ACTIVE_KEY_TTL_SECONDS
    for key, item in list(known.items()):
        if not isinstance(item, dict) or int(item.get("last_seen", item.get("last_present", 0)) or 0) < cutoff:
            known.pop(key, None)
    return known


def remember_known_active_key(watch, key, account, ts):
    key = str(key or "").strip()
    if not key:
        return
    known = known_active_keys(watch)
    known[key] = {
        "account": str(account or key[:8]).strip() or key[:8],
        "last_seen": int(ts),
        "last_present": int(ts),
    }


def remember_known_active_snapshot(watch, snapshot, ts):
    prune_known_active_keys(watch, ts)
    for key, record in (snapshot or {}).items():
        if str(key).startswith("__") or is_auth_record(record):
            continue
        if isinstance(record, dict) and api_key_logically_present(record):
            remember_known_active_key(watch, key, change_watch_label(key, record), ts)


def quota_disabled_cpa_tombstones(watch):
    tombstones = watch.get("quota_disabled_cpa_tombstones")
    if not isinstance(tombstones, dict):
        tombstones = {}
        watch["quota_disabled_cpa_tombstones"] = tombstones
    return tombstones


def prune_quota_disabled_cpa_tombstones(watch, ts):
    tombstones = quota_disabled_cpa_tombstones(watch)
    for key, item in list(tombstones.items()):
        if not isinstance(item, dict) or int(item.get("expires_at", 0) or 0) <= int(ts):
            tombstones.pop(key, None)
    return tombstones


def remember_quota_disabled_cpa_tombstone(watch, key, account, ts):
    key = str(key or "").strip()
    if not key:
        return
    tombstones = quota_disabled_cpa_tombstones(watch)
    tombstones[key] = {
        "account": str(account or key[:8]).strip() or key[:8],
        "last_seen": int(ts),
        "expires_at": int(ts) + QUOTA_DISABLED_CPA_TOMBSTONE_TTL_SECONDS,
    }


def remember_quota_disabled_cpa_tombstone_snapshot(watch, snapshot, ts):
    prune_quota_disabled_cpa_tombstones(watch, ts)
    for key, record in (snapshot or {}).items():
        if str(key).startswith("__") or is_auth_record(record):
            continue
        if api_key_quota_disabled_cpa_tombstone(record):
            remember_quota_disabled_cpa_tombstone(watch, key, change_watch_label(key, record), ts)


def recently_saw_quota_disabled_cpa_tombstone(watch, key, ts):
    key = str(key or "").strip()
    if not key:
        return False
    return key in prune_quota_disabled_cpa_tombstones(watch, ts)


def pending_has_logical_event(watch, key, logical_type):
    target_key = str(key or "").strip()
    pending = watch.get("pending")
    if not target_key or not isinstance(pending, dict):
        return False
    for item in pending.values():
        if isinstance(item, dict) and str(item.get("key") or "").strip() == target_key and logical_type_for_event(item) == logical_type:
            return True
    return False


def recent_has_logical_event(watch, key, logical_type, ts):
    target_key = str(key or "").strip()
    if not target_key:
        return False
    recent = prune_recent_logical_events(watch, ts)
    return f"{target_key}:{logical_type}" in recent


def api_key_fully_removed(record):
    return isinstance(record, dict) and (
        not api_key_logically_present(record)
        and bool(record.get("cpa_deleted"))
        and not bool(record.get("in_quota"))
        and not bool(record.get("in_proxy_config"))
        and not bool(record.get("disabled_by_quota"))
    )


def api_key_fully_removed_with_only_historical_tombstone(record):
    return api_key_fully_removed(record) and bool(record.get("cpa_deleted_while_quota_disabled"))


def enqueue_known_active_removals(watch, snapshot, ts):
    known = prune_known_active_keys(watch, ts)
    changed = False
    for key, item in list(known.items()):
        record = snapshot.get(key) if isinstance(snapshot, dict) else None
        if not api_key_fully_removed(record):
            continue
        historical_tombstone_removal = api_key_fully_removed_with_only_historical_tombstone(record)
        if (
            api_key_quota_enforcer_silent_state(record)
            and not historical_tombstone_removal
        ) or (
            recently_saw_quota_disabled_cpa_tombstone(watch, key, ts)
            and not historical_tombstone_removal
        ):
            forget_known_active_key(watch, key)
            changed = True
            continue
        if pending_has_logical_event(watch, key, "key_removed"):
            continue
        if recent_has_logical_event(watch, key, "key_removed", ts):
            continue
        account = str(item.get("account") or change_watch_label(key, record)).strip() or change_watch_label(key, record)
        merge_pending_change_event(watch, logical_event(
            key,
            "key_removed",
            "API key deleted",
            account,
            evidence=membership_evidence({"in_proxy_config": True, "in_quota": True, "cpa_deleted": False}, "removed_from"),
        ))
        changed = True
    return changed


def forget_known_active_key(watch, key):
    known = watch.get("known_active_keys")
    if isinstance(known, dict):
        known.pop(str(key or "").strip(), None)


def logical_event(key: str, logical_type: str, title: str, account: str, changes: list[str] | None = None, evidence: dict[str, Any] | None = None) -> ChangeEvent:
    """Build the normalized logical event shape used by notification formatting.
    
    Backend/source evidence stays in the event for debounce and tests, but operator
    messages render only logical account changes."""
    return {
        "key": key,
        "logical_type": logical_type,
        "title": title,
        "account": account,
        "changes": list(changes or []),
        "evidence": evidence or {},
    }


def membership_evidence(record, prefix):
    sources = []
    if record.get("in_proxy_config"):
        sources.append("proxy config")
    if not record.get("cpa_deleted"):
        sources.append("web management")
    if record.get("in_quota"):
        sources.append("quota config")
    return {prefix: ordered_sources(sources)}


def key_added_quota_lines(record):
    if not record.get("in_quota"):
        return []
    daily = record.get("daily")
    weekly = record.get("weekly", "default")
    return [
        f"Daily quota: {format_operator_quota_limit(daily)}",
        f"Weekly quota: {format_effective_weekly_for_reply(daily, weekly)}",
    ]


def key_status_quota_lines(record, status):
    return [f"Status: {status}", *key_added_quota_lines(record)]


def build_change_events(old_snapshot: dict[str, dict[str, Any]], new_snapshot: dict[str, dict[str, Any]]) -> list[ChangeEvent]:
    """Diff two snapshots into a complete list of logical key/account events.
    
    This function must not cap results; detail limits and bulk summaries happen at
    notification flush time so tests/debugging see the full logical diff."""
    events = []
    old_keys = {key for key in old_snapshot if not str(key).startswith("__")}
    new_keys = {key for key in new_snapshot if not str(key).startswith("__")}

    for key in sorted(new_keys - old_keys, key=lambda item: change_watch_label(item, new_snapshot[item]).lower()):
        record = new_snapshot[key]
        if is_auth_record(record):
            changes = [f"Status: {auth_account_status(record)}"]
            account_type = str(record.get("type") or "").strip()
            if account_type:
                changes.append(f"Type: {account_type}")
            events.append(logical_event(
                key,
                "auth_account_added",
                "Proxy account added",
                change_watch_label(key, record),
                changes,
                evidence={"account_type": account_type} if account_type else None,
            ))
            continue
        if api_key_logically_present(record):
            events.append(logical_event(
                key,
                "key_added",
                "API key created",
                change_watch_label(key, record),
                key_status_quota_lines(record, "Active"),
                evidence=membership_evidence(record, "added_to"),
            ))

    for key in sorted(old_keys - new_keys, key=lambda item: change_watch_label(item, old_snapshot[item]).lower()):
        old = old_snapshot[key]
        if is_auth_record(old):
            events.append(logical_event(
                key,
                "auth_account_removed",
                "Proxy account removed",
                change_watch_label(key, old),
                evidence={
                    "account_type": str(old.get("type") or "").strip(),
                    "removed_from": ["auth files"],
                },
            ))
            continue
        if api_key_logically_present(old):
            events.append(logical_event(
                key,
                "key_removed",
                "API key deleted",
                change_watch_label(key, old),
                evidence=membership_evidence(old, "removed_from"),
            ))

    for key in sorted(old_keys & new_keys, key=lambda item: change_watch_label(item, new_snapshot[item]).lower()):
        old = old_snapshot[key]
        new = new_snapshot[key]
        if is_auth_record(old) or is_auth_record(new):
            changes = []
            old_status = auth_account_status(old)
            new_status = auth_account_status(new)
            if old_status != new_status:
                changes.append(f"Status: {old_status} -> {new_status}")
            if old.get("alias") != new.get("alias"):
                changes.append(f"Alias: {old.get('alias') or '-'} -> {new.get('alias') or '-'}")
            if old.get("type") != new.get("type"):
                changes.append(f"Type: {old.get('type') or '-'} -> {new.get('type') or '-'}")
            if old.get("read_error") != new.get("read_error"):
                changes.append("Read status changed")
            if changes:
                events.append(logical_event(
                    key,
                    "auth_account_changed",
                    "Proxy account changed",
                    change_watch_label(key, new),
                    changes,
                ))
            continue
        if is_quota_enforcer_only_change(old, new):
            continue
        manual_transition = manual_key_state_transition(old, new)
        if manual_transition:
            logical_type = "key_manually_disabled" if manual_transition == "disabled" else "key_manually_enabled"
            title = "Proxy key manually disabled" if manual_transition == "disabled" else "Proxy key manually enabled"
            events.append(logical_event(
                key,
                logical_type,
                title,
                change_watch_label(key, new),
                key_status_quota_lines(new, "Disabled" if manual_transition == "disabled" else "Active"),
            ))
            continue
        if api_key_quota_enforcer_silent_state(old) and api_key_fully_removed(new):
            if (
                api_key_protected_quota_disabled_tombstone(old)
                or api_key_protected_quota_disabled_tombstone(new)
            ) and not api_key_active_with_protected_quota_tombstone(old):
                continue
            events.append(logical_event(
                key,
                "key_removed",
                "API key deleted",
                change_watch_label(key, old),
                evidence=membership_evidence(old, "removed_from"),
            ))
            continue

        old_present = api_key_logically_present(old)
        new_present = api_key_logically_present(new)
        if old_present and not new_present:
            if api_key_quota_enforcer_silent_state(new):
                quota_changes = quota_change_lines(old, new)
                if quota_changes:
                    events.append(logical_event(
                        key,
                        "quota_changed",
                        "Quota updated",
                        change_watch_label(key, new),
                        quota_changes,
                    ))
                continue
            events.append(logical_event(
                key,
                "key_removed",
                "API key deleted",
                change_watch_label(key, old),
                evidence=membership_evidence(old, "removed_from"),
            ))
            continue
        if not old_present and new_present:
            if api_key_quota_enforcer_silent_state(old):
                quota_changes = quota_change_lines(old, new)
                if quota_changes:
                    events.append(logical_event(
                        key,
                        "quota_changed",
                        "Quota updated",
                        change_watch_label(key, new),
                        quota_changes,
                    ))
                continue
            events.append(logical_event(
                key,
                "key_added",
                "API key created",
                change_watch_label(key, new),
                key_status_quota_lines(new, "Active"),
                evidence=membership_evidence(new, "added_to"),
            ))
            continue
        if not old_present and not new_present:
            quota_changes = quota_change_lines(old, new)
            if quota_changes and (api_key_quota_enforcer_silent_state(old) or api_key_quota_enforcer_silent_state(new)):
                events.append(logical_event(
                    key,
                    "quota_changed",
                    "Quota updated",
                    change_watch_label(key, new),
                    quota_changes,
                ))
            continue

        if old.get("alias") != new.get("alias"):
            old_alias = old.get("alias") or "-"
            new_alias = new.get("alias") or "-"
            events.append(logical_event(
                key,
                "alias_changed",
                "API key changed",
                f"{old_alias} -> {new_alias}",
                evidence={"old_alias": old_alias, "new_alias": new_alias},
            ))

        quota_changes = quota_change_lines(old, new)
        if quota_changes:
            events.append(logical_event(
                key,
                "quota_changed",
                "Quota updated",
                change_watch_label(key, new),
                quota_changes,
            ))
    return events


def logical_type_for_event(event):
    logical_type = str((event or {}).get("logical_type") or "").strip()
    if logical_type:
        return logical_type
    title = str((event or {}).get("title") or "")
    changes = [str(change or "") for change in (event or {}).get("changes") or []]
    if title == "API key added":
        return "key_added"
    if title == "API key created":
        return "key_added"
    if title in {"API key removed", "API key deleted"} or any(change.startswith("Removed from: ") for change in changes):
        return "key_removed"
    if title == "Quota updated" or any(change.startswith(("Daily: ", "Weekly: ", "Daily quota: ", "Weekly quota: ")) for change in changes):
        return "quota_changed"
    if any(change.startswith("Alias: ") for change in changes):
        return "alias_changed"
    if title in {"Proxy account added", "Codex account added", "Antigravity account added"}:
        return "auth_account_added"
    if title in {"Proxy account removed", "Codex account removed", "Antigravity account removed"}:
        return "auth_account_removed"
    if title == "Proxy account changed":
        return "auth_account_changed"
    if title == "Proxy key manually disabled":
        return "key_manually_disabled"
    if title == "Proxy key manually enabled":
        return "key_manually_enabled"
    return "key_changed"


def merge_change_list_values(changes, prefix):
    values = []
    remaining = []
    for change in changes:
        text = str(change or "")
        if text.startswith(prefix):
            for item in text[len(prefix):].split(","):
                item = item.strip()
                if item and item not in values:
                    values.append(item)
        else:
            remaining.append(text)
    if values:
        remaining.insert(0, source_change_line(prefix, values))
    return remaining


def normalized_change_lines(event):
    logical_type = logical_type_for_event(event)
    if logical_type == "key_removed":
        return ["Status: Removed"]
    if logical_type == "alias_changed":
        return []

    changes = []
    for change in event.get("changes") or []:
        text = str(change or "").strip()
        if not text:
            continue
        if text.startswith("Daily quota: "):
            text = "Daily: " + text[len("Daily quota: "):]
        if text.startswith("Weekly quota: "):
            text = "Weekly: " + text[len("Weekly quota: "):]
        if text.startswith("Restored in: "):
            text = "Enabled in: " + text[len("Restored in: "):]
        changes.append(text)
    changes = merge_change_list_values(changes, "Removed from: ")
    changes = merge_change_list_values(changes, "Added to: ")
    changes = merge_change_list_values(changes, "Enabled in: ")
    return changes


def format_change_event(event):
    logical_type = logical_type_for_event(event)
    title = event.get("title", "API key updated")
    if logical_type == "key_removed":
        heading = "API key deleted"
    elif logical_type == "key_added":
        heading = "API key created"
    elif logical_type == "quota_changed":
        heading = "Quota updated"
    elif logical_type == "alias_changed":
        heading = "API key changed"
    elif title == "Proxy account removed":
        heading = "Proxy account removed"
    elif title == "Proxy account added":
        heading = "Proxy account added"
    elif title == "Proxy account changed":
        heading = "Proxy account changed"
    elif logical_type in {"key_manually_disabled", "key_manually_enabled"}:
        return format_manual_key_group(logical_type, [event])
    else:
        heading = "API key changed"
    if logical_type in {"auth_account_added", "auth_account_removed"}:
        return format_proxy_account_group(logical_type, [event])
    lines = [
        heading,
        "",
        f"{'Account' if logical_type == 'auth_account_changed' else 'User'}: {event.get('account') or 'unknown'}",
    ]
    if logical_type == "key_added":
        lines.extend(str(change or "").strip() for change in event.get("changes") or [] if str(change or "").strip())
    else:
        lines.extend(normalized_change_lines(event))
    return "\n".join(lines)


def format_proxy_account_group(logical_type, events):
    action = "removed" if logical_type == "auth_account_removed" else "added"
    labels = [safe_proxy_account_label(event) for event in events]
    provider = proxy_account_provider_label(events[0] if events else {})
    lines = [
        f"{provider} account {action}",
        "",
    ]
    lines.extend(f"- {label}" for label in labels)
    return "\n".join(lines)


def format_manual_key_group(logical_type, events):
    action = "disabled" if logical_type == "key_manually_disabled" else "enabled"
    noun = "key" if len(events) == 1 else "keys"
    lines = [f"API {noun} {action}", ""]
    for index, event in enumerate(events):
        if index:
            lines.append("")
        lines.append(f"User: {safe_change_summary_label(event)}")
        changes = [str(change or "").strip() for change in event.get("changes") or [] if str(change or "").strip()]
        if logical_type == "key_manually_disabled":
            changes = [change for change in changes if change == "Status: Disabled"]
        lines.extend(changes)
    return "\n".join(lines)


def change_notification_keyboard(logical_type):
    return None


def safe_change_summary_label(event):
    account = str((event or {}).get("account") or "unknown").strip() or "unknown"
    key = str((event or {}).get("key") or "").strip()
    if account == key or re.match(r"(?i)^sk-[A-Za-z0-9_-]{8,}$", account) or len(account) > 80:
        return mask_key(account)
    return account


def change_summary_type_label(logical_type):
    return {
        "key_added": "API key created",
        "key_removed": "API key deleted",
        "quota_changed": "Quota updated",
        "alias_changed": "API key changed",
        "auth_account_added": "Proxy account added",
        "auth_account_removed": "Proxy account removed",
        "auth_account_changed": "Proxy account changed",
        "key_manually_disabled": "Proxy key manually disabled",
        "key_manually_enabled": "Proxy key manually enabled",
    }.get(logical_type, "API key changed")


def format_change_summary(events):
    # Large batches still notify explicitly, but details are capped at send time so
    # build_change_events() can remain a complete logical diff for tests/debugging.
    counts = {}
    labels = []
    for event in events:
        logical_type = logical_type_for_event(event)
        counts[logical_type] = counts.get(logical_type, 0) + 1
        label = safe_change_summary_label(event)
        if label not in labels:
            labels.append(label)
    lines = [
        "Change notification summary",
        "",
        f"{len(events)} more logical change(s) detected.",
        "",
        "By type:",
    ]
    for logical_type, count in sorted(counts.items(), key=lambda item: change_summary_type_label(item[0])):
        lines.append(f"- {change_summary_type_label(logical_type)}: {count}")
    if labels:
        lines.extend(["", "Accounts:"])
        for label in labels[:10]:
            lines.append(f"- {label}")
        if len(labels) > 10:
            lines.append(f"... and {len(labels) - 10} more")
    return "\n".join(lines)


def prune_recent_logical_events(watch, ts):
    recent = watch.get("recent_logical_events")
    if not isinstance(recent, dict):
        return {}
    for key, item in list(recent.items()):
        if not isinstance(item, dict) or ts >= int(item.get("expires_at", 0) or 0):
            recent.pop(key, None)
    return recent


def recent_logical_key(event):
    key = str(event.get("key") or "").strip()
    if not key:
        return ""
    return f"{key}:{logical_type_for_event(event)}"


def remember_recent_logical_event(watch, event, ts):
    recent_key = recent_logical_key(event)
    if not recent_key:
        return
    recent = watch.setdefault("recent_logical_events", {})
    if not isinstance(recent, dict):
        recent = {}
        watch["recent_logical_events"] = recent
    evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
    recent[recent_key] = {
        "logical_type": logical_type_for_event(event),
        "sent_at": ts,
        "expires_at": ts + RECENT_LOGICAL_REMOVAL_SECONDS,
        "evidence": evidence,
    }


def clear_recent_removal_lifecycle(watch, key):
    recent = watch.get("recent_logical_events")
    if isinstance(recent, dict):
        recent.pop(f"{str(key or '').strip()}:key_removed", None)


def pending_change_key(event):
    key = str(event.get("key") or event.get("account") or short_code()).strip()
    logical_type = logical_type_for_event(event)
    if key and logical_type:
        return f"{key}:{logical_type}"
    return key or short_code()


def merge_evidence(existing, event):
    target = existing.setdefault("evidence", {})
    if not isinstance(target, dict):
        target = {}
        existing["evidence"] = target
    source = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
    for field, values in source.items():
        if isinstance(values, list):
            current = target.setdefault(field, [])
            if not isinstance(current, list):
                current = []
                target[field] = current
            for value in values:
                if value not in current:
                    current.append(value)
            target[field] = ordered_sources(current)
        elif values is not None:
            target[field] = values


# Pending events are logical key/account changes. Source deltas are merged as
# evidence, and late removal tail evidence is ignored briefly after the logical
# removal notification so quota/proxy/web deletes do not become duplicate chats.
def merge_pending_change_event(watch: dict[str, Any], event: ChangeEvent) -> None:
    """Merge one logical event into pending notification state.
    
    Source evidence is coalesced, recent removal tails are absorbed, and a logical
    re-add cancels a queued removal for the same key before holdback expires."""
    pending = watch.setdefault("pending", {})
    if not isinstance(pending, dict):
        pending = {}
        watch["pending"] = pending
    ts = now_ts()
    logical_type = logical_type_for_event(event)
    key = str(event.get("key") or event.get("account") or "").strip()
    prune_recent_logical_events(watch, ts)
    if logical_type == "key_added":
        clear_recent_removal_lifecycle(watch, key)
        # If a key disappears briefly while backends converge, a later logical
        # reappearance before holdback means the queued removal was transient.
        pending.pop(f"{key}:key_removed", None)
    if logical_type == "key_removed":
        recent = watch.get("recent_logical_events") if isinstance(watch.get("recent_logical_events"), dict) else {}
        recent_key = recent_logical_key(event)
        if recent_key and recent_key in recent:
            merge_evidence(recent[recent_key], event)
            return

    pending_key = pending_change_key(event)
    existing = pending.setdefault(pending_key, {
        "key": key or pending_key,
        "logical_type": logical_type,
        "title": event.get("title", "API key updated"),
        "account": event.get("account", "unknown"),
        "changes": [],
        "evidence": {},
        "first_seen": ts,
    })
    existing["logical_type"] = logical_type
    existing["title"] = event.get("title", existing.get("title", "API key updated"))
    existing["account"] = event.get("account", existing.get("account", "unknown"))
    existing["updated_at"] = ts
    changes = existing.setdefault("changes", [])
    for change in event.get("changes") or []:
        if change not in changes:
            changes.append(change)
    merge_evidence(existing, event)


# Non-removal logical events send after the normal debounce. Removals wait only a
# short holdback, then a recent-removal window absorbs slower backend tail events.
def flush_pending_change_notifications(watch: dict[str, Any], dry_run: bool = False, state: dict[str, Any] | None = None) -> int:
    """Send pending notifications that have passed debounce and removal holdback.
    
    Before sending removals, the current snapshot is checked to avoid stale false
    removals; overflow is summarized without full keys or backend source labels."""
    pending = watch.get("pending")
    if not isinstance(pending, dict):
        return 0
    ts = now_ts()
    prune_recent_logical_events(watch, ts)
    snapshot = watch.get("snapshot") if isinstance(watch.get("snapshot"), dict) else {}
    matured = []
    for key, event in list(pending.items()):
        last_change_raw = event.get("updated_at", event.get("first_seen"))
        last_change = ts if last_change_raw is None else int(last_change_raw)
        debounce_seconds = CHANGE_NOTIFICATION_DEBOUNCE_SECONDS
        logical_type = logical_type_for_event(event)
        bot_verified = matching_recent_bot_action(state, event, ts)
        if logical_type == "key_removed":
            event_key = str(event.get("key") or "").strip()
            # A current logical presence wins over a stale queued removal. This
            # prevents transient backend gaps from becoming false removal chats.
            current_record = snapshot.get(event_key) if event_key else None
            current_record_cancels_removal = isinstance(current_record, dict) and (
                api_key_logically_present(current_record)
                or (
                    api_key_quota_enforcer_silent_state(current_record)
                    and not api_key_fully_removed_with_only_historical_tombstone(current_record)
                )
            )
            current_record_is_historical_tombstone_removal = api_key_fully_removed_with_only_historical_tombstone(current_record)
            recent_quota_tombstone_cancels_removal = (
                recently_saw_quota_disabled_cpa_tombstone(watch, event_key, ts)
                and not current_record_is_historical_tombstone_removal
            )
            if current_record_cancels_removal or recent_quota_tombstone_cancels_removal:
                pending.pop(key, None)
                forget_known_active_key(watch, event_key)
                continue
            debounce_seconds = max(debounce_seconds, CHANGE_REMOVAL_DEBOUNCE_SECONDS)
            first_seen_raw = event.get("first_seen")
            first_seen = ts if first_seen_raw is None else int(first_seen_raw)
            if not bot_verified and ts - first_seen < max(debounce_seconds, REMOVAL_HOLDBACK_SECONDS):
                continue
        if not bot_verified and ts - last_change < max(0, debounce_seconds):
            continue
        matured.append((key, event))

    auth_groups = {}
    auth_group_order = []
    manual_key_groups = {}
    manual_key_group_order = []
    remaining = []
    for key, event in matured:
        logical_type = logical_type_for_event(event)
        if logical_type in {"auth_account_added", "auth_account_removed"}:
            group_key = (logical_type, proxy_account_provider_label(event))
            if group_key not in auth_groups:
                auth_groups[group_key] = []
                auth_group_order.append(group_key)
            auth_groups[group_key].append((key, event))
        elif logical_type in {"key_manually_disabled", "key_manually_enabled"}:
            if logical_type not in manual_key_groups:
                manual_key_groups[logical_type] = []
                manual_key_group_order.append(logical_type)
            manual_key_groups[logical_type].append((key, event))
        else:
            remaining.append((key, event))

    detailed = remaining[:DETAILED_CHANGE_NOTIFICATION_LIMIT]
    overflow = remaining[DETAILED_CHANGE_NOTIFICATION_LIMIT:]
    sent = 0
    for group_key in auth_group_order:
        logical_type = group_key[0]
        group = auth_groups.get(group_key, [])
        if not group:
            continue
        if send_telegram(format_proxy_account_group(logical_type, [event for _, event in group]), dry_run=dry_run):
            sent += 1
            for key, _ in group:
                pending.pop(key, None)

    for logical_type in manual_key_group_order:
        group = manual_key_groups.get(logical_type, [])
        if not group:
            continue
        if send_telegram(
            format_manual_key_group(logical_type, [event for _, event in group]),
            dry_run=dry_run,
            reply_markup=change_notification_keyboard(logical_type),
        ):
            sent += 1
            for key, _ in group:
                pending.pop(key, None)

    for key, event in detailed:
        logical_type = logical_type_for_event(event)
        text = format_change_event(event)
        reply_markup = change_notification_keyboard(logical_type)
        if reply_markup:
            sent_ok = send_telegram(text, dry_run=dry_run, reply_markup=reply_markup)
        else:
            sent_ok = send_telegram(text, dry_run=dry_run)
        if sent_ok:
            sent += 1
            if logical_type == "key_removed":
                remember_recent_logical_event(watch, event, ts)
                forget_known_active_key(watch, event.get("key"))
            elif logical_type == "key_added":
                clear_recent_removal_lifecycle(watch, event.get("key"))
                remember_known_active_key(watch, event.get("key"), event.get("account"), ts)
            pending.pop(key, None)

    if overflow:
        if send_telegram(format_change_summary([event for _, event in overflow]), dry_run=dry_run):
            sent += 1
            for key, event in overflow:
                logical_type = logical_type_for_event(event)
                if logical_type == "key_removed":
                    remember_recent_logical_event(watch, event, ts)
                    forget_known_active_key(watch, event.get("key"))
                elif logical_type == "key_added":
                    clear_recent_removal_lifecycle(watch, event.get("key"))
                    remember_known_active_key(watch, event.get("key"), event.get("account"), ts)
                pending.pop(key, None)

    return sent


def process_change_notifications(state: dict[str, Any], dry_run: bool = False, force: bool = False) -> int:
    """Run one change-watch tick and flush any matured logical notifications.
    
    The watch fingerprint/snapshot live in monitor state; force=True lets command
    handling trigger an immediate post-mutation diff pass."""
    watch = state.setdefault("change_watch", {})
    if not isinstance(watch, dict):
        watch = {}
        state["change_watch"] = watch
    ts = now_ts()
    if not force and ts - int(watch.get("checked_at", 0) or 0) < max(1, CHANGE_WATCH_INTERVAL_SECONDS):
        return 0
    watch["checked_at"] = ts

    try:
        snapshot = change_watch_snapshot()
        fingerprint = change_watch_fingerprint(snapshot)
    except Exception as exc:
        log(f"change watch failed: {exc}")
        return 0

    old_fingerprint = watch.get("fingerprint")
    old_snapshot = watch.get("snapshot") if isinstance(watch.get("snapshot"), dict) else None
    watch["fingerprint"] = fingerprint
    watch["snapshot"] = snapshot
    watch["updated_at"] = now_ts()
    remember_known_active_snapshot(watch, snapshot, ts)
    remember_quota_disabled_cpa_tombstone_snapshot(watch, snapshot, ts)

    changed = old_fingerprint != fingerprint or old_snapshot is None
    if old_fingerprint and old_fingerprint != fingerprint and old_snapshot is not None:
        event_old_snapshot = old_snapshot
        event_snapshot = snapshot
        if not has_auth_records(old_snapshot) and has_auth_records(snapshot):
            event_old_snapshot = strip_auth_records(old_snapshot)
            event_snapshot = strip_auth_records(snapshot)
        for event in build_change_events(event_old_snapshot, event_snapshot):
            if is_change_event_suppressed(state, event):
                changed = True
                continue
            merge_pending_change_event(watch, event)
            changed = True

    if enqueue_known_active_removals(watch, snapshot, ts):
        changed = True

    sent = flush_pending_change_notifications(watch, dry_run=dry_run, state=state)
    if sent:
        log(f"sent change notifications={sent}")
    return sent or (1 if changed else 0)
