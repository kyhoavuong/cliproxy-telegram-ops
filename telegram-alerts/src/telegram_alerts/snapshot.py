"""Cached operational snapshot builder and Telegram reply renderers."""

from __future__ import annotations
from typing import Any
from .contracts import AlertDict, QuotaRow, SnapshotPayload

from datetime import datetime, time as dtime, timedelta, timezone
import json
from pathlib import Path
import re
import time
from zoneinfo import ZoneInfo

from .settings import (
    ALERT_HOSTNAME,
    AUTH_DIR,
    AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS,
    BOT_STARTED_AT,
    CAPACITY_CHECK_FAST_CACHE_SECONDS,
    ENFORCER_LOG,
    QUOTA_CRITICAL_PERCENT,
    QUOTA_MANAGEMENT_FAST_CACHE_SECONDS,
    QUOTA_STATE,
    QUOTA_WARN_PERCENT,
    SNAPSHOT_MAX_AGE_SECONDS,
)
from .utils import fmt_duration, fmt_limit, fmt_tokens, key_ref, log_timing, mask_key, monotonic_ms, now_ts, percent
from .models import Alert
from .provider_labels import normalize_provider, provider_title_label
from .quota_config import load_cpa_alias_map, load_quota_data, preferred_quota_alias
from .storage import load_json
from .usage import get_usage_for_items, usage_rate_estimate, capacity_demand_rate_estimate
from . import health as health_module
from .health import (
    CODEX_WHAM_HEADERS,
    CODEX_WHAM_USAGE_URL,
    GPT_POOL_PRIMARY_TOKEN_EQUIVALENT,
    GPT_POOL_SECONDARY_TOKEN_EQUIVALENT,
    check_http_services_detailed,
    codex_free_plan_alert,
    collect_alerts_with_auth_observation,
    empty_gpt_pool_capacity,
    gpt_pool_capacity_snapshot,
    gpt_pool_capacity_snapshot_with_recent_cache,
    identity_auth_index,
    management_api_call_body,
    management_auth_files,
    management_request,
    management_window_used_percent,
    severity_icon,
)

_UNSET = object()


def list_or_empty(value):
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def dict_or_empty(value):
    return value if isinstance(value, dict) else {}


def set_or_empty(value):
    if isinstance(value, set):
        return value
    if isinstance(value, (list, tuple)):
        return set(value)
    return set()


def load_quota_context():
    started = monotonic_ms()
    tz_name, items, disabled, config_keys = load_quota_data()
    items = list_or_empty(items)
    disabled = set_or_empty(disabled)
    config_keys = set_or_empty(config_keys)
    alias_by_key = dict_or_empty(load_cpa_alias_map())
    usage = dict_or_empty(get_usage_for_items(items, tz_name))
    context = {
        "tz_name": tz_name,
        "items": items,
        "disabled": disabled,
        "config_keys": config_keys,
        "alias_by_key": alias_by_key,
        "usage": usage,
    }
    log_timing("load_quota_context", started, items=len(items))
    return context

def quota_display_alias(key, item_name, alias_by_key):
    return preferred_quota_alias(key, item_name, dict_or_empty(alias_by_key).get(key))

def quota_rows_from_context(context):
    context = dict_or_empty(context)
    items = list_or_empty(context.get("items", []))
    disabled = set_or_empty(context.get("disabled", set()))
    config_keys = set_or_empty(context.get("config_keys", set()))
    alias_by_key = dict_or_empty(context.get("alias_by_key", {}))
    usage = dict_or_empty(context.get("usage", {}))
    rows = []
    for item in items:
        key = item["key"]
        alias = quota_display_alias(key, item["name"], alias_by_key)
        daily_used = usage.get(key, {}).get("daily_tokens", 0)
        weekly_used = usage.get(key, {}).get("weekly_tokens", 0)
        daily_limit = item["daily_token_limit"]
        weekly_limit = item["weekly_token_limit"]
        daily_percent = percent(daily_used, daily_limit)
        weekly_percent = percent(weekly_used, weekly_limit)
        percents = [p for p in (daily_percent, weekly_percent) if p is not None]
        effective_percent = max(percents) if percents else None
        manually_disabled = bool(item.get("manually_disabled"))
        if key in disabled:
            status = "disabled"
        elif manually_disabled:
            status = "manually_disabled"
        else:
            status = "active"
        if config_keys and key not in config_keys and key not in disabled and not manually_disabled:
            status = "missing"
        rows.append({
            "name": item["name"],
            "alias": alias,
            "key": key,
            "masked": mask_key(key),
            "status": status,
            "daily_used": daily_used,
            "daily_limit": daily_limit,
            "daily_percent": daily_percent,
            "weekly_used": weekly_used,
            "weekly_limit": weekly_limit,
            "weekly_percent": weekly_percent,
            "effective_percent": effective_percent,
            "manually_disabled": manually_disabled,
        })
    rows.sort(key=lambda row: (
        row["status"] not in {"disabled", "manually_disabled"},
        -(row["effective_percent"] or 0),
        row["name"],
    ))
    return rows

def quota_alerts_from_context(context):
    alerts = []
    context = dict_or_empty(context)
    items = list_or_empty(context.get("items", []))
    disabled = set_or_empty(context.get("disabled", set()))
    config_keys = set_or_empty(context.get("config_keys", set()))
    alias_by_key = dict_or_empty(context.get("alias_by_key", {}))
    usage = dict_or_empty(context.get("usage", {}))
    for item in items:
        name = item["name"]
        key = item["key"]
        alias = quota_display_alias(key, name, alias_by_key)
        ref = key_ref(key)
        key_usage = usage.get(key, {})
        daily_used = key_usage.get("daily_tokens", 0)
        weekly_used = key_usage.get("weekly_tokens", 0)
        daily_limit = item["daily_token_limit"]
        weekly_limit = item["weekly_token_limit"]
        manually_disabled = bool(item.get("manually_disabled"))

        if key in disabled:
            alerts.append(Alert(
                alert_id=f"quota:disabled:{ref}",
                severity="critical",
                title=f"{alias} is disabled by quota",
                body=f"{alias} is currently removed from active proxy keys. Daily {fmt_tokens(daily_used)}/{fmt_limit(daily_limit)}, weekly {fmt_tokens(weekly_used)}/{fmt_limit(weekly_limit)}.",
                fingerprint=f"{daily_used}:{weekly_used}:{daily_limit}:{weekly_limit}",
            ))
            continue
        if manually_disabled:
            continue
        elif config_keys and key not in config_keys:
            alerts.append(Alert(
                alert_id=f"quota:not-in-proxy:{ref}",
                severity="warning",
                title=f"{alias} is not in active proxy config",
                body=f"{alias} exists in quotas.json but is missing from config.yaml api-keys and is not marked disabled.",
                fingerprint=f"{ref}:missing",
            ))

        windows = [
            ("daily", daily_used, daily_limit),
            ("weekly", weekly_used, weekly_limit),
        ]
        for window, used, limit in windows:
            usage_percent = percent(used, limit)
            if usage_percent is None:
                continue
            if usage_percent >= 100:
                severity = "critical"
                title = f"{alias} exhausted {window} quota"
            elif usage_percent >= QUOTA_CRITICAL_PERCENT:
                severity = "critical"
                title = f"{alias} is almost out of {window} quota"
            elif usage_percent >= QUOTA_WARN_PERCENT:
                severity = "warning"
                title = f"{alias} is high on {window} quota"
            else:
                continue

            alerts.append(Alert(
                alert_id=f"quota:{window}:{ref}",
                severity=severity,
                title=title,
                body=f"{alias} used {fmt_tokens(used)}/{fmt_tokens(limit)} tokens ({usage_percent:.2f}%).",
                fingerprint=f"{int(usage_percent // 5) * 5}:{used >= limit}",
            ))
    return alerts

def quota_data_unavailable_alert(exc):
    return Alert(
        alert_id="quota:data-unavailable",
        severity="critical",
        title="Quota data is unavailable",
        body=str(exc),
        fingerprint=str(exc),
    )

def alert_to_dict(alert: Alert) -> AlertDict:
    """Serialize an Alert dataclass into the JSON-compatible snapshot alert shape."""
    return {
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "title": alert.title,
        "body": alert.body,
        "fingerprint": alert.fingerprint,
    }

def dict_to_alert(data: AlertDict | dict[str, Any]) -> Alert:
    """Rehydrate a snapshot alert dict into an Alert, defaulting missing optional text safely."""
    return Alert(
        alert_id=str(data.get("alert_id", "")),
        severity=str(data.get("severity", "warning")),
        title=str(data.get("title", "")),
        body=str(data.get("body", "")),
        fingerprint=str(data.get("fingerprint", "")),
    )

def sanitize_quota_row(row: dict[str, Any]) -> QuotaRow:
    """Return the Telegram snapshot quota-row shape without the full API key.
    
    Callers should pass masked keys only to UI renderers so cached snapshots remain
    safe to inspect in logs or tests."""
    return {
        "name": row["name"],
        "alias": row["alias"],
        "masked": row.get("masked", ""),
        "status": row["status"],
        "daily_used": row["daily_used"],
        "daily_limit": row["daily_limit"],
        "daily_percent": row["daily_percent"],
        "weekly_used": row["weekly_used"],
        "weekly_limit": row["weekly_limit"],
        "weekly_percent": row["weekly_percent"],
        "effective_percent": row["effective_percent"],
    }

def auth_inspection_recently_complete(auth_inspection_state, ts):
    if not isinstance(auth_inspection_state, dict):
        return False
    try:
        last_complete_at = int(auth_inspection_state.get("last_complete_at", 0) or 0)
    except (TypeError, ValueError):
        last_complete_at = 0
    return last_complete_at > 0 and ts - last_complete_at < max(0, int(AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS or 0))


def apply_auth_inspection_staleness(system_alerts, auth_quota_observation, auth_inspection_state, ts):
    alerts = dict(system_alerts or {})
    # A transient partial inspection right after a complete one is not reliable
    # incident evidence; keep Health Alerts quiet until the condition is sustained.
    if (
        isinstance(auth_quota_observation, dict)
        and not bool(auth_quota_observation.get("complete"))
        and auth_inspection_recently_complete(auth_inspection_state, ts)
    ):
        alerts.pop("auth:quota-inspection-unavailable", None)
    return alerts


# Snapshots combine service health, auth quota inspection, and quota usage into
# one cached object so normal button taps are fast. Live interactive refreshes can
# force Usage Keeper quota inspection when the caller explicitly requests it.
def build_snapshot(interactive: bool = False, auth_refresh_before_check: bool | None = None, auth_wait_for_refresh: bool | None = None, auth_wait_seconds: int | None = None, auth_inspection_state: dict[str, Any] | None = None, gpt_pool_management_fallback: bool = True, gpt_pool_recent_cache: dict[str, Any] | None = None, gpt_pool_recent_cache_max_age_seconds: int | None = None) -> SnapshotPayload:
    """Build the cached operational snapshot consumed by menus and alert checks.

    This may touch HTTP health checks, Usage Keeper auth inspection, quota files, and
    SQLite usage reads; interactive callers usually skip slow auth refresh waits."""
    started = monotonic_ms()
    ts = now_ts()
    step_started = monotonic_ms()
    http_results = check_http_services_detailed()
    http_ms = monotonic_ms() - step_started
    if auth_refresh_before_check is None:
        auth_refresh_before_check = False
    if auth_wait_for_refresh is None:
        auth_wait_for_refresh = False
    step_started = monotonic_ms()
    system_alerts, auth_quota_observation = collect_alerts_with_auth_observation(
        http_results,
        auth_refresh_before_check=auth_refresh_before_check,
        auth_wait_for_refresh=auth_wait_for_refresh,
        auth_wait_seconds=auth_wait_seconds,
        include_cached_disabled_auth=not bool(interactive),
    )
    system_alerts = apply_auth_inspection_staleness(system_alerts, auth_quota_observation, auth_inspection_state, ts)
    alerts_ms = monotonic_ms() - step_started
    quota_context_ms = 0
    quota_signals_ms = 0
    step_started = monotonic_ms()
    try:
        quota_context = load_quota_context()
        quota_context_ms = monotonic_ms() - step_started
        step_started = monotonic_ms()
        quota_signals = {alert.alert_id: alert for alert in quota_alerts_from_context(quota_context)}
        quota_signals_ms = monotonic_ms() - step_started
        step_started = monotonic_ms()
        rows = [sanitize_quota_row(row) for row in quota_rows_from_context(quota_context)]
        quota_error = ""
    except Exception as exc:
        quota_context_ms = monotonic_ms() - step_started
        quota_signals = {"quota:data-unavailable": quota_data_unavailable_alert(exc)}
        rows = []
        quota_error = str(exc)
    quota_rows_ms = monotonic_ms() - step_started
    step_started = monotonic_ms()
    capacity_check_recent_gpt_pool = None
    try:
        if gpt_pool_recent_cache is not None or gpt_pool_recent_cache_max_age_seconds is not None:
            gpt_pool_capacity, capacity_check_recent_gpt_pool = gpt_pool_capacity_snapshot_with_recent_cache(
                recent_cache=gpt_pool_recent_cache,
                cache_now=ts,
                cache_max_age_seconds=gpt_pool_recent_cache_max_age_seconds or 0,
                allow_management_fallback=gpt_pool_management_fallback,
                auth_inspection_state=auth_inspection_state,
            )
        else:
            gpt_pool_capacity = gpt_pool_capacity_snapshot(allow_management_fallback=gpt_pool_management_fallback)
    except Exception:
        gpt_pool_capacity = empty_gpt_pool_capacity("Usage Keeper quota cache unavailable")
    gpt_pool_ms = monotonic_ms() - step_started

    # Capacity Check UI may use realtime 60m demand, but alerting stays on the
    # local estimate so a realtime endpoint outage cannot flap alert lifecycle.
    rate = usage_rate_estimate()
    gpt_pool_observation = gpt_pool_5h_observation(
        {"created_at": ts, "gpt_pool_capacity": gpt_pool_capacity},
        rate,
    )
    capacity_alert = gpt_pool_5h_low_capacity_alert(
        {"created_at": ts, "gpt_pool_capacity": gpt_pool_capacity},
        rate,
    )
    if capacity_alert is not None:
        system_alerts[capacity_alert.alert_id] = capacity_alert
    free_plan_alert = codex_free_plan_alert(gpt_pool_capacity)
    if free_plan_alert is not None:
        system_alerts[free_plan_alert.alert_id] = free_plan_alert

    enforcer_age = "unknown"
    if ENFORCER_LOG.exists():
        enforcer_age = f"{max(0, ts - int(ENFORCER_LOG.stat().st_mtime))}s"
    snapshot = {
        "created_at": ts,
        "service_lines": http_service_status_lines(http_results),
        "system_alerts": {k: alert_to_dict(v) for k, v in system_alerts.items()},
        "auth_quota_observation": auth_quota_observation,
        "quota_signals": {k: alert_to_dict(v) for k, v in quota_signals.items()},
        "quota_rows": rows,
        "quota_error": quota_error,
        "gpt_pool_capacity": gpt_pool_capacity,
        "capacity_demand_rate": rate,
        "gpt_pool_5h_observation": gpt_pool_observation,
        "enforcer_age": enforcer_age,
    }
    if capacity_check_recent_gpt_pool is not None:
        snapshot["capacity_check_recent_gpt_pool"] = capacity_check_recent_gpt_pool
    log_timing(
        "build_snapshot",
        started,
        interactive=int(bool(interactive)),
        http_ms=http_ms,
        alerts_ms=alerts_ms,
        quota_context_ms=quota_context_ms,
        quota_signals_ms=quota_signals_ms,
        quota_rows_ms=quota_rows_ms,
        gpt_pool_ms=gpt_pool_ms,
    )
    return snapshot

def get_snapshot(state: dict[str, Any], live: bool = False, interactive: bool = False, auth_refresh_before_check: bool | None = None, auth_wait_for_refresh: bool | None = None, auth_wait_seconds: int | None = None, auth_inspection_state: dict[str, Any] | None = None, gpt_pool_management_fallback: bool = True) -> SnapshotPayload:
    """Return cached snapshot state unless live data is requested or the cache is stale.

    Interactive defaults avoid blocking on auth refresh unless the caller explicitly
    asks for refresh/wait behavior."""
    snapshot = state.get("snapshot")
    if (
        live
        or not isinstance(snapshot, dict)
        or now_ts() - int(snapshot.get("created_at", 0) or 0) > SNAPSHOT_MAX_AGE_SECONDS
    ):
        if auth_refresh_before_check is None:
            auth_refresh_before_check = False if interactive else None
        if auth_wait_for_refresh is None:
            auth_wait_for_refresh = False if interactive else None
        snapshot = build_snapshot(
            interactive=interactive,
            auth_refresh_before_check=auth_refresh_before_check,
            auth_wait_for_refresh=auth_wait_for_refresh,
            auth_wait_seconds=auth_wait_seconds,
            auth_inspection_state=auth_inspection_state,
            gpt_pool_management_fallback=gpt_pool_management_fallback,
        )
        state["snapshot"] = snapshot
    return snapshot


def build_quota_rows_snapshot(cache_now=None) -> SnapshotPayload:
    """Build only quota rows for screens that do not need health or GPT capacity."""
    started = monotonic_ms()
    ts = int(cache_now if cache_now is not None else now_ts())
    try:
        context = load_quota_context()
        rows = [sanitize_quota_row(row) for row in quota_rows_from_context(context)]
        quota_error = ""
    except Exception as exc:
        rows = []
        quota_error = str(exc)
    snapshot = {
        "created_at": ts,
        "quota_rows": rows,
        "quota_error": quota_error,
    }
    log_timing("build_quota_rows_snapshot", started, rows=len(rows), error=int(bool(quota_error)))
    return snapshot


def build_health_alerts_snapshot(interactive: bool = False, auth_inspection_state: dict[str, Any] | None = None, cache_now=None) -> SnapshotPayload:
    """Build only system health alerts for the Health Alerts screen."""
    started = monotonic_ms()
    ts = int(cache_now if cache_now is not None else now_ts())
    http_results = check_http_services_detailed()
    system_alerts, auth_quota_observation = collect_alerts_with_auth_observation(
        http_results,
        auth_refresh_before_check=False if interactive else None,
        auth_wait_for_refresh=False if interactive else None,
        include_cached_disabled_auth=not bool(interactive),
    )
    system_alerts = apply_auth_inspection_staleness(system_alerts, auth_quota_observation, auth_inspection_state, ts)
    snapshot = {
        "created_at": ts,
        "service_lines": http_service_status_lines(http_results),
        "system_alerts": {k: alert_to_dict(v) for k, v in system_alerts.items()},
        "auth_quota_observation": auth_quota_observation,
    }
    log_timing("build_health_alerts_snapshot", started, alerts=len(system_alerts))
    return snapshot


def get_capacity_check_snapshot(state: dict[str, Any], live: bool = False) -> SnapshotPayload:
    snapshot = state.get("capacity_check_snapshot")
    ts = now_ts()
    try:
        age = ts - int(dict_or_empty(snapshot).get("created_at", 0) or 0)
    except (TypeError, ValueError):
        age = CAPACITY_CHECK_FAST_CACHE_SECONDS + 1
    if not live and isinstance(snapshot, dict) and age <= max(0, int(CAPACITY_CHECK_FAST_CACHE_SECONDS or 0)):
        return snapshot
    snapshot = build_snapshot(
        interactive=True,
        auth_refresh_before_check=False,
        auth_wait_for_refresh=False,
        auth_inspection_state=dict_or_empty(state.get("auth_quota_inspection")),
        gpt_pool_management_fallback=False,
        gpt_pool_recent_cache=dict_or_empty(state.get("capacity_check_recent_gpt_pool")),
        gpt_pool_recent_cache_max_age_seconds=CAPACITY_CHECK_FAST_CACHE_SECONDS,
    )
    recent_cache = snapshot.pop("capacity_check_recent_gpt_pool", None)
    if isinstance(recent_cache, dict):
        state["capacity_check_recent_gpt_pool"] = recent_cache
    if "capacity_check_demand_rate" not in snapshot and isinstance(snapshot.get("capacity_demand_rate"), dict):
        snapshot["capacity_check_demand_rate"] = snapshot["capacity_demand_rate"]
    state["capacity_check_snapshot"] = snapshot
    return snapshot

GPT_POOL_INTERACTIVE_RETRY_TIMEOUT_SECONDS = 6.0
GPT_POOL_INTERACTIVE_RETRY_INTERVAL_SECONDS = 1.0


def snapshot_with_complete_gpt_pool(
    state: dict[str, Any],
    live: bool = False,
    interactive: bool = True,
    auth_refresh_before_check: bool | None = None,
    auth_wait_for_refresh: bool | None = None,
    timeout_seconds: float = GPT_POOL_INTERACTIVE_RETRY_TIMEOUT_SECONDS,
    interval_seconds: float = GPT_POOL_INTERACTIVE_RETRY_INTERVAL_SECONDS,
    gpt_pool_management_fallback: bool = True,
) -> SnapshotPayload:
    """Return a Capacity-check snapshot, briefly retrying incomplete GPT quota coverage.

    This helper is intentionally used only by manual Capacity check callbacks so the
    background alert snapshot path never blocks for the interactive retry window.
    """
    snapshot = get_snapshot(
        state,
        live=live,
        interactive=interactive,
        auth_refresh_before_check=auth_refresh_before_check,
        auth_wait_for_refresh=auth_wait_for_refresh,
        gpt_pool_management_fallback=gpt_pool_management_fallback,
    )
    if gpt_pool_complete_coverage(dict_or_empty(snapshot.get("gpt_pool_capacity"))):
        return snapshot
    started = time.monotonic()
    latest = snapshot
    while time.monotonic() - started < float(timeout_seconds or 0):
        time.sleep(float(interval_seconds or 0))
        latest = get_snapshot(
            state,
            live=True,
            interactive=interactive,
            auth_refresh_before_check=auth_refresh_before_check,
            auth_wait_for_refresh=auth_wait_for_refresh,
            gpt_pool_management_fallback=gpt_pool_management_fallback,
        )
        if gpt_pool_complete_coverage(dict_or_empty(latest.get("gpt_pool_capacity"))):
            return latest
    return latest


def snapshot_age(snapshot):
    return max(0, now_ts() - int(snapshot.get("created_at", 0) or 0))

def snapshot_label(snapshot):
    age = snapshot_age(snapshot)
    return f"updated {age}s ago"

def http_service_status_lines(results=_UNSET):
    if results is _UNSET:
        results = check_http_services_detailed()
    if results is None:
        results = []
    return [
        result.get("line", f"- {result.get('name', 'service')}: unknown")
        for result in results
        if isinstance(result, dict)
    ]

def quota_attention_counts(snapshot):
    rows = list_or_empty(snapshot.get("quota_rows", []))
    disabled = [row for row in rows if row.get("status") == "disabled"]
    missing = [row for row in rows if row.get("status") == "missing"]
    high = [
        row for row in rows
        if row.get("status") == "active"
        and row.get("effective_percent") is not None
        and row.get("effective_percent") >= QUOTA_WARN_PERCENT
    ]
    top = sorted(rows, key=lambda row: int(row.get("daily_used", 0) or 0), reverse=True)
    return {
        "disabled": len(disabled),
        "missing": len(missing),
        "high": len(high),
        "top_alias": str((top[0] if top else {}).get("alias") or "none"),
        "top_tokens": int((top[0] if top else {}).get("daily_used", 0) or 0),
    }


def reauth_needed_count(snapshot):
    observation = dict_or_empty(dict_or_empty(snapshot).get("auth_quota_observation"))
    failed = {
        str(key or "").strip()
        for key in list_or_empty(observation.get("failed_identity_keys"))
        if str(key or "").strip()
    }
    return len(failed)


def finite_remaining(rows, limit_field, used_field):
    total = 0
    for row in rows:
        if row.get("status") != "active":
            continue
        limit = row.get(limit_field)
        if limit is None:
            continue
        total += max(0, int(limit or 0) - int(row.get(used_field, 0) or 0))
    return total


def finite_total(rows, limit_field):
    total = 0
    for row in rows:
        if row.get("status") != "active":
            continue
        limit = row.get(limit_field)
        if limit is None:
            continue
        total += int(limit or 0)
    return total


def percent_left(remaining, total):
    if not total:
        return None
    return max(0.0, min(100.0, float(remaining) * 100.0 / float(total)))



def weekly_cap_disabled_status_counts(rows):
    active = 0
    disabled = 0
    for row in rows:
        if row.get("weekly_limit") is not None:
            continue
        status = row.get("status")
        if status == "active":
            active += 1
        elif status in {"disabled", "manually_disabled"}:
            disabled += 1
    return active, disabled


def hours_until_week_end(tz_name="Asia/Ho_Chi_Minh"):
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone(timedelta(hours=7))
    now_local = datetime.now(tz)
    start_date = now_local.date() - timedelta(days=now_local.weekday())
    end_local = datetime.combine(start_date + timedelta(days=7), dtime.min, tzinfo=tz)
    return max(0.0, (end_local - now_local).total_seconds() / 3600)



def gpt_pool_enabled_count(pool):
    try:
        return int(dict_or_empty(pool).get("enabled_codex_count", 0) or 0)
    except (TypeError, ValueError):
        return 0


def gpt_pool_window_checked(pool, name):
    window = dict_or_empty(dict_or_empty(pool).get(name, {}))
    try:
        return int(window.get("checked_count", 0) or 0)
    except (TypeError, ValueError):
        return 0


def gpt_pool_quota_unavailable(pool):
    pool = dict_or_empty(pool)
    return bool(pool.get("error")) or gpt_pool_enabled_count(pool) <= 0


def gpt_pool_complete_coverage(pool):
    pool = dict_or_empty(pool)
    enabled = gpt_pool_enabled_count(pool)
    if enabled <= 0 or pool.get("error"):
        return False
    return (
        gpt_pool_window_checked(pool, "primary") == enabled
        and gpt_pool_window_checked(pool, "secondary") == enabled
    )


def gpt_pool_incomplete_coverage(pool):
    pool = dict_or_empty(pool)
    return not gpt_pool_quota_unavailable(pool) and not gpt_pool_complete_coverage(pool)


def gpt_pool_window_left_tokens(pool, name):
    window = dict_or_empty(dict_or_empty(pool).get(name, {}))
    try:
        return float(window.get("left_tokens"))
    except (TypeError, ValueError):
        return None


def gpt_pool_margin(left_tokens, need):
    if left_tokens is None or int(need or 0) <= 0:
        return None
    return float(left_tokens) / float(need)


def margin_text(value):
    if value is None:
        return "unavailable"
    return f"{float(value):.1f}x"


def fmt_token_equivalent(value):
    value = float(value or 0)
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(int(value))


GPT_POOL_5H_LOW_ALERT_ID = "capacity:gpt-pool-5h-low"
GPT_POOL_5H_ALERT_THRESHOLD = 0.8
GPT_POOL_5H_RECOVERY_THRESHOLD = 1.2


def empty_gpt_pool_5h_observation(reason=""):
    return {
        "complete": False if reason else True,
        "reason": str(reason or ""),
        "margin": None,
        "low": False,
        "recovered": False,
        "enabled_codex_count": 0,
        "primary_checked_count": 0,
        "secondary_checked_count": 0,
        "demand_tokens_5h": None,
    }


def gpt_pool_5h_observation(snapshot, rate):
    snapshot = dict_or_empty(snapshot)
    rate = dict_or_empty(rate)
    pool = dict_or_empty(snapshot.get("gpt_pool_capacity"))
    enabled = gpt_pool_enabled_count(pool)
    primary_checked = gpt_pool_window_checked(pool, "primary")
    secondary_checked = gpt_pool_window_checked(pool, "secondary")

    def incomplete(reason):
        observation = empty_gpt_pool_5h_observation(reason)
        observation.update({
            "enabled_codex_count": enabled,
            "primary_checked_count": primary_checked,
            "secondary_checked_count": secondary_checked,
        })
        return observation

    if gpt_pool_quota_unavailable(pool):
        return incomplete("quota-unavailable")
    if gpt_pool_incomplete_coverage(pool):
        return incomplete("incomplete-coverage")
    if rate.get("error"):
        return incomplete("demand-unavailable")
    try:
        hourly = float(rate.get("tokens_per_hour", 0) or 0)
    except (TypeError, ValueError):
        hourly = 0.0
    next_5h_need = int(hourly * 5)
    left_tokens = gpt_pool_window_left_tokens(pool, "primary")
    margin = gpt_pool_margin(left_tokens, next_5h_need)
    if margin is None:
        return incomplete("demand-unavailable")
    observation = empty_gpt_pool_5h_observation()
    observation.update({
        "margin": round(float(margin), 3),
        "low": float(margin) < GPT_POOL_5H_ALERT_THRESHOLD,
        "recovered": float(margin) >= GPT_POOL_5H_RECOVERY_THRESHOLD,
        "enabled_codex_count": enabled,
        "primary_checked_count": primary_checked,
        "secondary_checked_count": secondary_checked,
        "demand_tokens_5h": next_5h_need,
    })
    return observation


def gpt_pool_5h_margin_bucket(margin):
    if margin is None or margin >= GPT_POOL_5H_ALERT_THRESHOLD:
        return ""
    if margin < 0.5:
        return "critical-under-0.5"
    return "low-0.5-to-0.8"


def gpt_pool_5h_low_capacity_alert(snapshot, rate):
    snapshot = dict_or_empty(snapshot)
    rate = dict_or_empty(rate)
    pool = dict_or_empty(snapshot.get("gpt_pool_capacity"))
    if gpt_pool_incomplete_coverage(pool) or gpt_pool_quota_unavailable(pool) or rate.get("error"):
        return None
    hourly = float(rate.get("tokens_per_hour", 0) or 0)
    next_5h_need = int(hourly * 5)
    left_tokens = gpt_pool_window_left_tokens(pool, "primary")
    margin = gpt_pool_margin(left_tokens, next_5h_need)
    bucket = gpt_pool_5h_margin_bucket(margin)
    if not bucket:
        return None
    enabled = gpt_pool_enabled_count(pool)
    checked = gpt_pool_window_checked(pool, "primary")
    return Alert(
        alert_id=GPT_POOL_5H_LOW_ALERT_ID,
        severity="warning",
        title="GPT pool 5h capacity low",
        body="\n".join([
            f"- 5h pool left: {fmt_token_equivalent(left_tokens)} token-equivalent",
            f"- 5h demand: {fmt_tokens(next_5h_need)}",
            f"- 5h margin: {margin_text(margin)}",
            f"- Codex quota coverage: {checked}/{enabled}",
        ]),
        fingerprint=f"{bucket}:{enabled}",
    )


def clean_percent(value):
    value = float(value)
    if value.is_integer():
        return f"{int(value)}%"
    return f"{value:.1f}%"


def gpt_pool_window_lines(label, window, enabled_count):
    window = dict_or_empty(window)
    checked = int(window.get("checked_count", 0) or 0)
    avg = window.get("avg_left_percent")
    lowest = window.get("lowest_left_percent")
    left_tokens = window.get("left_tokens")
    if checked <= 0 or avg is None or lowest is None or left_tokens is None:
        return [f"- {label} avail: unavailable"]
    return [
        f"- {label} avail: {fmt_token_equivalent(left_tokens)}",
        f"(avg: {float(avg):.1f}%, lowest: {clean_percent(lowest)})",
    ]


def user_key_quota_line(label, remaining, total):
    if total <= 0:
        return f"- {label}: unavailable"
    left = percent_left(remaining, total)
    if left is None:
        return f"- {label}: unavailable"
    return f"- {label}: {fmt_tokens(remaining)} / {fmt_tokens(total)} ({left:.1f}%)"


def sentence_period(label):
    label = str(label or "").strip()
    if not label:
        return "updated unknown."
    return f"{label}."


def build_capacity_reply(snapshot: SnapshotPayload | dict[str, Any], rate: dict[str, Any] | None = None) -> str:
    """Render GPT pool capacity separately from user API key quota and demand forecast."""
    snapshot = dict_or_empty(snapshot)
    pool = dict_or_empty(snapshot.get("gpt_pool_capacity"))
    rows = list_or_empty(snapshot.get("quota_rows", []))
    daily_remaining = finite_remaining(rows, "daily_limit", "daily_used")
    weekly_remaining = finite_remaining(rows, "weekly_limit", "weekly_used")
    daily_total = finite_total(rows, "daily_limit")
    weekly_total = finite_total(rows, "weekly_limit")
    rate = rate or capacity_demand_rate_estimate()
    hourly = float(rate.get("tokens_per_hour", 0) or 0)
    next_5h_need = int(hourly * 5)
    week_hours = hours_until_week_end()
    week_need = int(hourly * week_hours)
    primary_margin = gpt_pool_margin(gpt_pool_window_left_tokens(pool, "primary"), next_5h_need)
    secondary_margin = gpt_pool_margin(gpt_pool_window_left_tokens(pool, "secondary"), week_need)
    age_label = snapshot_label(snapshot)
    lookback = rate.get("lookback_hours", rate.get("hours", 0))
    demand_suffix = str(rate.get("display_suffix") or f"{float(lookback or 0):g}h avg")
    if rate.get("error"):
        rate_line = "Demand rate: unavailable"
        projected_5h_line = "5h demand: unavailable"
        projected_week_line = "Weekly demand: unavailable"
    else:
        rate_line = f"Demand rate: {fmt_tokens(int(hourly))}/h ({demand_suffix})"
        projected_5h_line = f"5h demand: {fmt_tokens(next_5h_need)}"
        projected_week_line = f"Weekly demand: {fmt_tokens(week_need)}"

    enabled_codex_count = gpt_pool_enabled_count(pool)
    try:
        excluded_reauth_count = int(pool.get("excluded_reauth_count", 0) or 0)
    except (TypeError, ValueError):
        excluded_reauth_count = 0
    try:
        usable_codex_count = int(pool.get("usable_codex_count", enabled_codex_count) or 0)
    except (TypeError, ValueError):
        usable_codex_count = enabled_codex_count
    try:
        free_codex_count = int(pool.get("free_codex_count", 0) or 0)
    except (TypeError, ValueError):
        free_codex_count = 0
    codex_identity_lines = []
    identity_notes = []
    if free_codex_count > 0:
        identity_notes.append(f"{free_codex_count} free")
    if identity_notes or excluded_reauth_count > 0:
        codex_identity_lines.append(
            f"- Codex identities: {usable_codex_count} usable"
            + (", " + ", ".join(identity_notes) if identity_notes else "")
        )
    if gpt_pool_incomplete_coverage(pool):
        gpt_pool_lines = [
            (
                f"- Quota data updating: {gpt_pool_window_checked(pool, 'primary')}/{enabled_codex_count} with 5h data, "
                f"{gpt_pool_window_checked(pool, 'secondary')}/{enabled_codex_count} with weekly data"
            ),
            "- Tap Refresh after quota cache finishes updating",
        ]
    else:
        gpt_pool_lines = [
            *gpt_pool_window_lines("5h", pool.get("primary"), enabled_codex_count),
            *gpt_pool_window_lines("Weekly", pool.get("secondary"), enabled_codex_count),
        ]
        if gpt_pool_complete_coverage(pool):
            gpt_pool_lines.extend([
                f"- 5h margin: {margin_text(primary_margin)}",
                f"- Weekly margin: {margin_text(secondary_margin)}",
            ])

    pool_source = str(pool.get("source") or "usage_keeper")
    if pool_source == "management_fallback":
        gpt_pool_source_line = "- GPT pool uses management quota fallback data."
    else:
        gpt_pool_source_line = "- GPT pool uses Usage Keeper quota cache data."
    lines = [
        "Capacity Check",
        "",
        "Demand Forecast",
        f"- {rate_line}",
        f"- {projected_5h_line}",
        f"- {projected_week_line}",
        "",
        "GPT Pool Capacity",
        *codex_identity_lines,
        *gpt_pool_lines,
        "",
        "User Key Quota (Remaining)",
        user_key_quota_line("Daily", daily_remaining, daily_total),
        user_key_quota_line("Weekly", weekly_remaining, weekly_total),
        "",
        "Evidence",
        f"- Data: {sentence_period(age_label)}",
        f"- Quota sync: updated {snapshot.get('enforcer_age', 'unknown')} ago.",
        f"- Demand source: {sentence_period(rate.get('source_label') or 'local usage estimate')}",
        gpt_pool_source_line,
        "- GPT pool token-equivalent assumes 20M per 5h quota and 140M per weekly quota per codex account.",
    ]
    if rate.get("error"):
        lines.append(f"- Demand forecast unavailable: {rate['error']}")
    if snapshot.get("quota_error"):
        lines.append(f"- User key quota unavailable: {snapshot['quota_error']}")
    return "\n".join(lines)


def auth_type_from_file(path, data):
    value = ""
    if isinstance(data, dict):
        value = str(data.get("type") or "").strip().lower()
    if not value:
        value = path.stem.split("-", 1)[0].strip().lower()
    normalized = normalize_provider(value)
    if normalized in {"codex", "antigravity"}:
        return normalized
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", value or ""):
        return "unknown"
    return value


def auth_account_type_counts():
    counts = {}
    if not AUTH_DIR.exists():
        return counts
    for path in sorted(AUTH_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        account_type = auth_type_from_file(path, data)
        bucket = counts.setdefault(account_type, {"enabled": 0, "disabled": 0})
        if isinstance(data, dict) and bool(data.get("disabled")):
            bucket["disabled"] += 1
        else:
            bucket["enabled"] += 1
    return counts


def title_case_account_type(value):
    return provider_title_label(value)


def auth_account_overview_lines():
    counts = auth_account_type_counts()
    if not counts:
        return ["- None found"]
    return [
        f"- {title_case_account_type(account_type)}: {values['enabled']} enabled, {values['disabled']} disabled"
        for account_type, values in sorted(counts.items())
    ]


def auth_quota_ref(name):
    import hashlib
    from pathlib import Path
    return hashlib.sha256(f"auth-file:{Path(str(name or '')).name}".encode("utf-8")).hexdigest()[:16]


def management_label_email(value):
    raw = str(value or "").strip()
    if not raw:
        return ""
    match = re.search(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", raw)
    if not match:
        return ""
    label = match.group(0)
    lowered = label.lower()
    if any(marker in lowered for marker in ("secret", "token", "password", "bearer", "api_key", "api-key", "refresh_token", "access_token", "management_token", "cookie")):
        return ""
    if lowered.endswith(".test"):
        return ""
    return label


def safe_management_account_label(value):
    raw = str(value or "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    if "@" in raw or "/" in raw or "\\" in raw or lowered.endswith(".json"):
        return ""
    if re.search(r"(?i)(?:bearer|token|access[_-]?token|refresh[_-]?token|api[_-]?key|management[_-]?token|secret|password|cookie)", raw):
        return ""
    if re.fullmatch(r"(?i)sk-[A-Za-z0-9_-]{12,}", raw):
        return ""
    if len(raw) > 80:
        return ""
    return raw


def codex_auth_file_label(value):
    raw = Path(str(value or "")).name.strip()
    if raw.lower().endswith(".json"):
        raw = raw[:-5]
    raw = re.sub(r"(?i)-plus$", "", raw).strip()
    if not raw.lower().startswith("codex-"):
        return ""
    email = management_label_email(raw.split("-", 1)[1])
    if not email:
        return ""
    return f"codex-{email}"


def codex_email_label(value):
    email = management_label_email(value)
    if not email:
        return ""
    if email.lower().startswith("codex-"):
        return email
    return f"codex-{email}"


def auth_management_label(path, data):
    label = codex_auth_file_label(getattr(path, "name", "") or "")
    if label:
        return label
    data = dict_or_empty(data)
    for key in ("email", "account_email", "user_email"):
        label = codex_email_label(data.get(key))
        if label:
            return label
    for key in ("alias", "label", "account", "username", "name"):
        label = safe_management_account_label(data.get(key))
        if label:
            return label
    return f"codex ...{auth_quota_ref(path.name)[-4:]}"


def percent_label(value):
    if value is None:
        return "unavailable"
    value = float(value)
    if value.is_integer():
        return f"{int(value)}%"
    return f"{value:.1f}%"


def auth_quota_line(row):
    return f"5h avail: {percent_label(row.get('primary'))}, weekly avail: {percent_label(row.get('secondary'))}"


def auth_state_markers():
    state = load_json(QUOTA_STATE, {})
    markers = state.get("auth_weekly_auto_disabled") if isinstance(state, dict) else {}
    return markers if isinstance(markers, dict) else {}


def auth_file_rows():
    rows = []
    if not AUTH_DIR.exists():
        return rows
    markers = auth_state_markers()
    for path in sorted(AUTH_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not auth_file_is_codex_data(path, data):
            continue
        ref = auth_quota_ref(path.name)
        marker = markers.get(ref) if isinstance(markers, dict) else None
        label = auth_management_label(path, data)
        rows.append({
            "ref": ref,
            "label": label,
            "quota_match": label.lower(),
            "status": "disabled" if bool(data.get("disabled")) else "enabled",
            "auth_index": str((marker if isinstance(marker, dict) else {}).get("auth_index") or "").strip(),
        })
    return rows


def auth_file_is_codex_data(path, data):
    if not isinstance(data, dict):
        return False
    value = str(data.get("type") or "").strip().lower().replace("_", "-")
    if not value:
        value = path.stem.split("-", 1)[0].strip().lower().replace("_", "-")
    return value == "codex"


def auth_quota_match_key(value):
    label = codex_auth_file_label(value) or codex_email_label(value) or safe_management_account_label(value)
    return label.lower() if label else ""


def quota_left_from_cache_item(item):
    values = {}
    for row in health_module.quota_rows_from_cache_item(item):
        row = dict_or_empty(row)
        quota_key = str(row.get("key") or "").strip()
        window_name = ""
        for candidate, expected_key in health_module.GPT_POOL_QUOTA_KEYS.items():
            if quota_key == expected_key:
                window_name = candidate
                break
        if not window_name:
            continue
        used = health_module.used_percent_value(row)
        if used is not None:
            values[window_name] = max(0.0, min(100.0, 100.0 - float(used)))
    return values


def usage_keeper_auth_quota_left_by_ref(rows):
    if not health_module.USAGE_KEEPER_PASSWORD:
        return {}
    try:
        cookie = health_module.usage_keeper_session_cookie()
        if not cookie:
            return {}
        index_by_match = {}
        auth_indexes = []
        seen = set()
        page = 1
        while page <= 10:
            path = f"usage/identities/page?auth_type=1&active_only=true&page={page}&page_size={health_module.GPT_POOL_IDENTITY_PAGE_SIZE}"
            _, data, _ = health_module.usage_keeper_request(path, cookie=cookie)
            for item in health_module.payload_items(data):
                if not health_module.identity_is_enabled_codex(item):
                    continue
                auth_index = health_module.identity_quota_cache_index(item)
                if not auth_index or auth_index in seen:
                    continue
                seen.add(auth_index)
                auth_indexes.append(auth_index)
                item = dict_or_empty(item)
                for candidate in (auth_index, item.get("file_name"), item.get("filename"), item.get("name"), item.get("email"), item.get("identity")):
                    match_key = auth_quota_match_key(candidate)
                    if match_key:
                        index_by_match.setdefault(match_key, auth_index)
            if not isinstance(data, dict):
                break
            total_pages = int(data.get("totalPages") or data.get("total_pages") or 0)
            has_next = bool(data.get("hasNext") or data.get("has_next"))
            if total_pages:
                if page >= total_pages:
                    break
            elif not has_next:
                break
            page += 1
        if not auth_indexes:
            return {}
        _, data, _ = health_module.usage_keeper_request(
            "quota/cache",
            method="POST",
            payload={"auth_indexes": auth_indexes},
            cookie=cookie,
        )
        quota_by_index = {}
        for item in health_module.payload_items(data):
            auth_index = health_module.identity_quota_cache_index(item)
            if auth_index:
                quota = quota_left_from_cache_item(item)
                if quota:
                    quota_by_index[auth_index] = quota
        values = {}
        for row in list_or_empty(rows):
            if row.get("status") != "enabled":
                continue
            auth_index = row.get("auth_index") or index_by_match.get(str(row.get("quota_match") or "").lower())
            quota = quota_by_index.get(auth_index)
            if quota:
                values[row["ref"]] = quota
        return values
    except Exception:
        return {}


def management_auth_ref(item):
    item = dict_or_empty(item)
    for key in ("file_name", "filename", "name"):
        raw = str(item.get(key) or "").strip()
        if raw:
            return auth_quota_ref(raw)
    return ""


def auth_quota_left_for_index(auth_index):
    if not auth_index:
        return {}
    body = management_api_call_body(management_request(
        "api-call",
        method="POST",
        payload={
            "authIndex": auth_index,
            "method": "GET",
            "url": CODEX_WHAM_USAGE_URL,
            "header": dict(CODEX_WHAM_HEADERS),
        },
    ))
    values = {}
    for source, target in (("primary", "primary"), ("secondary", "secondary")):
        used = management_window_used_percent(body, source)
        if used is not None:
            values[target] = max(0.0, min(100.0, 100.0 - float(used)))
    return values


def auth_management_quota_left_by_ref(rows=None):
    rows = list_or_empty(rows) or auth_file_rows()
    values = usage_keeper_auth_quota_left_by_ref(rows)
    missing_enabled_rows = [
        row for row in rows
        if row.get("status") == "enabled" and row.get("ref") not in values
    ]
    for row in missing_enabled_rows:
        auth_index = row.get("auth_index")
        if not auth_index:
            continue
        try:
            quota = auth_quota_left_for_index(auth_index)
            if quota:
                values[row["ref"]] = quota
        except Exception:
            continue
    missing_refs = {
        row.get("ref") for row in missing_enabled_rows
        if row.get("ref") not in values
    }
    if not missing_refs:
        return values
    try:
        for item in management_auth_files(management_request("auth-files")):
            ref = management_auth_ref(item)
            if ref not in missing_refs:
                continue
            auth_index = identity_auth_index(item)
            if not ref or not auth_index:
                continue
            quota = auth_quota_left_for_index(auth_index)
            if quota:
                values[ref] = quota
    except Exception:
        pass
    return values


def build_quota_management_snapshot(cache_now=None):
    rows = auth_file_rows()
    quota_by_ref = auth_management_quota_left_by_ref(rows)
    for row in rows:
        row.update(quota_by_ref.get(row["ref"], {}))
    return {
        "created_at": int(cache_now if cache_now is not None else now_ts()),
        "quota_management_rows": rows,
    }


def get_quota_management_snapshot(state: dict[str, Any], live: bool = False) -> SnapshotPayload:
    snapshot = state.get("quota_management_snapshot")
    ts = now_ts()
    try:
        age = ts - int(dict_or_empty(snapshot).get("created_at", 0) or 0)
    except (TypeError, ValueError):
        age = QUOTA_MANAGEMENT_FAST_CACHE_SECONDS + 1
    if not live and isinstance(snapshot, dict) and age <= max(0, int(QUOTA_MANAGEMENT_FAST_CACHE_SECONDS or 0)):
        return snapshot
    snapshot = build_quota_management_snapshot(cache_now=ts)
    state["quota_management_snapshot"] = snapshot
    return snapshot


def build_quota_management_reply(snapshot):
    snapshot = dict_or_empty(snapshot)
    rows = list_or_empty(snapshot.get("quota_management_rows"))
    if not rows:
        rows = auth_file_rows()
        quota_by_ref = auth_management_quota_left_by_ref(rows)
        for row in rows:
            row.update(quota_by_ref.get(row["ref"], {}))
    enabled = [row for row in rows if row.get("status") == "enabled"]
    disabled = [row for row in rows if row.get("status") == "disabled"]
    lines = [
        "Quota Management",
        f"Data: {snapshot_label(snapshot)}",
        "",
        "Enabled Auth Accounts",
    ]
    if enabled:
        for index, row in enumerate(enabled, start=1):
            lines.append(f"{index}. {row['label']}")
            lines.append(f"({auth_quota_line(row)})")
    else:
        lines.append("- None")
    lines.extend(["", "Disabled Auth Accounts"])
    if disabled:
        lines.extend(f"{index}. {row['label']}" for index, row in enumerate(disabled, start=1))
    else:
        lines.append("- None")
    return "\n".join(lines)


def overview_service_line(line):
    raw = str(line or "").strip()
    match = re.match(r"^-\s*([^:]+):\s*(.*)$", raw)
    if not match:
        return raw
    names = {
        "cliproxy": "Cliproxy",
        "usage-keeper": "Usage Keeper",
        "quota-gate": "Quota Gate",
    }
    service = match.group(1).strip().lower()
    label = names.get(service, title_case_account_type(service))
    return f"- {label}: {match.group(2).strip()}"


def freshness_line(label):
    label = str(label or "").strip()
    if label.lower().startswith("updated "):
        return label[:1].upper() + label[1:]
    return label


def overview_duration(value):
    return re.sub(r"(?<=[a-z])(?=\d)", " ", fmt_duration(value))


def build_overview_reply(snapshot):
    alerts = snapshot.get("system_alerts", {})
    quota_signals = snapshot.get("quota_signals", {})
    critical = sum(1 for item in alerts.values() if item.get("severity") == "critical")
    warning = sum(1 for item in alerts.values() if item.get("severity") == "warning")
    quota_critical = sum(1 for item in quota_signals.values() if item.get("severity") == "critical")
    quota_warning = sum(1 for item in quota_signals.values() if item.get("severity") == "warning")
    quota_counts = quota_attention_counts(snapshot)
    reauth_count = reauth_needed_count(snapshot)
    needs_attention_lines = []
    if alerts:
        needs_attention_lines.append(f"- Health alerts: {len(alerts)} ({critical} critical, {warning} warning)")
    if reauth_count > 0:
        needs_attention_lines.append(f"- Reauth needed: {reauth_count}")
    if quota_counts["disabled"] > 0:
        needs_attention_lines.append(f"- Disabled keys: {quota_counts['disabled']}")
    lines = [
        "System Overview",
        "",
        "Health",
        *(overview_service_line(line) for line in snapshot.get("service_lines", [])),
    ]
    if needs_attention_lines:
        lines.extend(["", "Needs Attention", *needs_attention_lines])
    lines.extend([
        "",
        "Auth Accounts",
        *auth_account_overview_lines(),
        "",
        "Data Freshness",
        f"- {freshness_line(snapshot_label(snapshot))}",
        f"- Quota Enforcer log: updated {snapshot.get('enforcer_age', 'unknown')} ago",
        f"- Bot uptime: {overview_duration(now_ts() - BOT_STARTED_AT)}",
    ])
    return "\n".join(lines)

def alert_display_title_from_mapping(alert):
    alert_id = str(alert.get("alert_id") or "")
    if alert_id == "capacity:gpt-pool-5h-low":
        return "GPT Pool 5h Capacity Low"
    if alert_id == "auth:quota-inspection-unavailable":
        return "Proxy Auth Inspection Unavailable"
    if alert_id == "auth:quota-inspection-failed":
        return str(alert.get("title") or "Proxy accounts need reauth")
    return str(alert.get("title") or "")


def build_alerts_reply(snapshot):
    alerts = snapshot.get("system_alerts", {})
    if not alerts:
        return "\n".join([
            "Health Alerts",
            f"Data: {snapshot_label(snapshot)}",
            "No active health alerts.",
            "",
            "Checked:",
            "- API health",
            "- Usage Keeper health",
            "- Quota Gate health",
            "- Quota enforcer freshness",
            "- Usage DB WAL size",
            "- Proxy auth quota inspection",
        ])
    ordered = sorted(alerts.values(), key=lambda item: (item.get("severity") != "critical", item.get("title", "")))
    lines = [
        "Health Alerts",
        f"Data: {snapshot_label(snapshot)}",
        f"{len(ordered)} active health alert(s)",
        "",
    ]
    for alert in ordered[:20]:
        lines.append(f"{severity_icon(alert.get('severity'))} {alert_display_title_from_mapping(alert)}")
    if len(ordered) > 20:
        lines.append(f"... and {len(ordered) - 20} more")
    return "\n".join(lines)

def filter_quota_rows(rows, query):
    query = str(query or "").strip().lower()
    if not query:
        return rows
    return [
        row for row in rows
        if query in str(row.get("alias", "")).lower()
        or query in str(row.get("name", "")).lower()
        or query in str(row.get("status", "")).lower()
    ]

def build_quota_reply(snapshot, all_accounts=False, query=""):
    if snapshot.get("quota_error"):
        return f"{ALERT_HOSTNAME}: quota data unavailable: {snapshot['quota_error']}"
    all_rows = filter_quota_rows(list(snapshot.get("quota_rows", [])), query)
    rows = list(all_rows)
    if not all_accounts:
        rows = [
            row for row in rows
            if row["status"] != "active"
            or (row["effective_percent"] is not None and row["effective_percent"] >= QUOTA_WARN_PERCENT)
        ]
    rows = rows[:25]
    if not rows:
        if query:
            return f"{ALERT_HOSTNAME}: no quota rows matched '{query}'."
        disabled = sum(1 for row in all_rows if row.get("status") == "disabled")
        missing = sum(1 for row in all_rows if row.get("status") == "missing")
        high = sum(
            1 for row in all_rows
            if row.get("status") == "active"
            and row.get("effective_percent") is not None
            and row.get("effective_percent") >= QUOTA_WARN_PERCENT
        )
        return "\n".join([
            "No quota warnings.",
            "",
            "Checked:",
            f"- Disabled by quota: {disabled}",
            f"- Over {QUOTA_WARN_PERCENT:.0f}% daily/weekly: {high}",
            f"- Missing from proxy config: {missing}",
            "",
            "Use Usage for per-account details.",
        ])
    title = f"{ALERT_HOSTNAME} quota"
    if query:
        title += f" for '{query}'"
    title += f" ({snapshot_label(snapshot)})"
    lines = [title, ""]
    for row in rows:
        daily = "unlimited" if row["daily_limit"] is None else f"{fmt_tokens(row['daily_used'])}/{fmt_tokens(row['daily_limit'])}"
        weekly = "cap disabled" if row["weekly_limit"] is None else f"{fmt_tokens(row['weekly_used'])}/{fmt_tokens(row['weekly_limit'])}"
        suffix = ""
        if row["effective_percent"] is not None:
            suffix = f" ({row['effective_percent']:.1f}%)"
        lines.append(f"- {row['alias']} [{row['status']}]{suffix}: daily {daily}, weekly {weekly}")
    return "\n".join(lines)
def safe_key_status_label(row):
    for field in ("alias", "name"):
        value = str(row.get(field) or "").strip()
        lowered = value.lower()
        if not value:
            continue
        if "@" in value or "/" in value or "\\" in value:
            continue
        if lowered.endswith(".json") or lowered.startswith("sk-") or "secret" in lowered:
            continue
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
            return value
    return "key"



def disabled_key_status_line(row):
    status = str(row.get("status") or "")
    reason = "manually disabled" if status == "manually_disabled" else "quota exceeded"
    return f"- {safe_key_status_label(row)} ({reason})"


def build_key_status_reply(snapshot):
    if snapshot.get("quota_error"):
        return f"{ALERT_HOSTNAME}: quota data unavailable: {snapshot['quota_error']}"
    rows = list_or_empty(snapshot.get("quota_rows", []))
    disabled = [row for row in rows if row["status"] in {"disabled", "manually_disabled"}]
    missing = [row for row in rows if row["status"] == "missing"]
    active = [row for row in rows if row["status"] == "active"]
    weekly_cap_disabled_active_count, weekly_cap_disabled_disabled_count = weekly_cap_disabled_status_counts(rows)
    lines = [
        "Key Status",
        f"Data: {snapshot_label(snapshot)}",
        "",
        "Summary",
        f"- Active keys: {len(active)}",
        f"- Disabled keys: {len(disabled)}",
        f"- Missing from config: {len(missing)}",
        f"- Uncapped weekly: {weekly_cap_disabled_active_count} active, {weekly_cap_disabled_disabled_count} disabled",
    ]
    if disabled:
        lines.extend(["", "Disabled Keys"])
        lines.extend(disabled_key_status_line(row) for row in disabled)
    return "\n".join(lines)


def build_top_reply(snapshot):
    if snapshot.get("quota_error"):
        return f"{ALERT_HOSTNAME}: quota data unavailable: {snapshot['quota_error']}"
    rows = sorted(
        snapshot.get("quota_rows", []),
        key=lambda row: row.get("daily_used", 0),
        reverse=True,
    )[:10]
    if not rows:
        return f"{ALERT_HOSTNAME}: no quota rows available."
    lines = ["Top Users", f"Data: {snapshot_label(snapshot)}", ""]
    for row in rows:
        daily = "unlimited" if row["daily_limit"] is None else f"{fmt_tokens(row['daily_used'])}/{fmt_tokens(row['daily_limit'])}"
        lines.append(f"- {row['alias']} [{row['status']}]: {daily}")
    return "\n".join(lines)
