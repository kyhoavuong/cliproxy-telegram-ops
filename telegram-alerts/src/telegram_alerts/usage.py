"""Usage Keeper SQLite readers for per-account and aggregate Telegram reports."""

from __future__ import annotations
from typing import Any
from .contracts import UsageBreakdown, UsageBucket, UsageModelRow

import sqlite3
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .settings import USAGE_DB, USAGE_REPORT_CACHE_SECONDS
from .utils import fmt_tokens, log_timing, mask_key, monotonic_ms, now_ts, percent
from .quota_config import load_cpa_alias_map, load_quota_data, window_utc

_usage_breakdown_cache = {}

def usage_accounts_for_picker():
    started = monotonic_ms()
    accounts = []
    seen = set()
    tz_name, items, disabled, config_keys = load_quota_data()
    quota_by_key = {
        str(item.get("key", "")).strip(): item
        for item in items
        if str(item.get("key", "")).strip()
    }
    # Match CPA Usage Keeper's active key list: aliases come from cpa_api_keys
    # where is_deleted=0. Quota/config data is only joined in for limits/status.
    for key, alias in load_cpa_alias_map().items():
        key = str(key or "").strip()
        if not key or key in seen:
            continue
        item = quota_by_key.get(key) or {}
        if key in disabled:
            status = "disabled"
        elif item.get("manually_disabled"):
            status = "manually_disabled"
        elif config_keys and key in config_keys:
            status = "active"
        elif item:
            status = "missing"
        else:
            status = "cpa-only"
        accounts.append({
            "key": key,
            "alias": str(alias or key[:8]).strip() or key[:8],
            "daily": item.get("daily_token_limit"),
            "weekly": item.get("weekly_token_limit"),
            "status": status,
            "masked": mask_key(key),
        })
        seen.add(key)
    accounts.sort(key=lambda item: item["alias"].lower())
    log_timing("usage_accounts_for_picker", started, accounts=len(accounts))
    return tz_name, accounts

def empty_usage_bucket() -> UsageBucket:
    """Return the zeroed daily/weekly usage bucket shape used by reports and cache entries."""
    return {
        "total_tokens": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
        "cached_tokens": 0,
        "cache_read_tokens": 0,
        "cache_creation_tokens": 0,
        "requests": 0,
        "failed": 0,
        "models": [],
        "fallback_trim": False,
    }

def usage_window_strings(tz_name, kind):
    start_utc, end_utc = window_utc(tz_name, kind)
    return start_utc.strftime("%Y-%m-%d %H:%M:%S"), end_utc.strftime("%Y-%m-%d %H:%M:%S")

def query_usage_models(conn, api_key, start_s, end_s, trim_key=False):
    key_predicate = "TRIM(api_group_key) = ?" if trim_key else "api_group_key = ?"
    sql = f"""
        SELECT
          COALESCE(NULLIF(model_alias, ''), NULLIF(model, ''), 'unknown') AS model_name,
          COUNT(*) AS requests,
          COALESCE(SUM(CASE WHEN COALESCE(failed, 0) != 0 THEN 1 ELSE 0 END), 0) AS failed,
          COALESCE(SUM(input_tokens), 0) AS input_tokens,
          COALESCE(SUM(output_tokens), 0) AS output_tokens,
          COALESCE(SUM(reasoning_tokens), 0) AS reasoning_tokens,
          COALESCE(SUM(cached_tokens), 0) AS cached_tokens,
          COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens,
          COALESCE(SUM(cache_creation_tokens), 0) AS cache_creation_tokens,
          COALESCE(SUM(total_tokens), 0) AS total_tokens
        FROM usage_events
        WHERE {key_predicate}
          AND datetime(timestamp) >= datetime(?)
          AND datetime(timestamp) < datetime(?)
        GROUP BY model_name
        ORDER BY total_tokens DESC
    """
    rows = []
    for row in conn.execute(sql, (api_key, start_s, end_s)):
        rows.append({
            "model": str(row[0] or "unknown"),
            "requests": int(row[1] or 0),
            "failed": int(row[2] or 0),
            "input_tokens": int(row[3] or 0),
            "output_tokens": int(row[4] or 0),
            "reasoning_tokens": int(row[5] or 0),
            "cached_tokens": int(row[6] or 0),
            "cache_read_tokens": int(row[7] or 0),
            "cache_creation_tokens": int(row[8] or 0),
            "total_tokens": int(row[9] or 0),
        })
    return rows

def summarize_usage_models(models: list[UsageModelRow] | list[dict[str, Any]], fallback_trim: bool = False) -> UsageBucket:
    """Fold per-model rows into one usage bucket while preserving the original model list.
    
    The fallback_trim flag records whether historical rows matched only after trimming
    api_group_key whitespace."""
    bucket = empty_usage_bucket()
    bucket["fallback_trim"] = bool(fallback_trim)
    bucket["models"] = models
    for model in models:
        bucket["total_tokens"] += int(model.get("total_tokens", 0) or 0)
        bucket["input_tokens"] += int(model.get("input_tokens", 0) or 0)
        bucket["output_tokens"] += int(model.get("output_tokens", 0) or 0)
        bucket["reasoning_tokens"] += int(model.get("reasoning_tokens", 0) or 0)
        bucket["cached_tokens"] += int(model.get("cached_tokens", 0) or 0)
        bucket["cache_read_tokens"] += int(model.get("cache_read_tokens", 0) or 0)
        bucket["cache_creation_tokens"] += int(model.get("cache_creation_tokens", 0) or 0)
        bucket["requests"] += int(model.get("requests", 0) or 0)
        bucket["failed"] += int(model.get("failed", 0) or 0)
    return bucket

def get_usage_breakdown_for_key(api_key: str, tz_name: str) -> UsageBreakdown:
    """Return cached daily and weekly per-model usage buckets for one key.
    
    The cache key includes the current daily/weekly window starts, and query results
    merge trimmed-key historical rows without double-counting exact matches."""
    started = monotonic_ms()
    cache_ttl = max(0, int(USAGE_REPORT_CACHE_SECONDS or 0))
    daily_start, _ = usage_window_strings(tz_name, "daily")
    weekly_start, _ = usage_window_strings(tz_name, "weekly")
    cache_key = (str(api_key or ""), str(tz_name or ""), daily_start, weekly_start)
    cached = _usage_breakdown_cache.get(cache_key)
    if cache_ttl and isinstance(cached, dict) and now_ts() - int(cached.get("created_at", 0) or 0) <= cache_ttl:
        result = cached.get("result")
        if isinstance(result, dict):
            log_timing("usage_breakdown", started, cached=1)
            return result

    result = {"daily": empty_usage_bucket(), "weekly": empty_usage_bucket()}
    conn = sqlite3.connect(f"file:{USAGE_DB}?mode=ro", uri=True, timeout=4)
    try:
        for kind in ("daily", "weekly"):
            start_s, end_s = usage_window_strings(tz_name, kind)
            models = query_usage_models(conn, api_key, start_s, end_s, trim_key=False)
            trim_models = query_usage_models(conn, api_key, start_s, end_s, trim_key=True)
            exact_by_model = {model["model"]: model for model in models}
            fallback_trim = False
            for trim_model in trim_models:
                exact_model = exact_by_model.get(trim_model["model"])
                if exact_model:
                    for field in ("requests", "failed", "input_tokens", "output_tokens", "reasoning_tokens", "cached_tokens", "cache_read_tokens", "cache_creation_tokens", "total_tokens"):
                        trim_value = int(trim_model.get(field, 0) or 0)
                        exact_value = int(exact_model.get(field, 0) or 0)
                        if trim_value > exact_value:
                            exact_model[field] = trim_value
                            fallback_trim = True
                else:
                    models.append(trim_model)
                    fallback_trim = True
            models.sort(key=lambda item: int(item.get("total_tokens", 0) or 0), reverse=True)
            result[kind] = summarize_usage_models(models, fallback_trim=fallback_trim)
    finally:
        conn.close()
    if cache_ttl:
        _usage_breakdown_cache.clear()
        _usage_breakdown_cache[cache_key] = {"created_at": now_ts(), "result": result}
    log_timing(
        "usage_breakdown",
        started,
        cached=0,
        daily_requests=result["daily"].get("requests", 0),
        weekly_requests=result["weekly"].get("requests", 0),
        fallback_trim=int(result["daily"].get("fallback_trim") or result["weekly"].get("fallback_trim") or 0),
    )
    return result

def usage_rate_estimate(lookback_hours: float = 3) -> dict[str, Any]:
    """Estimate recent global token rate for capacity forecasting.
    
    Failures are returned as source=unavailable with an error string so capacity UI can
    still render a Watch recommendation instead of raising."""
    hours = max(0.25, float(lookback_hours or 3))
    try:
        tz_name = local_tz_name() if "local_tz_name" in globals() else "Asia/Ho_Chi_Minh"
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = timezone(timedelta(hours=7))
        end_utc = datetime.now(tz).astimezone(timezone.utc)
        start_utc = end_utc - timedelta(hours=hours)
        if not USAGE_DB.exists():
            raise FileNotFoundError(f"missing usage db: {USAGE_DB}")
        conn = sqlite3.connect(f"file:{USAGE_DB}?mode=ro", uri=True, timeout=4)
        try:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(total_tokens), 0), COUNT(*)
                FROM usage_events
                WHERE datetime(timestamp) >= datetime(?)
                  AND datetime(timestamp) < datetime(?)
                """,
                (start_utc.strftime("%Y-%m-%d %H:%M:%S"), end_utc.strftime("%Y-%m-%d %H:%M:%S")),
            ).fetchone()
        finally:
            conn.close()
        tokens = int((row or [0])[0] or 0)
        requests = int((row or [0, 0])[1] or 0)
        return {
            "tokens": tokens,
            "requests": requests,
            "hours": hours,
            "tokens_per_hour": tokens / hours if hours else 0,
            "lookback_hours": hours,
            "source": "recent",
            "error": "",
        }
    except Exception as exc:
        return {
            "tokens": 0,
            "requests": 0,
            "hours": hours,
            "tokens_per_hour": 0,
            "lookback_hours": hours,
            "source": "unavailable",
            "error": str(exc),
        }


def realtime_token_velocity_rate(window: str = "60m") -> dict[str, Any]:
    """Return aggregate Usage Keeper realtime token velocity for Capacity Check.

    Usage Keeper reports tokens_per_minute as a rate. Average valid bucket rates
    and multiply by 60 to get tokens/hour; do not sum rate fields as tokens.
    """
    from . import health as health_module

    window = str(window or "60m").strip() or "60m"
    if window not in {"15m", "30m", "60m"}:
        window = "60m"
    if not health_module.USAGE_KEEPER_PASSWORD:
        return {"error": "Usage Keeper realtime unavailable"}
    try:
        cookie = health_module.usage_keeper_session_cookie()
        if not cookie:
            return {"error": "Usage Keeper realtime unavailable"}
        status, data, _ = health_module.usage_keeper_request(
            f"usage/overview/realtime?window={window}",
            cookie=cookie,
        )
        if int(status or 0) >= 400 or not isinstance(data, dict):
            return {"error": "Usage Keeper realtime unavailable"}
        buckets = data.get("token_velocity")
        if not isinstance(buckets, list):
            return {"error": "Usage Keeper realtime unavailable"}
        rates = []
        for bucket in buckets:
            if not isinstance(bucket, dict):
                continue
            try:
                rate = float(bucket.get("tokens_per_minute"))
            except (TypeError, ValueError):
                continue
            if rate < 0:
                continue
            rates.append(rate)
        if not rates:
            return {"error": "Usage Keeper realtime unavailable"}
        tokens_per_minute = sum(rates) / len(rates)
        tokens_per_hour = tokens_per_minute * 60.0
        return {
            "tokens": int(tokens_per_hour),
            "requests": 0,
            "hours": 1.0,
            "tokens_per_hour": tokens_per_hour,
            "lookback_hours": 1.0,
            "source": "usage_keeper_realtime",
            "source_label": f"Usage Keeper realtime {window}",
            "display_suffix": f"{window} realtime",
            "window": window,
            "error": "",
        }
    except Exception:
        return {"error": "Usage Keeper realtime unavailable"}


def local_usage_rate_with_source() -> dict[str, Any]:
    rate = dict(usage_rate_estimate())
    rate.setdefault("source_label", "local usage estimate")
    return rate


def capacity_demand_rate_estimate(window: str = "60m") -> dict[str, Any]:
    realtime = realtime_token_velocity_rate(window=window)
    if isinstance(realtime, dict) and not realtime.get("error"):
        return realtime
    return local_usage_rate_with_source()


def format_usage_limit_line(used, limit, no_cap_label="unlimited"):
    used = int(used or 0)
    if limit is None:
        return f"{fmt_tokens(used)} / {no_cap_label}"
    limit = int(limit or 0)
    pct = percent(used, limit) or 0
    return f"{fmt_tokens(used)} / {fmt_tokens(limit)} ({pct:.1f}%)"

def usage_cache_tokens(row):
    return int(row.get("cached_tokens", 0) or 0) + int(row.get("cache_read_tokens", 0) or 0) + int(row.get("cache_creation_tokens", 0) or 0)

def format_model_lines(models, max_models=6):
    if not models:
        return ["- No usage"]
    lines = []
    for model in models[:max_models]:
        lines.append(f"- {model.get('model', 'unknown')}: {fmt_tokens(model.get('total_tokens', 0))}")
        lines.append(
            f"+ In {fmt_tokens(model.get('input_tokens', 0))}, "
            f"out {fmt_tokens(model.get('output_tokens', 0))}"
        )
        lines.append(
            f"+ Cache {fmt_tokens(usage_cache_tokens(model))}, "
            f"reasoning {fmt_tokens(model.get('reasoning_tokens', 0))}"
        )
    if len(models) > max_models:
        lines.append(f"... and {len(models) - max_models} more model(s)")
    return lines

def build_usage_report(account, usage, tz_name):
    daily = usage.get("daily", empty_usage_bucket())
    weekly = usage.get("weekly", empty_usage_bucket())
    status = account.get("status") or "unknown"
    lines = [
        f"Usage: {account.get('alias') or 'unknown'}",
        f"Status: {status}",
        "",
        "Today",
        f"- Used: {format_usage_limit_line(daily.get('total_tokens', 0), account.get('daily'))}",
        f"- Requests: {int(daily.get('requests', 0)):,}, failed: {int(daily.get('failed', 0)):,}",
        "",
        "Models today",
        *format_model_lines(daily.get("models", [])),
        "",
        "This week",
        f"- Used: {format_usage_limit_line(weekly.get('total_tokens', 0), account.get('weekly'), 'unlimited')}",
        f"- Requests: {int(weekly.get('requests', 0)):,}, failed: {int(weekly.get('failed', 0)):,}",
        "",
        "Models week",
        *format_model_lines(weekly.get("models", [])),
    ]
    if daily.get("fallback_trim") or weekly.get("fallback_trim"):
        lines.extend(["", "Note: matched historical records with trimmed key text."])
    return "\n".join(lines)

def usage_key_chunks(keys, size=500):
    keys = list(keys)
    for index in range(0, len(keys), max(1, int(size or 1))):
        yield keys[index:index + max(1, int(size or 1))]

def apply_usage_rows(usage, rows, merge=False):
    for row in rows:
        key = str(row[0] or "").strip()
        if key not in usage:
            continue
        if merge:
            usage[key]["daily_tokens"] += int(row[1] or 0)
            usage[key]["daily_requests"] += int(row[2] or 0)
            usage[key]["weekly_tokens"] += int(row[3] or 0)
            usage[key]["weekly_requests"] += int(row[4] or 0)
        else:
            usage[key]["daily_tokens"] = int(row[1] or 0)
            usage[key]["daily_requests"] = int(row[2] or 0)
            usage[key]["weekly_tokens"] = int(row[3] or 0)
            usage[key]["weekly_requests"] = int(row[4] or 0)

def get_usage_for_items(items: list[dict[str, Any]], tz_name: str) -> dict[str, dict[str, int]]:
    """Aggregate daily and weekly usage totals for quota-managed keys.
    
    Queries run in bounded chunks and merge trimmed-key fallback rows so older records
    remain visible without double-counting exact matches."""
    started = monotonic_ms()
    keys = [str(item.get("key", "")).strip() for item in items if str(item.get("key", "")).strip()]
    usage = {key: {"daily_tokens": 0, "daily_requests": 0, "weekly_tokens": 0, "weekly_requests": 0} for key in keys}
    if not keys:
        return usage
    if not USAGE_DB.exists():
        raise FileNotFoundError(f"missing usage db: {USAGE_DB}")

    daily_start, daily_end = usage_window_strings(tz_name, "daily")
    weekly_start, weekly_end = usage_window_strings(tz_name, "weekly")

    conn = sqlite3.connect(f"file:{USAGE_DB}?mode=ro", uri=True, timeout=4)
    try:
        for chunk in usage_key_chunks(keys):
            placeholders = ",".join("?" for _ in chunk)
            rows = list(conn.execute(
                f"""
                SELECT
                  api_group_key,
                  COALESCE(SUM(CASE WHEN datetime(timestamp) >= datetime(?) AND datetime(timestamp) < datetime(?) THEN total_tokens ELSE 0 END), 0) AS daily_tokens,
                  COALESCE(SUM(CASE WHEN datetime(timestamp) >= datetime(?) AND datetime(timestamp) < datetime(?) THEN 1 ELSE 0 END), 0) AS daily_requests,
                  COALESCE(SUM(total_tokens), 0) AS weekly_tokens,
                  COUNT(*) AS weekly_requests
                FROM usage_events
                WHERE api_group_key IN ({placeholders})
                  AND datetime(timestamp) >= datetime(?)
                  AND datetime(timestamp) < datetime(?)
                GROUP BY api_group_key
                """,
                (daily_start, daily_end, daily_start, daily_end, *chunk, weekly_start, weekly_end),
            ))
            apply_usage_rows(usage, rows)

        # Some historical rows have whitespace around api_group_key. Merge a
        # TRIM() fallback without double-counting exact matches so old usage is
        # still visible in Telegram reports.
        fallback_used = 0
        for chunk in usage_key_chunks(keys):
            placeholders = ",".join("?" for _ in chunk)
            rows = list(conn.execute(
                f"""
                SELECT
                  TRIM(api_group_key) AS key,
                  COALESCE(SUM(CASE WHEN datetime(timestamp) >= datetime(?) AND datetime(timestamp) < datetime(?) THEN total_tokens ELSE 0 END), 0) AS daily_tokens,
                  COALESCE(SUM(CASE WHEN datetime(timestamp) >= datetime(?) AND datetime(timestamp) < datetime(?) THEN 1 ELSE 0 END), 0) AS daily_requests,
                  COALESCE(SUM(total_tokens), 0) AS weekly_tokens,
                  COUNT(*) AS weekly_requests
                FROM usage_events
                WHERE TRIM(api_group_key) IN ({placeholders})
                  AND api_group_key NOT IN ({placeholders})
                  AND datetime(timestamp) >= datetime(?)
                  AND datetime(timestamp) < datetime(?)
                GROUP BY TRIM(api_group_key)
                """,
                (daily_start, daily_end, daily_start, daily_end, *chunk, *chunk, weekly_start, weekly_end),
            ))
            apply_usage_rows(usage, rows, merge=True)
            fallback_used += len(rows)
    finally:
        conn.close()

    log_timing("get_usage_for_items", started, keys=len(keys), fallback_rows=fallback_used)
    return usage
