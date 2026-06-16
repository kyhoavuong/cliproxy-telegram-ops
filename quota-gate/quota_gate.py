
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
}

def filtered_headers(headers):
    return {
        k: v
        for k, v in headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }

#!/usr/bin/env python3
import asyncio
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta, time as dtime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from aiohttp import ClientConnectionError, ClientPayloadError, ClientSession, ClientTimeout, ServerDisconnectedError, web

BASE_DIR = Path(os.environ.get("CLIPROXY_BASE_DIR", "/opt/cliproxy"))
QUOTAS = BASE_DIR / "quota-enforcer" / "quotas.json"
STATE = BASE_DIR / "quota-enforcer" / "state.json"
DB = BASE_DIR / "usage-keeper" / "app.db"

UPSTREAM = os.environ.get("UPSTREAM_URL", "http://cliproxy:3000").rstrip("/")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8081"))
MISSING = object()

SKIP_QUOTA_PREFIXES = (
    "/quota",
    "/healthz",
    "/keep-alive",
    "/anthropic/callback",
    "/codex/callback",
    "/google/callback",
    "/antigravity/callback",
    "/favicon",
)

# Dashboard and management surfaces should not be exposed by quota-gate when
# it is deployed as a full reverse proxy fallback.
BLOCKED_PROXY_PREFIXES = (
    "/v0/management",
    "/management.html",
    "/usage",
)

_cache = {
    "loaded_at": 0.0,
    "quotas_mtime": None,
    "state_mtime": None,
    "data": None,
}


def now_ts():
    return time.time()


def load_json(path, default):
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def normalize_limit(value):
    if value is None:
        return None
    try:
        limit = int(value)
    except (TypeError, ValueError):
        return None
    return limit if limit > 0 else None


def mask_key(key):
    key = str(key or "").strip()
    if len(key) <= 14:
        return key[:3] + "***" + key[-3:]
    return key[:6] + "***" + key[-6:]


def load_quota_data():
    qm = QUOTAS.stat().st_mtime if QUOTAS.exists() else None
    sm = STATE.stat().st_mtime if STATE.exists() else None

    if (
        _cache["data"] is not None
        and _cache["quotas_mtime"] == qm
        and _cache["state_mtime"] == sm
        and now_ts() - _cache["loaded_at"] < 2
    ):
        return _cache["data"]

    quotas = load_json(QUOTAS, {})
    state = load_json(STATE, {})

    timezone_name = quotas.get("timezone", "Asia/Ho_Chi_Minh")
    items = quotas.get("keys", [])
    by_key = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key", "")).strip()
        if not key:
            continue
        daily_limit = normalize_limit(item.get("daily_token_limit"))
        weekly_raw = item.get("weekly_token_limit", MISSING)
        if weekly_raw is MISSING:
            weekly_limit = daily_limit * 4 if daily_limit is not None else None
        else:
            weekly_limit = normalize_limit(weekly_raw)
        by_key[key] = {
            "name": str(item.get("name") or key[-8:]),
            "key": key,
            "daily_token_limit": daily_limit,
            "weekly_token_limit": weekly_limit,
        }

    disabled_raw = state.get("disabled_by_quota", [])
    disabled = set()
    if isinstance(disabled_raw, list):
        for item in disabled_raw:
            if isinstance(item, str):
                disabled.add(item)
            elif isinstance(item, dict) and item.get("key"):
                disabled.add(str(item["key"]))

    data = {
        "timezone": timezone_name,
        "by_key": by_key,
        "disabled": disabled,
    }

    _cache.update({
        "loaded_at": now_ts(),
        "quotas_mtime": qm,
        "state_mtime": sm,
        "data": data,
    })
    return data


def extract_api_key(request):
    auth = request.headers.get("Authorization", "").strip()
    if auth:
        parts = auth.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        return auth

    for header in ("X-Api-Key", "X-Goog-Api-Key"):
        value = request.headers.get(header, "").strip()
        if value:
            return value

    qs = parse_qs(request.query_string or "")
    for name in ("key", "auth_token"):
        vals = qs.get(name)
        if vals and vals[0].strip():
            return vals[0].strip()

    return ""


def today_window_utc(tz_name):
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone(timedelta(hours=7))

    now_local = datetime.now(tz)
    start_local = datetime.combine(now_local.date(), dtime.min, tzinfo=tz)
    reset_local = datetime.combine(now_local.date() + timedelta(days=1), dtime.min, tzinfo=tz)

    return (
        start_local.astimezone(timezone.utc),
        reset_local.astimezone(timezone.utc),
        reset_local,
    )


def week_window_utc(tz_name):
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone(timedelta(hours=7))

    now_local = datetime.now(tz)
    start_date = now_local.date() - timedelta(days=now_local.weekday())
    start_local = datetime.combine(start_date, dtime.min, tzinfo=tz)
    reset_local = datetime.combine(start_date + timedelta(days=7), dtime.min, tzinfo=tz)

    return (
        start_local.astimezone(timezone.utc),
        reset_local.astimezone(timezone.utc),
        reset_local,
    )


def usage_for_key_window(con, key, start_utc, end_utc):
    start_s = start_utc.strftime("%Y-%m-%d %H:%M:%S")
    end_s = end_utc.strftime("%Y-%m-%d %H:%M:%S")

    row = con.execute(
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

    return int(row[0] or 0), int(row[1] or 0)


def usage_for_key(key, tz_name):
    today_start, today_end, daily_reset_local = today_window_utc(tz_name)
    week_start, week_end, weekly_reset_local = week_window_utc(tz_name)

    if not DB.exists():
        return {
            "today_tokens": 0,
            "requests_today": 0,
            "daily_reset_at": daily_reset_local.isoformat(),
            "week_tokens": 0,
            "requests_week": 0,
            "weekly_reset_at": weekly_reset_local.isoformat(),
            "db_available": False,
        }

    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=2)
    try:
        today_tokens, requests_today = usage_for_key_window(con, key, today_start, today_end)
        week_tokens, requests_week = usage_for_key_window(con, key, week_start, week_end)
    finally:
        con.close()

    return {
        "today_tokens": today_tokens,
        "requests_today": requests_today,
        "daily_reset_at": daily_reset_local.isoformat(),
        "week_tokens": week_tokens,
        "requests_week": requests_week,
        "weekly_reset_at": weekly_reset_local.isoformat(),
        "db_available": True,
    }


def quota_summary_for_key(key):
    data = load_quota_data()
    item = data["by_key"].get(key)
    usage = usage_for_key(key, data["timezone"])

    daily_limit = item.get("daily_token_limit") if item else None
    weekly_limit = item.get("weekly_token_limit") if item else None
    today_used = usage["today_tokens"]
    week_used = usage["week_tokens"]
    disabled = key in data["disabled"]

    daily_remaining = max(0, daily_limit - today_used) if daily_limit is not None else None
    weekly_remaining = max(0, weekly_limit - week_used) if weekly_limit is not None else None
    remaining_candidates = []
    if daily_remaining is not None:
        remaining_candidates.append(("daily", daily_remaining))
    if weekly_remaining is not None:
        remaining_candidates.append(("weekly", weekly_remaining))
    if remaining_candidates:
        effective_remaining_window, effective_remaining = min(
            remaining_candidates,
            key=lambda item: item[1],
        )
    else:
        effective_remaining_window, effective_remaining = None, None

    daily_usage_percent = round((today_used / daily_limit) * 100, 2) if daily_limit else None
    weekly_usage_percent = round((week_used / weekly_limit) * 100, 2) if weekly_limit else None
    usage_percent_candidates = []
    if daily_usage_percent is not None:
        usage_percent_candidates.append(("daily", daily_usage_percent))
    if weekly_usage_percent is not None:
        usage_percent_candidates.append(("weekly", weekly_usage_percent))
    if usage_percent_candidates:
        effective_usage_window, effective_usage_percent = max(
            usage_percent_candidates,
            key=lambda item: item[1],
        )
    else:
        effective_usage_window, effective_usage_percent = None, None

    over_daily = daily_limit is not None and today_used >= daily_limit
    over_weekly = weekly_limit is not None and week_used >= weekly_limit
    disabled_reasons = []
    if disabled:
        disabled_reasons.append("state")
    if over_daily:
        disabled_reasons.append("daily")
    if over_weekly:
        disabled_reasons.append("weekly")

    if daily_limit is None and weekly_limit is None:
        status = "unlimited"
    elif disabled_reasons:
        status = "disabled_by_quota"
    else:
        status = "active"

    return {
        "name": item.get("name") if item else None,
        "key": mask_key(key),
        "known_key": item is not None,
        "today_tokens": today_used,
        "daily_token_limit": daily_limit,
        "daily_remaining_tokens": daily_remaining,
        "daily_usage_percent": daily_usage_percent,
        "week_tokens": week_used,
        "weekly_token_limit": weekly_limit,
        "weekly_remaining_tokens": weekly_remaining,
        "weekly_usage_percent": weekly_usage_percent,
        "effective_remaining_tokens": effective_remaining,
        "effective_remaining_window": effective_remaining_window,
        "effective_usage_percent": effective_usage_percent,
        "effective_usage_window": effective_usage_window,
        "remaining_tokens": effective_remaining,
        "usage_percent": effective_usage_percent,
        "requests_today": usage["requests_today"],
        "requests_week": usage["requests_week"],
        "status": status,
        "disabled_reasons": disabled_reasons,
        "reset_at": usage["daily_reset_at"],
        "daily_reset_at": usage["daily_reset_at"],
        "weekly_reset_at": usage["weekly_reset_at"],
    }


def path_matches_prefix(path, prefixes):
    return any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)


def should_skip_quota(path):
    return path_matches_prefix(path, SKIP_QUOTA_PREFIXES)


def should_block_proxy_path(path):
    return path_matches_prefix(path, BLOCKED_PROXY_PREFIXES)


async def blocked_proxy_route(request):
    return web.json_response({"error": "forbidden"}, status=403)


async def healthz(request):
    return web.json_response({"status": "ok"})


async def quota_page(request):
    text = """CPA Proxy Quota Self Check

Use:
curl -s https://api.example.com/quota/me \\
  -H "Authorization: Bearer YOUR_API_KEY"

"""
    return web.Response(text=text, content_type="text/plain")


async def quota_me(request):
    key = extract_api_key(request)
    if not key:
        return web.json_response(
            {"error": "missing_api_key", "message": "Send Authorization: Bearer YOUR_API_KEY"},
            status=401,
        )

    data = load_quota_data()
    if key not in data.get("by_key", {}):
        return web.json_response(
            {"error": "unauthorized", "message": "Invalid API key"},
            status=401,
        )

    return web.json_response(quota_summary_for_key(key))


async def reject_quota(request, key):
    summary = quota_summary_for_key(key)
    return web.json_response(
        {
            "error": "quota_exceeded",
            "message": "Token quota exceeded",
            **summary,
            "usage_url": "/quota/me",
        },
        status=429,
    )


async def proxy_request(request):
    if should_block_proxy_path(request.path):
        return await blocked_proxy_route(request)

    key = extract_api_key(request)

    if key and not should_skip_quota(request.path):
        data = load_quota_data()
        if key in data.get("disabled", set()):
            return await reject_quota(request, key)

    session = request.app["client"]
    upstream_url = request.app["upstream"].rstrip("/") + request.rel_url.path_qs

    body = await request.read()
    headers = filtered_headers(request.headers)
    headers["Host"] = request.app["upstream_host"]

    try:
        async with session.request(
            request.method,
            upstream_url,
            headers=headers,
            data=body,
            allow_redirects=False,
        ) as upstream:
            response_headers = filtered_headers(upstream.headers)
            response_headers.setdefault("X-Accel-Buffering", "no")
            response_headers.setdefault("Cache-Control", "no-cache")

            resp = web.StreamResponse(
                status=upstream.status,
                reason=upstream.reason,
                headers=response_headers,
            )
            await resp.prepare(request)

            try:
                async for chunk in upstream.content.iter_chunked(16384):
                    if chunk:
                        await resp.write(chunk)
            except (asyncio.CancelledError, ConnectionResetError, ClientConnectionError, ClientPayloadError, ServerDisconnectedError):
                return resp

            try:
                await resp.write_eof()
            except (ConnectionResetError, RuntimeError, ClientConnectionError):
                pass

            return resp

    except (asyncio.CancelledError, ConnectionResetError, ClientConnectionError, ClientPayloadError, ServerDisconnectedError):
        return web.Response(status=499, text="client closed request")


async def handler(request):
    if request.path == "/quota/healthz":
        return await healthz(request)
    if request.path == "/quota":
        return await quota_page(request)
    if request.path == "/quota/me":
        return await quota_me(request)
    return await proxy_request(request)


async def client_ctx(app):
    timeout = ClientTimeout(total=None, connect=30, sock_connect=30, sock_read=None)
    app["client"] = ClientSession(timeout=timeout)
    yield
    await app["client"].close()


def make_app():
    app = web.Application(client_max_size=64 * 1024 * 1024)
    parsed_upstream = urlsplit(UPSTREAM)
    app["upstream"] = UPSTREAM
    app["upstream_host"] = parsed_upstream.netloc or parsed_upstream.path
    app.cleanup_ctx.append(client_ctx)
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


if __name__ == "__main__":
    web.run_app(make_app(), host=LISTEN_HOST, port=LISTEN_PORT)
