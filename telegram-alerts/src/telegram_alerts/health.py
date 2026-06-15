"""Health checks and alert construction for cliproxy support services."""

from __future__ import annotations
from typing import Any

from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
import json
import re
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from .settings import (
    ALERT_HOSTNAME,
    AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS,
    AUTH_QUOTA_INSPECTION_WAIT_SECONDS,
    AUTH_QUOTA_REFRESH_BEFORE_CHECK,
    CHECKS,
    CLIPROXY_MANAGEMENT_BASE_URL,
    CLIPROXY_MANAGEMENT_FALLBACK_ENABLED,
    CLIPROXY_MANAGEMENT_TOKEN,
    DB_WAL_WARN_BYTES,
    ENFORCER_LOG,
    ENFORCER_MAX_AGE_SECONDS,
    HTTP_TIMEOUT_SECONDS,
    USAGE_DB,
    USAGE_KEEPER_BASE_URL,
    USAGE_KEEPER_PASSWORD,
)
from .utils import fmt_tokens, log, mask_key, now_ts
from .models import Alert

def http_get_json(url):
    request = Request(url, headers={"User-Agent": "cliproxy-telegram-alerts/1.0"})
    with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        body = response.read(256 * 1024)
        status = getattr(response, "status", 200)
    text = body.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = {"raw": text[:500]}
    return status, data

def check_one_http_service(name, url):
    alerts = []
    try:
        status, data = http_get_json(url)
        label = "OK" if status < 400 else f"HTTP {status}"
        if isinstance(data, dict) and data.get("status") not in (None, "ok"):
            label = str(data.get("status"))
        if status >= 400:
            alerts.append(Alert(
                alert_id=f"service:{name}",
                severity="critical",
                title=f"{name} health check failed",
                body=f"{url} returned HTTP {status}: {data}",
                fingerprint=f"http:{status}",
            ))
        elif isinstance(data, dict) and data.get("status") not in (None, "ok") and data.get("message") not in (None, "ok"):
            alerts.append(Alert(
                alert_id=f"service:{name}",
                severity="warning",
                title=f"{name} returned unusual health payload",
                body=f"{url} returned: {data}",
                fingerprint="unusual-health-payload",
            ))
        return {"name": name, "line": f"- {name}: {label}", "alerts": alerts}
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        return {
            "name": name,
            "line": f"- {name}: DOWN ({exc})",
            "alerts": [Alert(
                alert_id=f"service:{name}",
                severity="critical",
                title=f"{name} is not reachable",
                body=f"{url} failed: {exc}",
                fingerprint="unreachable",
            )],
        }

def check_http_services_detailed():
    items = list(CHECKS.items())
    if not items:
        return []
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(len(items), 8))) as executor:
        futures = [executor.submit(check_one_http_service, name, url) for name, url in items]
        for future in futures:
            results.append(future.result())
    return results

_UNSET = object()


def check_http_services(results=_UNSET):
    if results is _UNSET:
        results = check_http_services_detailed()
    if results is None:
        results = []
    alerts = []
    for result in results:
        if isinstance(result, dict):
            alerts.extend(result.get("alerts", []) or [])
    return alerts

def check_enforcer():
    alerts = []
    if not ENFORCER_LOG.exists():
        return [Alert(
            alert_id="enforcer:log-missing",
            severity="critical",
            title="Quota enforcer log is missing",
            body=f"Expected log file at {ENFORCER_LOG}.",
            fingerprint="missing",
        )]

    age = max(0, now_ts() - int(ENFORCER_LOG.stat().st_mtime))
    if age > ENFORCER_MAX_AGE_SECONDS:
        alerts.append(Alert(
            alert_id="enforcer:stale",
            severity="critical",
            title="Quota enforcer looks stale",
            body=f"{ENFORCER_LOG} has not changed for {age}s. Expected under {ENFORCER_MAX_AGE_SECONDS}s.",
            fingerprint="stale",
        ))

    return alerts

def check_storage():
    alerts = []
    wal = Path(str(USAGE_DB) + "-wal")
    if wal.exists() and wal.stat().st_size > DB_WAL_WARN_BYTES:
        alerts.append(Alert(
            alert_id="storage:usage-db-wal-large",
            severity="warning",
            title="Usage Keeper WAL is large",
            body=f"{wal} is {fmt_tokens(wal.stat().st_size)}B. Consider checking usage-keeper health/backups if it keeps growing.",
            fingerprint="large",
        ))
    return alerts

def usage_keeper_request(path, method="GET", payload=None, cookie=None):
    url = f"{USAGE_KEEPER_BASE_URL}/api/v1/{path.lstrip('/')}"
    data = None
    headers = {"User-Agent": "cliproxy-telegram-alerts/1.0"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    request = Request(url, data=data, headers=headers, method=method)
    with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        body = response.read(512 * 1024)
        status = getattr(response, "status", 200)
        set_cookie = response.headers.get("Set-Cookie", "")
    text = body.decode("utf-8", errors="replace")
    if text:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = {"raw": text[:500]}
    else:
        parsed = {}
    return status, parsed, set_cookie

def usage_keeper_session_cookie():
    if not USAGE_KEEPER_PASSWORD:
        return ""
    _, _, set_cookie = usage_keeper_request(
        "auth/login",
        method="POST",
        payload={"password": USAGE_KEEPER_PASSWORD},
    )
    return set_cookie.split(";", 1)[0].strip()


def list_or_empty(value):
    return value if isinstance(value, list) else []


def dict_or_empty(value):
    return value if isinstance(value, dict) else {}


GPT_POOL_IDENTITY_PAGE_SIZE = 500
GPT_POOL_QUOTA_KEYS = {
    "primary": "rate_limit.primary_window",
    "secondary": "rate_limit.secondary_window",
}
GPT_POOL_PLUS_COMPATIBLE_PLAN_TYPES = {"plus", "team"}
GPT_POOL_FREE_PLAN_TYPES = {"free"}
GPT_POOL_WINDOW_SECONDS = {
    "primary": 18_000,
    "secondary": 604_800,
}
GPT_POOL_PRIMARY_TOKEN_EQUIVALENT = 20_000_000
GPT_POOL_SECONDARY_TOKEN_EQUIVALENT = 140_000_000
GPT_POOL_EMPTY_WINDOW = {
    "checked_count": 0,
    "avg_left_percent": None,
    "lowest_left_percent": None,
    "left_tokens": None,
}


def empty_gpt_pool_capacity(error="", source="usage_keeper"):
    return {
        "source": str(source or "usage_keeper"),
        "enabled_codex_count": 0,
        "primary": dict(GPT_POOL_EMPTY_WINDOW),
        "secondary": dict(GPT_POOL_EMPTY_WINDOW),
        "error": str(error or ""),
        "usage_keeper_checked_count": 0,
        "management_checked_count": 0,
        "missing_rows_count": 0,
    }


def payload_items(data):
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for key in ("items", "identities", "results", "data", "rows"):
        value = data.get(key)
        if isinstance(value, list):
            return value
        nested = payload_items(value)
        if nested:
            return nested
    return []


def identity_auth_index(item):
    item = dict_or_empty(item)
    return str(
        item.get("auth_index")
        or item.get("authIndex")
        or item.get("index")
        or item.get("id")
        or item.get("identity")
        or ""
    ).strip()


def identity_quota_cache_index(item):
    item = dict_or_empty(item)
    return str(
        item.get("identity")
        or item.get("auth_index")
        or item.get("authIndex")
        or item.get("index")
        or item.get("id")
        or ""
    ).strip()


def identity_is_codex(item):
    item = dict_or_empty(item)
    if not item:
        return False
    auth_type = str(
        item.get("type")
        or item.get("auth_type")
        or item.get("authType")
        or item.get("provider")
        or ""
    ).strip().lower()
    # The endpoint is already queried with auth_type=1 (codex), but when the
    # payload includes a type-like field, enforce codex so secondary auth pools
    # such as antigravity never enter Codex quota refresh or capacity math.
    return not auth_type or auth_type in {"codex", "1"}


def identity_is_enabled_codex(item):
    item = dict_or_empty(item)
    if not item:
        return False
    if bool(item.get("disabled")) or bool(item.get("is_deleted")):
        return False
    if item.get("active") is False or item.get("enabled") is False:
        return False
    status = str(item.get("status") or item.get("state") or "").strip().lower()
    if status in {"disabled", "inactive", "deleted", "archived"}:
        return False
    return identity_is_codex(item)


def usage_keeper_codex_identity_items(cookie, active_only=True):
    items = []
    seen = set()
    page = 1
    max_pages = 10
    active = "true" if active_only else "false"
    while page <= max_pages:
        path = f"usage/identities/page?auth_type=1&active_only={active}&page={page}&page_size={GPT_POOL_IDENTITY_PAGE_SIZE}"
        try:
            _, data, _ = usage_keeper_request(path, cookie=cookie)
        except Exception:
            if not active_only:
                log("quota inspection identity fallback unavailable")
            break
        for item in payload_items(data):
            item = dict_or_empty(item)
            if not item or bool(item.get("is_deleted")) or bool(item.get("deleted")):
                continue
            if active_only and not identity_is_enabled_codex(item):
                continue
            if not active_only and not identity_is_codex(item):
                continue
            auth_index = identity_auth_index(item)
            if auth_index and auth_index not in seen:
                seen.add(auth_index)
                items.append(item)
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
    return items


def enabled_codex_auth_items(cookie):
    return usage_keeper_codex_identity_items(cookie, active_only=True)


def all_known_codex_auth_items(cookie):
    """Return deduped Codex identity rows from Usage Keeper's full identity list."""
    return usage_keeper_codex_identity_items(cookie, active_only=False)


def all_known_codex_auth_indexes(cookie):
    """Return deduped Codex auth indexes from Usage Keeper's full identity list.

    This is only used as a recovery fallback when quota inspection says rows are
    missing, because the inspection payload itself cannot name omitted accounts.
    """
    return [identity_quota_cache_index(item) for item in all_known_codex_auth_items(cookie) if identity_quota_cache_index(item)]


def quota_rows_from_cache_item(item):
    item = dict_or_empty(item)
    if not item:
        return []
    quota = dict_or_empty(item.get("quota"))
    rows = quota.get("quota")
    if isinstance(rows, list):
        return rows
    for key in ("quotas", "quota_rows", "rows", "items", "data"):
        rows = item.get(key)
        if isinstance(rows, list):
            return rows
    if "key" in item and any(field in item for field in ("usedPercent", "used_percent", "usedPercentage")):
        return [item]
    return []


def used_percent_value(row):
    row = dict_or_empty(row)
    raw = row.get("usedPercent", row.get("used_percent", row.get("usedPercentage")))
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def quota_row_plan_type(row):
    row = dict_or_empty(row)
    return str(row.get("planType") or row.get("plan_type") or row.get("plan") or "").strip().lower()


def quota_row_window_seconds(row):
    row = dict_or_empty(row)
    raw = row.get("windowSeconds", row.get("window_seconds", row.get("seconds")))
    if raw is None:
        window = row.get("window")
        if isinstance(window, dict):
            raw = window.get("seconds")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def gpt_pool_expected_window_seconds(window_name):
    return GPT_POOL_WINDOW_SECONDS.get(str(window_name or ""))


def gpt_pool_row_matches_plus_window(row, window_name):
    expected = gpt_pool_expected_window_seconds(window_name)
    seconds = quota_row_window_seconds(row)
    return expected is not None and seconds == expected


def gpt_pool_row_plus_compatible(row, window_name):
    plan = quota_row_plan_type(row)
    seconds = quota_row_window_seconds(row)
    if plan in GPT_POOL_FREE_PLAN_TYPES:
        return False
    if gpt_pool_row_matches_plus_window(row, window_name):
        return True
    if plan:
        return plan in GPT_POOL_PLUS_COMPATIBLE_PLAN_TYPES and seconds is None
    # Legacy Usage Keeper test/runtime rows did not always include plan/window
    # metadata. Treat key-only rows as compatible unless they explicitly identify
    # a non-Plus window above.
    return seconds is None


def gpt_pool_row_free_plan(row):
    plan = quota_row_plan_type(row)
    return plan in GPT_POOL_FREE_PLAN_TYPES


def gpt_pool_window_summary(values_by_auth, token_equivalent):
    values = [float(value) for value in values_by_auth.values()]
    if not values:
        return dict(GPT_POOL_EMPTY_WINDOW)
    return {
        "checked_count": len(values),
        "avg_left_percent": round(sum(values) / len(values), 1),
        "lowest_left_percent": round(min(values), 1),
        "left_tokens": sum((value / 100.0) * float(token_equivalent) for value in values),
    }


def gpt_pool_capacity_complete(capacity):
    capacity = dict_or_empty(capacity)
    try:
        enabled = int(capacity.get("enabled_codex_count", 0) or 0)
        primary_checked = int(dict_or_empty(capacity.get("primary")).get("checked_count", 0) or 0)
        secondary_checked = int(dict_or_empty(capacity.get("secondary")).get("checked_count", 0) or 0)
    except (TypeError, ValueError):
        return False
    return enabled > 0 and not capacity.get("error") and primary_checked == enabled and secondary_checked == enabled


def gpt_pool_capacity_checked_min(capacity):
    capacity = dict_or_empty(capacity)
    try:
        primary_checked = int(dict_or_empty(capacity.get("primary")).get("checked_count", 0) or 0)
        secondary_checked = int(dict_or_empty(capacity.get("secondary")).get("checked_count", 0) or 0)
    except (TypeError, ValueError):
        return 0
    return min(primary_checked, secondary_checked)


def codex_free_plan_alert(capacity):
    capacity = dict_or_empty(capacity)
    try:
        count = int(capacity.get("free_codex_count", 0) or 0)
    except (TypeError, ValueError):
        count = 0
    if count <= 0:
        return None
    labels = [str(label).strip() for label in list_or_empty(capacity.get("free_codex_labels")) if str(label or "").strip()]
    hashes = [str(value).strip() for value in list_or_empty(capacity.get("free_codex_hashes")) if str(value or "").strip()]
    account_labels = labels or [f"hash {value}" for value in hashes]
    if not account_labels:
        account_labels = [f"{count} enabled Codex account" if count == 1 else f"{count} enabled Codex accounts"]
    lines = [
        f"- Account {label} is reported to have a Free quota and is excluded from the GPT Plus pool capacity."
        for label in account_labels[:15]
    ]
    if count > 15:
        lines.append(f"... and {count - 15} more")
    return Alert(
        alert_id="auth:codex-free-plan",
        severity="warning",
        title="Codex accounts downgraded to Free",
        body="\n".join(lines),
        fingerprint=f"free-codex:{count}",
    )


CODEX_WHAM_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"
CODEX_WHAM_HEADERS = {
    "Authorization": "Bearer $TOKEN$",
    "Content-Type": "application/json",
    "User-Agent": "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
}


def management_request(path, method="GET", payload=None):
    if not CLIPROXY_MANAGEMENT_FALLBACK_ENABLED or not CLIPROXY_MANAGEMENT_TOKEN:
        raise RuntimeError("management quota fallback unavailable")
    url = urljoin(f"{CLIPROXY_MANAGEMENT_BASE_URL}/", str(path or "").lstrip("/"))
    data = None
    headers = {
        "Authorization": f"Bearer {CLIPROXY_MANAGEMENT_TOKEN}",
        "User-Agent": "cliproxy-telegram-alerts/1.0",
    }
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        body = response.read(1024 * 1024)
        status = getattr(response, "status", 200)
    text = body.decode("utf-8", errors="replace")
    if status >= 400:
        raise RuntimeError(f"management quota fallback HTTP {status}")
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("management quota fallback malformed response") from exc


def management_auth_files(data):
    if isinstance(data, dict):
        files = data.get("files") or data.get("items") or data.get("data") or []
    elif isinstance(data, list):
        files = data
    else:
        files = []
    return [item for item in files if isinstance(item, dict)]


def management_auth_file_is_enabled_codex(item):
    item = dict_or_empty(item)
    provider = str(item.get("provider") or item.get("type") or "").strip().lower().replace("_", "-")
    if provider != "codex":
        return False
    if bool(item.get("disabled")) or bool(item.get("is_deleted")) or bool(item.get("deleted")):
        return False
    if item.get("active") is False or item.get("enabled") is False:
        return False
    return bool(identity_auth_index(item))


def decode_jwt_payload(value):
    if not isinstance(value, str) or "." not in value:
        return {}
    parts = value.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1].strip()
    if not payload:
        return {}
    try:
        padded = payload + "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(decoded.decode("utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def chatgpt_account_id_from_auth_file(item):
    item = dict_or_empty(item)
    for container in (item, dict_or_empty(item.get("metadata")), dict_or_empty(item.get("attributes"))):
        direct = str(container.get("chatgpt_account_id") or container.get("chatgptAccountId") or "").strip()
        if direct:
            return direct
        decoded = decode_jwt_payload(container.get("id_token"))
        account_id = str(decoded.get("chatgpt_account_id") or decoded.get("chatgptAccountId") or "").strip()
        if account_id:
            return account_id
    return ""


def parse_jsonish_body(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def management_api_call_body(data):
    data = dict_or_empty(data)
    status_code = int(data.get("status_code") or data.get("statusCode") or 0)
    if status_code and (status_code < 200 or status_code >= 300):
        raise RuntimeError(f"management quota fallback upstream HTTP {status_code}")
    return parse_jsonish_body(data.get("body") if "body" in data else data)


def management_window_used_percent(quota_data, window_name):
    quota_data = dict_or_empty(quota_data)
    rate_limit = dict_or_empty(quota_data.get("rate_limit") or quota_data.get("rateLimit"))
    window = dict_or_empty(rate_limit.get(f"{window_name}_window") or rate_limit.get(f"{window_name}Window"))
    if not window:
        return None
    return used_percent_value(window)


def management_gpt_pool_capacity_snapshot(enabled_count_hint=0):
    capacity = empty_gpt_pool_capacity(source="management_fallback")
    try:
        files = [
            item for item in management_auth_files(management_request("auth-files"))
            if management_auth_file_is_enabled_codex(item)
        ]
        capacity["enabled_codex_count"] = len(files) or int(enabled_count_hint or 0)
        if not files:
            capacity["error"] = "management quota fallback unavailable"
            return capacity
        left_values = {"primary": {}, "secondary": {}}
        for index, item in enumerate(files):
            auth_index = identity_auth_index(item)
            headers = dict(CODEX_WHAM_HEADERS)
            account_id = chatgpt_account_id_from_auth_file(item)
            if account_id:
                headers["Chatgpt-Account-Id"] = account_id
            body = management_api_call_body(management_request(
                "api-call",
                method="POST",
                payload={
                    "authIndex": auth_index,
                    "method": "GET",
                    "url": CODEX_WHAM_USAGE_URL,
                    "header": headers,
                },
            ))
            for window_name in ("primary", "secondary"):
                used = management_window_used_percent(body, window_name)
                if used is not None:
                    left_values[window_name][f"slot-{index}"] = max(0.0, min(100.0, 100.0 - used))
        capacity["primary"] = gpt_pool_window_summary(left_values["primary"], GPT_POOL_PRIMARY_TOKEN_EQUIVALENT)
        capacity["secondary"] = gpt_pool_window_summary(left_values["secondary"], GPT_POOL_SECONDARY_TOKEN_EQUIVALENT)
        capacity["management_checked_count"] = gpt_pool_capacity_checked_min(capacity)
        capacity["missing_rows_count"] = max(0, int(capacity.get("enabled_codex_count", 0) or 0) - capacity["management_checked_count"])
        if not gpt_pool_capacity_complete(capacity):
            capacity["error"] = "management quota fallback incomplete"
        return capacity
    except Exception:
        return empty_gpt_pool_capacity("management quota fallback unavailable", source="management_fallback")


def auth_index_identity_key(auth_index):
    auth_index = str(auth_index or "").strip()
    if not auth_index:
        return ""
    return hashlib.sha256(auth_index.encode("utf-8", errors="replace")).hexdigest()[:16]



def gpt_pool_recent_cache_identity_key(auth_index):
    return auth_index_identity_key(auth_index)


def gpt_pool_recent_cache_fresh(recent_cache, cache_now, cache_max_age_seconds):
    recent_cache = dict_or_empty(recent_cache)
    try:
        created_at = int(recent_cache.get("created_at", 0) or 0)
        cache_now = int(cache_now if cache_now is not None else now_ts())
        cache_max_age_seconds = int(cache_max_age_seconds or 0)
    except (TypeError, ValueError):
        return False
    return created_at > 0 and cache_max_age_seconds >= 0 and cache_now - created_at <= cache_max_age_seconds


def gpt_pool_recent_cache_value(entry, window_name):
    entry = dict_or_empty(entry)
    try:
        value = float(entry.get(window_name))
    except (TypeError, ValueError):
        return None
    if value < 0 or value > 100:
        return None
    return value


def merge_gpt_pool_recent_cache(auth_indexes, left_values, recent_cache=None, cache_now=None, cache_max_age_seconds=0):
    merged = {
        "primary": dict(dict_or_empty(left_values).get("primary", {})),
        "secondary": dict(dict_or_empty(left_values).get("secondary", {})),
    }
    if not gpt_pool_recent_cache_fresh(recent_cache, cache_now, cache_max_age_seconds):
        return merged
    identities = dict_or_empty(dict_or_empty(recent_cache).get("identities"))
    for auth_index in auth_indexes:
        cache_key = gpt_pool_recent_cache_identity_key(auth_index)
        entry = dict_or_empty(identities.get(cache_key))
        if not entry:
            continue
        for window_name in ("primary", "secondary"):
            if auth_index in merged[window_name]:
                continue
            cached_value = gpt_pool_recent_cache_value(entry, window_name)
            if cached_value is not None:
                merged[window_name][auth_index] = cached_value
    return merged


def gpt_pool_recent_cache_from_values(auth_indexes, left_values, cache_now=None):
    identities = {}
    for auth_index in auth_indexes:
        cache_key = gpt_pool_recent_cache_identity_key(auth_index)
        if not cache_key:
            continue
        entry = {}
        for window_name in ("primary", "secondary"):
            if auth_index not in left_values.get(window_name, {}):
                continue
            value = gpt_pool_recent_cache_value({window_name: left_values[window_name][auth_index]}, window_name)
            if value is not None:
                entry[window_name] = value
        if entry:
            identities[cache_key] = entry
    return {"created_at": int(cache_now if cache_now is not None else now_ts()), "identities": identities}


def auth_inspection_failed_auth_index_keys(auth_inspection_state, ts=None):
    auth_inspection_state = dict_or_empty(auth_inspection_state)
    if not bool(auth_inspection_state.get("raw_current_complete") or auth_inspection_state.get("complete")):
        return set()
    try:
        last_complete_at = int(auth_inspection_state.get("last_complete_at", 0) or 0)
        ts = int(ts if ts is not None else now_ts())
    except (TypeError, ValueError):
        return set()
    if last_complete_at <= 0:
        return set()
    max_age = max(0, int(AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS or 0))
    if ts - last_complete_at >= max_age:
        return set()
    keys = auth_inspection_state.get("failed_auth_index_keys")
    if not isinstance(keys, list):
        return set()
    return {
        str(key).strip().lower()
        for key in keys
        if re.fullmatch(r"[0-9a-fA-F]{16}", str(key or "").strip())
    }


def usable_gpt_pool_auth_indexes(auth_indexes, auth_inspection_state=None, ts=None):
    auth_indexes = [str(auth_index or "").strip() for auth_index in auth_indexes if str(auth_index or "").strip()]
    failed_keys = auth_inspection_failed_auth_index_keys(auth_inspection_state, ts=ts)
    if not failed_keys:
        return auth_indexes, 0
    usable = []
    excluded = 0
    for auth_index in auth_indexes:
        if auth_index_identity_key(auth_index) in failed_keys:
            excluded += 1
        else:
            usable.append(auth_index)
    return usable, excluded


def _gpt_pool_capacity_snapshot(allow_management_fallback=True, recent_cache=None, cache_now=None, cache_max_age_seconds=0, auth_inspection_state=None):
    """Return sanitized GPT pool capacity and recent-cache data."""
    empty_cache = {"created_at": int(cache_now if cache_now is not None else now_ts()), "identities": {}}
    if not USAGE_KEEPER_PASSWORD:
        return empty_gpt_pool_capacity("Usage Keeper quota cache unavailable"), empty_cache
    try:
        cookie = usage_keeper_session_cookie()
        if not cookie:
            return empty_gpt_pool_capacity("Usage Keeper quota cache unavailable"), empty_cache
        auth_items = enabled_codex_auth_items(cookie)
        identity_items_by_auth_index = {
            identity_quota_cache_index(item): item
            for item in auth_items
            if identity_quota_cache_index(item)
        }
        stable_auth_index_by_quota_cache_index = {
            identity_quota_cache_index(item): (identity_auth_index(item) or identity_quota_cache_index(item))
            for item in auth_items
            if identity_quota_cache_index(item)
        }
        auth_indexes = list(identity_items_by_auth_index.keys())
        failed_keys = auth_inspection_failed_auth_index_keys(auth_inspection_state, ts=cache_now)
        usable_auth_indexes = []
        excluded_reauth_count = 0
        for auth_index in auth_indexes:
            stable_auth_index = stable_auth_index_by_quota_cache_index.get(auth_index) or auth_index
            if auth_index_identity_key(stable_auth_index) in failed_keys or auth_index_identity_key(auth_index) in failed_keys:
                excluded_reauth_count += 1
            else:
                usable_auth_indexes.append(auth_index)
        capacity = empty_gpt_pool_capacity(source="usage_keeper")
        capacity["enabled_codex_count"] = len(usable_auth_indexes)
        if excluded_reauth_count:
            capacity["total_enabled_codex_count"] = len(auth_indexes)
            capacity["excluded_reauth_count"] = excluded_reauth_count
            capacity["usable_codex_count"] = len(usable_auth_indexes)
        if not auth_indexes or not usable_auth_indexes:
            return capacity, empty_cache
        _, data, _ = usage_keeper_request(
            "quota/cache",
            method="POST",
            payload={"auth_indexes": usable_auth_indexes},
            cookie=cookie,
        )
        requested = set(usable_auth_indexes)
        current_left_values = {"primary": {}, "secondary": {}}
        free_auth_indexes = set()
        for item in payload_items(data):
            item = dict_or_empty(item)
            auth_index = identity_quota_cache_index(item)
            if not auth_index or auth_index not in requested:
                continue
            for row in quota_rows_from_cache_item(item):
                row = dict_or_empty(row)
                quota_key = str(row.get("key") or "").strip()
                window_name = ""
                for candidate, expected_key in GPT_POOL_QUOTA_KEYS.items():
                    if quota_key == expected_key:
                        window_name = candidate
                        break
                if not window_name:
                    continue
                if gpt_pool_row_free_plan(row):
                    free_auth_indexes.add(auth_index)
                    continue
                if not gpt_pool_row_plus_compatible(row, window_name):
                    continue
                used = used_percent_value(row)
                if used is None:
                    continue
                current_left_values[window_name][auth_index] = max(0.0, min(100.0, 100.0 - used))
        plus_usable_auth_indexes = [auth_index for auth_index in usable_auth_indexes if auth_index not in free_auth_indexes]
        if free_auth_indexes:
            for values in current_left_values.values():
                for auth_index in free_auth_indexes:
                    values.pop(auth_index, None)
            free_labels = []
            free_hashes = []
            for auth_index in sorted(free_auth_indexes):
                label = auth_account_actionable_label_text(identity_items_by_auth_index.get(auth_index, {}))
                if label:
                    free_labels.append(label)
                hash_key = auth_index_identity_key(auth_index)
                if hash_key:
                    free_hashes.append(hash_key)
            capacity["free_codex_count"] = len(free_auth_indexes)
            capacity["free_codex_labels"] = sorted(set(free_labels))
            capacity["free_codex_hashes"] = sorted(set(free_hashes))
            capacity["total_enabled_codex_count"] = len(auth_indexes)
            capacity["usable_codex_count"] = len(plus_usable_auth_indexes)
        capacity["enabled_codex_count"] = len(plus_usable_auth_indexes)
        left_values = merge_gpt_pool_recent_cache(
            plus_usable_auth_indexes,
            current_left_values,
            recent_cache=recent_cache,
            cache_now=cache_now,
            cache_max_age_seconds=cache_max_age_seconds,
        )
        next_cache = gpt_pool_recent_cache_from_values(plus_usable_auth_indexes, left_values, cache_now=cache_now)
        capacity["primary"] = gpt_pool_window_summary(
            left_values["primary"],
            GPT_POOL_PRIMARY_TOKEN_EQUIVALENT,
        )
        capacity["secondary"] = gpt_pool_window_summary(
            left_values["secondary"],
            GPT_POOL_SECONDARY_TOKEN_EQUIVALENT,
        )
        capacity["usage_keeper_checked_count"] = gpt_pool_capacity_checked_min(capacity)
        capacity["missing_rows_count"] = max(0, len(plus_usable_auth_indexes) - capacity["usage_keeper_checked_count"])
        if gpt_pool_capacity_complete(capacity):
            return capacity, next_cache
        if not allow_management_fallback or excluded_reauth_count or free_auth_indexes:
            return capacity, next_cache
        fallback = management_gpt_pool_capacity_snapshot(enabled_count_hint=len(plus_usable_auth_indexes))
        if gpt_pool_capacity_complete(fallback):
            fallback["usage_keeper_checked_count"] = capacity["usage_keeper_checked_count"]
            return fallback, next_cache
        return capacity, next_cache
    except Exception:
        return empty_gpt_pool_capacity("Usage Keeper quota cache unavailable"), empty_cache


def gpt_pool_capacity_snapshot(allow_management_fallback=True):
    """Return sanitized GPT pool capacity, preferring Usage Keeper quota cache.

    Only enabled codex identities are requested and the returned snapshot contains
    aggregate counts/percentages, never auth indexes or account labels. The cliproxy
    management quota path is used only as a GPT-capacity fallback when Usage Keeper
    quota-cache window coverage is incomplete.
    """
    capacity, _ = _gpt_pool_capacity_snapshot(allow_management_fallback=allow_management_fallback)
    return capacity


def gpt_pool_capacity_snapshot_with_recent_cache(recent_cache=None, cache_now=None, cache_max_age_seconds=0, allow_management_fallback=False, auth_inspection_state=None):
    return _gpt_pool_capacity_snapshot(
        allow_management_fallback=allow_management_fallback,
        recent_cache=recent_cache,
        cache_now=cache_now,
        cache_max_age_seconds=cache_max_age_seconds,
        auth_inspection_state=auth_inspection_state,
    )


AUTH_INSPECTION_IDENTITY_FALLBACK_REASONS = {"count-mismatch", "results-none", "results-missing"}


def dedupe_auth_indexes(values):
    indexes = []
    seen = set()
    for value in values:
        auth_index = str(value or "").strip()
        if auth_index and auth_index not in seen:
            seen.add(auth_index)
            indexes.append(auth_index)
    return indexes


def inspection_result_auth_indexes(data):
    if not isinstance(data, dict):
        return []
    return dedupe_auth_indexes(
        item.get("auth_index")
        for item in list_or_empty(data.get("results"))
        if isinstance(item, dict)
    )


def quota_refresh_auth_indexes(data, cookie):
    auth_indexes = inspection_result_auth_indexes(data)
    reason = auth_quota_incomplete_reason(data)
    if reason in AUTH_INSPECTION_IDENTITY_FALLBACK_REASONS:
        fallback_indexes = all_known_codex_auth_indexes(cookie)
        if fallback_indexes:
            return fallback_indexes
    return auth_indexes


def quota_inspection_payload(refresh_before_check: bool | None = None, wait_for_refresh: bool = True, wait_seconds: int | None = None) -> dict[str, Any]:
    """Fetch Usage Keeper quota inspection using the configured dashboard password.

    Auth quota refresh is asynchronous, so a just-triggered refresh can briefly
    return partial inspection payloads. When waiting is requested, poll until the
    strict inspection payload is complete or the auth-specific wait timeout expires."""
    if refresh_before_check is None:
        refresh_before_check = AUTH_QUOTA_REFRESH_BEFORE_CHECK
    if wait_seconds is None:
        wait_seconds = AUTH_QUOTA_INSPECTION_WAIT_SECONDS
    cookie = usage_keeper_session_cookie()
    if not cookie:
        raise RuntimeError("USAGE_KEEPER_PASSWORD is not configured for quota inspection")
    _, data, _ = usage_keeper_request("quota/inspection", cookie=cookie)
    if not isinstance(data, dict):
        raise RuntimeError("quota inspection response is not an object")

    if refresh_before_check:
        auth_indexes = quota_refresh_auth_indexes(data, cookie)
        if auth_indexes:
            try:
                usage_keeper_request(
                    "quota/refresh",
                    method="POST",
                    payload={"auth_indexes": auth_indexes},
                    cookie=cookie,
                )
                if wait_for_refresh:
                    deadline = time.monotonic() + max(0, int(wait_seconds or 0))
                    while True:
                        time.sleep(1)
                        _, data, _ = usage_keeper_request("quota/inspection", cookie=cookie)
                        if not isinstance(data, dict) or not auth_quota_incomplete_reason(data):
                            break
                        if time.monotonic() >= deadline:
                            break
            except Exception as exc:
                log(f"quota refresh before auth check failed: {exc.__class__.__name__}")
    if not isinstance(data, dict):
        raise RuntimeError("quota inspection response is not an object")
    return data

def quota_error_details(error_text):
    text = str(error_text or "").strip()
    status_match = re.search(r"HTTP\s+(\d+)", text)
    status = status_match.group(1) if status_match else ""
    code = ""
    message = ""
    json_start = text.find("{")
    if json_start >= 0:
        try:
            data = json.loads(text[json_start:])
            err = data.get("error") if isinstance(data, dict) else {}
            if isinstance(err, dict):
                code = str(err.get("code") or "")
                message = str(err.get("message") or "")
        except Exception:
            pass
    if not message:
        message = re.sub(r"\s+", " ", text)[:180]
    if status and message:
        message = re.sub(r"(?i)^\s*HTTP\s+\d+\s*:?\s*", "", message).strip()
    bits = []
    if status:
        bits.append(status)
    if code:
        bits.append(code)
    if message:
        bits.append(message)
    return " - ".join(bits) if bits else "failed"


REAUTH_ERROR_SECRET_PATTERNS = [
    re.compile(r"(?i)\bbearer\s+[^\s,;]+"),
    re.compile(r"(?i)\b(?:api[_-]?key|cookie|management[_-]?token|access[_-]?token|refresh[_-]?token|token|secret)\s*[=:]\s*[^\s,;]+"),
    re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{8,}\b"),
]


def sanitize_reauth_error_detail(text):
    detail = str(text or "")
    for pattern in REAUTH_ERROR_SECRET_PATTERNS:
        detail = pattern.sub("[redacted]", detail)
    return detail


CANONICAL_INVALIDATED_TOKEN_REAUTH_DETAIL = "401 Encountered invalidated oauth token for user, failing request"


def canonical_reauth_evidence_detail(detail):
    detail = sanitize_reauth_error_detail(detail)
    detail = re.sub(r"\s+", " ", str(detail or "").strip())
    detail = re.sub(r"(?:\s*\[redacted\])+\s*$", "", detail).strip()
    if not detail:
        return "reauth required"

    lowered = detail.lower()
    has_401 = "401" in lowered or "unauthorized_401" in lowered or "unauthorized" in lowered
    invalidated_markers = (
        "invalidated oauth token",
        "authentication token has been invalidated",
        "token has been invalidated",
        "token invalidated",
        "invalidated token",
        "please try signing in again",
    )
    if has_401 and any(marker in lowered for marker in invalidated_markers):
        return CANONICAL_INVALIDATED_TOKEN_REAUTH_DETAIL
    return detail


def reauth_error_details(error):
    verbose = quota_error_details(error)
    parts = [part.strip() for part in str(verbose or "").split(" - ") if part.strip()]
    if len(parts) >= 3:
        return canonical_reauth_evidence_detail(f"{parts[0]} {parts[-1]}")
    if len(parts) == 2:
        return canonical_reauth_evidence_detail(f"{parts[0]} {parts[1]}")
    return canonical_reauth_evidence_detail(verbose or "failed")


EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")


def safe_email_from_auth_label(value):
    text = str(value or "").strip()
    if not text:
        return ""
    candidates = [text]
    if text.lower().endswith(".json"):
        candidates.insert(0, text[:-5])
    for candidate in candidates:
        match = EMAIL_RE.search(candidate)
        if match:
            return match.group(0)
    return ""


AUTH_REAUTH_STATUSES = {
    "unauthorized_401",
    "token_revoked",
    "invalid_auth",
    "expired_auth",
    "auth_invalid",
    "needs_reauth",
    "reauth_required",
}
AUTH_QUOTA_DISABLED_STATUSES = {
    "disabled_by_quota",
    "quota_disabled",
    "quota_exceeded",
    "daily_quota_exceeded",
    "weekly_quota_exceeded",
    "limit_reached",
}


def is_reauth_status(status):
    status = str(status or "").strip().lower()
    return (
        status in AUTH_REAUTH_STATUSES
        or "unauthorized" in status
        or "reauth" in status
        or status.startswith("invalid_auth")
        or status.startswith("expired_auth")
    )


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


def is_reauth_auth_item(item):
    item = dict_or_empty(item)
    status = str(item.get("status") or item.get("state") or item.get("auth_status") or item.get("authStatus") or "").strip().lower()
    if status in {"", "normal", "ok", "healthy", "available", "completed"} or is_quota_disabled_auth_status(status):
        return False
    if is_reauth_status(status):
        return True
    text = auth_item_reauth_text(item).lower()
    if "401" in text or "unauthorized" in text:
        return True
    return any(pattern in text for pattern in REAUTH_EVIDENCE_PATTERNS)


def is_quota_disabled_auth_status(status):
    return str(status or "").strip().lower() in AUTH_QUOTA_DISABLED_STATUSES


def auth_account_identity(item):
    return str(item.get("file_name") or item.get("name") or item.get("auth_index") or "unknown").strip() or "unknown"


def safe_auth_account_label(item):
    label = auth_account_identity(item)
    lowered = label.lower()
    if "@" in label or lowered.endswith(".json") or "/" in label or "\\" in label:
        alnum = "".join(ch for ch in label if ch.isalnum())
        digits = "".join(ch for ch in label if ch.isdigit())
        suffix = (digits or alnum)[-4:] if (digits or alnum) else "****"
        return f"account ending ...{suffix}"
    if re.search(r"(?i)\b(api[_ -]?key|token|secret)\b", label):
        return mask_key(label)
    if re.match(r"(?i)^sk-[A-Za-z0-9_-]{12,}$", label):
        return mask_key(label)
    if re.match(r"^[a-z0-9]{2,20}-[A-Za-z0-9_-]{20,}$", label):
        return mask_key(label)
    if len(label) > 80:
        return f"{label[:24]}...{label[-12:]}"
    return label


def safe_non_email_auth_label(value):
    text = str(value or "").strip()
    if not text or safe_email_from_auth_label(text):
        return ""
    lowered = text.lower()
    if lowered.endswith(".json") or "/" in text or "\\" in text:
        return ""
    if any(pattern.search(text) for pattern in REAUTH_ERROR_SECRET_PATTERNS):
        return ""
    if re.search(r"(?i)\b(api[_ -]?key|token|secret)\b", text):
        return ""
    if re.match(r"(?i)^sk-[A-Za-z0-9_-]{12,}$", text):
        return ""
    if re.match(r"^[a-z0-9]{2,20}-[A-Za-z0-9_-]{20,}$", text):
        return ""
    if len(text) > 80:
        return f"{text[:24]}...{text[-12:]}"
    return text


def is_codex_email_label(value):
    email = safe_email_from_auth_label(value)
    if not email:
        return False
    local = email.split("@", 1)[0].lower()
    return local.startswith("codex-")


def preferred_reauth_email_label(emails):
    for email in emails:
        if is_codex_email_label(email):
            return email
    return emails[0] if emails else ""


def auth_account_actionable_label_text(item):
    item = dict_or_empty(item)
    email_candidates = [
        item.get("email"),
        item.get("account_email"),
        item.get("user_email"),
        item.get("account"),
        item.get("username"),
        item.get("alias"),
        item.get("label"),
        item.get("name"),
        item.get("file_name"),
        item.get("filename"),
        item.get("identity"),
        item.get("auth_index"),
        item.get("authIndex"),
    ]
    emails = []
    for candidate in email_candidates:
        email = safe_email_from_auth_label(candidate)
        if email:
            emails.append(email)
    if emails:
        return preferred_reauth_email_label(emails)

    label_candidates = [
        item.get("alias"),
        item.get("label"),
        item.get("username"),
        item.get("account"),
        item.get("name"),
        item.get("file_name"),
        item.get("filename"),
        item.get("identity"),
    ]
    for candidate in label_candidates:
        label = safe_non_email_auth_label(candidate)
        if label:
            return label
    return ""


def alert_account_label_from_value(value, identity_key):
    value = str(value or "").strip()
    if value.lower().startswith("hash "):
        return value
    email = safe_email_from_auth_label(value)
    if email:
        return email
    label = safe_non_email_auth_label(value)
    if label:
        return label
    return f"hash {identity_key}"


def reauth_label_identity_key(label):
    label = str(label or "").strip()
    email = safe_email_from_auth_label(label)
    if email:
        local, _, domain = email.lower().partition("@")
        if local.startswith("codex-"):
            local = local[6:]
        return f"email:{local}@{domain}"
    if label.lower().startswith("hash "):
        return re.sub(r"\s+", " ", label.lower())
    normalized = re.sub(r"\s+", " ", label).lower()
    return f"label:{normalized}"


def reauth_label_preference(label):
    label = str(label or "").strip()
    if label.lower().startswith("hash "):
        return 1
    if is_codex_email_label(label):
        return 4
    if safe_email_from_auth_label(label):
        return 3
    return 2


def safe_reauth_render_label(label):
    label = str(label or "").strip()
    if label.lower().startswith("hash "):
        return label
    return alert_account_label_from_value(label, hashlib.sha256(label.encode("utf-8", errors="replace")).hexdigest()[:16])


def auth_account_identity_key(item):
    raw = auth_account_identity(dict_or_empty(item))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def empty_auth_quota_observation(reason=""):
    return {
        "complete": False if reason else True,
        "reason": str(reason or ""),
        "observed_identity_keys": [],
        "healthy_identity_keys": [],
        "failed_identity_keys": [],
        "failed_auth_index_keys": [],
        "failed_labels": {},
        "failed_details": {},
    }


def auth_quota_incomplete_reason(data):
    if not isinstance(data, dict):
        return "malformed-payload"
    if data.get("running"):
        return "refresh-running"
    for key, reason in (
        ("partial", "partial"),
        ("incomplete", "partial"),
        ("cache_incomplete", "cache-incomplete"),
        ("cacheIncomplete", "cache-incomplete"),
        ("quota_cache_incomplete", "cache-incomplete"),
        ("quotaCacheIncomplete", "cache-incomplete"),
        ("refreshing", "refresh-running"),
    ):
        if data.get(key):
            return reason
    if "results" not in data:
        return "results-missing"
    results = data.get("results")
    if results is None:
        return "results-none"
    if not isinstance(results, list):
        return "malformed-results"
    if any(not isinstance(item, dict) for item in results):
        return "malformed-results"
    for key in ("expected_count", "expectedCount", "total", "total_count", "totalCount"):
        if key not in data:
            continue
        try:
            expected = int(data.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if expected > len(results):
            return "count-mismatch"
    return ""


def auth_quota_observation_from_payload(data):
    reason = auth_quota_incomplete_reason(data)
    observation = empty_auth_quota_observation(reason)
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return observation
    complete = not reason
    observed = []
    healthy = []
    failed = []
    failed_auth_indexes = []
    failed_labels = {}
    failed_details = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        identity_key = auth_account_identity_key(item)
        observed.append(identity_key)
        status = str(item.get("status") or "").strip().lower()
        if is_reauth_auth_item(item):
            failed.append(identity_key)
            auth_index_key = auth_index_identity_key(identity_auth_index(item))
            if auth_index_key:
                failed_auth_indexes.append(auth_index_key)
            failed_labels[identity_key] = auth_account_actionable_label_text(item) or safe_auth_account_label(item)
            failed_details[identity_key] = reauth_error_details(item.get("error") or item.get("message") or status or "failed")
        elif complete and (status in {"", "normal", "ok", "healthy", "available", "completed"} or is_quota_disabled_auth_status(status)):
            healthy.append(identity_key)
    observation.update({
        "complete": complete,
        "reason": reason,
        "observed_identity_keys": sorted(set(observed)),
        "healthy_identity_keys": sorted(set(healthy)),
        "failed_identity_keys": sorted(set(failed)),
        "failed_auth_index_keys": sorted(set(failed_auth_indexes)),
        "failed_labels": failed_labels,
        "failed_details": failed_details,
    })
    return observation


def quota_cache_auth_health_observation():
    """Return a sanitized auth-health observation from Usage Keeper cached quota rows.

    This deliberately reads Usage Keeper's cached identity/quota data only; it does
    not trigger quota refresh and does not touch OpenAI/ChatGPT backends directly.
    """
    cookie = usage_keeper_session_cookie()
    if not cookie:
        return empty_auth_quota_observation()
    auth_items = all_known_codex_auth_items(cookie)
    auth_indexes = [identity_quota_cache_index(item) for item in auth_items if identity_quota_cache_index(item)]
    if not auth_indexes:
        return empty_auth_quota_observation()
    labels_by_identity_key = {}
    for item in auth_items:
        label = auth_account_actionable_label_text(item)
        for auth_index in {identity_quota_cache_index(item), identity_auth_index(item)}:
            if auth_index:
                labels_by_identity_key[auth_index_identity_key(auth_index)] = label
    _, data, _ = usage_keeper_request(
        "quota/cache",
        method="POST",
        payload={"auth_indexes": auth_indexes},
        cookie=cookie,
    )
    observed = []
    healthy = []
    failed = []
    failed_auth_indexes = []
    failed_labels = {}
    failed_details = {}
    for auth_index in auth_indexes:
        observed.append(auth_index_identity_key(auth_index))
    for item in payload_items(data):
        item = dict_or_empty(item)
        auth_index = identity_quota_cache_index(item)
        identity_key = auth_index_identity_key(auth_index)
        if not identity_key:
            continue
        if identity_key not in observed:
            observed.append(identity_key)
        if is_reauth_auth_item(item):
            failed.append(identity_key)
            failed_auth_indexes.append(identity_key)
            failed_labels[identity_key] = auth_account_actionable_label_text(item) or labels_by_identity_key.get(identity_key) or f"hash {identity_key}"
            failed_details[identity_key] = reauth_error_details(item.get("error") or item.get("message") or item.get("status") or "failed")
        else:
            healthy.append(identity_key)
    observation = empty_auth_quota_observation()
    observation.update({
        "complete": True,
        "observed_identity_keys": sorted(set(observed)),
        "healthy_identity_keys": sorted(set(healthy) - set(failed)),
        "failed_identity_keys": sorted(set(failed)),
        "failed_auth_index_keys": sorted(set(failed_auth_indexes)),
        "failed_labels": failed_labels,
        "failed_details": failed_details,
    })
    return observation


def merge_auth_quota_observations(primary, extra):
    primary = dict_or_empty(primary)
    extra = dict_or_empty(extra)
    if not extra:
        return dict(primary)
    merged = dict(primary)
    for key in ("observed_identity_keys", "healthy_identity_keys", "failed_identity_keys", "failed_auth_index_keys"):
        merged[key] = sorted(set(list_or_empty(primary.get(key))) | set(list_or_empty(extra.get(key))))
    failed = set(list_or_empty(merged.get("failed_identity_keys")))
    merged["healthy_identity_keys"] = sorted(set(list_or_empty(merged.get("healthy_identity_keys"))) - failed)
    labels = {}
    labels.update(dict_or_empty(primary.get("failed_labels")))
    labels.update(dict_or_empty(extra.get("failed_labels")))
    merged["failed_labels"] = labels
    details = {}
    details.update(dict_or_empty(primary.get("failed_details")))
    details.update(dict_or_empty(extra.get("failed_details")))
    merged["failed_details"] = details
    merged["complete"] = bool(primary.get("complete")) and bool(extra.get("complete", True))
    merged["reason"] = str(primary.get("reason") or extra.get("reason") or "")
    return merged


def quota_inspection_unavailable_category(exc: object) -> str:
    """Map volatile inspection failures to stable alert fingerprint categories.
    
    The alert body still includes raw evidence, but the two-observation gate should
    not reset because timeout wording changes."""
    # Fingerprints use stable categories so the two-observation gate is not reset
    # by volatile timeout wording, while the alert body still shows raw evidence.
    text = str(exc or "").strip().lower()
    if "still running" in text or "running" == text:
        return "refresh-running"
    if isinstance(exc, TimeoutError) or "timed out" in text or "timeout" in text:
        return "timeout"
    if "usage_keeper_password" in text or "not configured" in text:
        return "not-configured"
    if (
        "not an object" in text
        or "malformed" in text
        or "invalid json" in text
        or "results-none" in text
        or "results-missing" in text
        or "malformed-results" in text
    ):
        return "malformed-payload"
    if isinstance(exc, URLError) or any(marker in text for marker in ("connection refused", "network is unreachable", "name or service not known", "temporary failure")):
        return "unreachable"
    return "unknown"


def quota_inspection_unavailable_alert(exc):
    category = quota_inspection_unavailable_category(exc)
    return Alert(
        alert_id="auth:quota-inspection-unavailable",
        severity="warning",
        title="Proxy auth inspection unavailable",
        body=f"Usage Keeper quota inspection did not return fresh account status: {str(exc)[:180]}",
        fingerprint=f"unavailable:{category}",
    )


def auth_inspection_unavailable_for_observation(observation):
    reason = str(dict_or_empty(observation).get("reason") or "malformed-payload")
    if reason == "refresh-running":
        return quota_inspection_unavailable_alert("quota inspection refresh is still running")
    return quota_inspection_unavailable_alert(f"quota inspection malformed payload: {reason}")


def check_auth_quota_status_with_observation(refresh_before_check: bool | None = None, wait_for_refresh: bool = True, wait_seconds: int | None = None, include_cached_disabled_auth: bool = True) -> tuple[list[Alert], dict[str, Any]]:
    """Return auth/reauth alerts plus sanitized auth inspection observation metadata.

    Quota-disabled statuses are ignored because quota enforcement owns those
    transitions; only real account availability/auth failures alert here."""
    try:
        data = quota_inspection_payload(refresh_before_check=refresh_before_check, wait_for_refresh=wait_for_refresh, wait_seconds=wait_seconds)
    except Exception as exc:
        log(f"quota inspection auth check failed: {exc}")
        return [quota_inspection_unavailable_alert(exc)], empty_auth_quota_observation("inspection-unavailable")

    observation = auth_quota_observation_from_payload(data)
    alerts = []
    if not observation.get("complete"):
        alerts.append(auth_inspection_unavailable_for_observation(observation))
        return alerts, observation

    if include_cached_disabled_auth:
        try:
            cache_observation = quota_cache_auth_health_observation()
            observation = merge_auth_quota_observations(observation, cache_observation)
        except Exception as exc:
            log(f"quota cache auth health check failed: {exc.__class__.__name__}")

    failed = []
    results = data.get("results") if isinstance(data, dict) else None
    for item in list_or_empty(results):
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "").strip()
        if is_quota_disabled_auth_status(status):
            continue
        if is_reauth_auth_item(item):
            failed.append(item)
    failed_identity_keys = set(list_or_empty(observation.get("failed_identity_keys")))
    if not failed and not failed_identity_keys:
        return alerts, observation

    failed.sort(key=lambda item: (str(item.get("status") or ""), safe_auth_account_label(item)))
    lines = []
    reported_keys = set()
    for item in failed[:15]:
        identity_key = auth_account_identity_key(item)
        reported_keys.add(identity_key)
        details = reauth_error_details(item.get("error") or item.get("message") or item.get("status") or "failed")
        label_text = auth_account_actionable_label_text(item) or f"hash {identity_key}"
        lines.append(f"- {label_text}: {details}")
    labels = dict_or_empty(observation.get("failed_labels"))
    details_by_key = dict_or_empty(observation.get("failed_details"))
    for identity_key in sorted(failed_identity_keys - reported_keys):
        if len(lines) >= 15:
            break
        label = alert_account_label_from_value(labels.get(identity_key), identity_key)
        details = canonical_reauth_evidence_detail(str(details_by_key.get(identity_key) or "reauth required"))
        lines.append(f"- {label}: {details}")
    if len(failed_identity_keys) > 15:
        lines.append(f"... and {len(failed_identity_keys) - 15} more")
    fingerprint_bits = []
    for item in failed:
        identity_key = auth_account_identity_key(item)
        details = reauth_error_details(item.get("error") or item.get("message") or item.get("status") or "failed")
        fingerprint_bits.append(f"{identity_key}:{details}")
    fingerprint_bits.extend(
        f"{identity_key}:{canonical_reauth_evidence_detail(details_by_key.get(identity_key, ''))}"
        for identity_key in sorted(failed_identity_keys - reported_keys)
    )
    fingerprint_src = "|".join(sorted(fingerprint_bits))
    fingerprint = hashlib.sha256(fingerprint_src.encode("utf-8")).hexdigest()[:16]
    alerts.append(Alert(
        alert_id="auth:quota-inspection-failed",
        severity="critical",
        title="Proxy accounts need reauth",
        body="\n".join(lines),
        fingerprint=fingerprint,
    ))
    return alerts, observation


def check_auth_quota_status(refresh_before_check: bool | None = None, wait_for_refresh: bool = True, wait_seconds: int | None = None, include_cached_disabled_auth: bool = True) -> list[Alert]:
    alerts, _ = check_auth_quota_status_with_observation(
        refresh_before_check=refresh_before_check,
        wait_for_refresh=wait_for_refresh,
        wait_seconds=wait_seconds,
        include_cached_disabled_auth=include_cached_disabled_auth,
    )
    return alerts


def collect_alerts_with_auth_observation(http_results: list[dict[str, Any]] | None | object = _UNSET, auth_refresh_before_check: bool | None = None, auth_wait_for_refresh: bool = True, auth_wait_seconds: int | None = None, include_cached_disabled_auth: bool = True) -> tuple[dict[str, Alert], dict[str, Any]]:
    alerts = []
    alerts.extend(check_http_services(http_results))
    alerts.extend(check_enforcer() or [])
    alerts.extend(check_storage() or [])
    auth_alerts, observation = check_auth_quota_status_with_observation(
        refresh_before_check=auth_refresh_before_check,
        wait_for_refresh=auth_wait_for_refresh,
        wait_seconds=auth_wait_seconds,
        include_cached_disabled_auth=include_cached_disabled_auth,
    )
    alerts.extend(auth_alerts or [])
    return {alert.alert_id: alert for alert in alerts}, observation


def collect_alerts(http_results: list[dict[str, Any]] | None | object = _UNSET, auth_refresh_before_check: bool | None = None, auth_wait_for_refresh: bool = True, auth_wait_seconds: int | None = None, include_cached_disabled_auth: bool = True) -> dict[str, Alert]:
    """Collect service, enforcer, storage, and auth-inspection alerts.

    The returned map is keyed by stable alert id so handlers can track active
    incident fingerprints and recoveries across polling ticks."""
    alerts = []
    alerts.extend(check_http_services(http_results))
    alerts.extend(check_enforcer() or [])
    alerts.extend(check_storage() or [])
    alerts.extend(check_auth_quota_status(
        refresh_before_check=auth_refresh_before_check,
        wait_for_refresh=auth_wait_for_refresh,
        wait_seconds=auth_wait_seconds,
        include_cached_disabled_auth=include_cached_disabled_auth,
    ) or [])
    return {alert.alert_id: alert for alert in alerts}

def severity_icon(severity):
    return {"critical": "[CRITICAL]", "warning": "[WARN]", "info": "[INFO]"}.get(severity, "[ALERT]")

def alert_impact_and_action(alert):
    alert_id = str(alert.alert_id or "")
    if alert_id == "service:cliproxy":
        return (
            "API requests may fail or return errors.",
            "Check docker compose ps, cliproxy logs, and recent config changes.",
        )
    if alert_id == "service:usage-keeper":
        return (
            "Usage dashboard and Telegram usage summaries may be stale or unavailable.",
            "Check docker compose ps and usage-keeper logs.",
        )
    if alert_id == "service:quota-gate":
        return (
            "Quota self-check endpoints may fail, but normal API traffic still uses cliproxy directly.",
            "Check docker compose ps, quota-gate logs, and http://127.0.0.1:8081/quota/healthz.",
        )
    if alert_id.startswith("enforcer:"):
        return (
            "Quota enforcement may stop removing or restoring over-limit keys.",
            "Check systemctl status cliproxy-quota-enforcer.timer and the quota enforcer log.",
        )
    if alert_id == "storage:usage-db-wal-large":
        return (
            "Usage Keeper SQLite WAL is growing; disk usage or backup behavior may need attention.",
            "Check usage-keeper health, disk usage, and whether WAL size keeps increasing.",
        )
    if alert_id == "auth:quota-inspection-failed":
        return (
            "Affected accounts may not serve proxy traffic.",
            "Reauth the listed account(s), then check Health alerts.",
        )
    if alert_id == "auth:quota-inspection-unavailable":
        return (
            "Proxy account availability could not be confirmed from Usage Keeper inspection.",
            "Check Usage Keeper health/logs if this warning persists.",
        )
    if alert_id == "capacity:gpt-pool-5h-low":
        return (
            "5h GPT pool capacity may not cover current demand.",
            "Add more codex/GPT accounts or reduce demand.",
        )
    return (
        "The Telegram monitor detected an issue that may need operator review.",
        "Open Health alerts and Errors today, then inspect the related service logs.",
    )


def alert_display_title(alert):
    alert_id = str(alert.alert_id or "")
    if alert_id == "capacity:gpt-pool-5h-low":
        return "GPT pool 5h capacity low"
    if alert_id == "auth:quota-inspection-unavailable":
        return "Proxy Auth Inspection Unavailable"
    if alert_id == "auth:quota-inspection-failed":
        return str(alert.title or "Proxy accounts need reauth")
    return str(alert.title or "")


def normalize_reauth_render_detail(detail):
    return canonical_reauth_evidence_detail(detail)


def parse_reauth_alert_body(body):
    groups = []
    by_detail = {}
    indexes_by_detail = {}
    extras = []
    for raw in str(body or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("- "):
            item = line[2:].strip()
            if ":" in item:
                label, detail = item.split(":", 1)
                label = label.strip()
                detail = normalize_reauth_render_detail(detail)
            else:
                label = item.strip()
                detail = "reauth required"
            if not label:
                continue
            label = safe_reauth_render_label(label)
            label_key = reauth_label_identity_key(label)
            if detail not in by_detail:
                by_detail[detail] = []
                indexes_by_detail[detail] = {}
                groups.append((detail, by_detail[detail]))
            existing_index = indexes_by_detail[detail].get(label_key)
            if existing_index is None:
                indexes_by_detail[detail][label_key] = len(by_detail[detail])
                by_detail[detail].append(label)
            elif reauth_label_preference(label) > reauth_label_preference(by_detail[detail][existing_index]):
                by_detail[detail][existing_index] = label
        else:
            extras.append(line)
    normalized_groups = [
        (detail, sorted(labels, key=lambda label: (reauth_label_identity_key(label), label.lower())))
        for detail, labels in groups
    ]
    normalized_groups.sort(key=lambda group: group[0].lower())
    return normalized_groups, extras


def build_reauth_alert_message(alert):
    groups, extras = parse_reauth_alert_body(alert.body)
    lines = [
        f"{severity_icon(alert.severity)} {alert_display_title(alert)}",
        "",
    ]
    if groups and len(groups) == 1 and not extras:
        detail, labels = groups[0]
        lines.append(f"Evidence: {detail}")
        lines.extend(f"- {label}" for label in labels)
    elif groups or extras:
        lines.append("Evidence:")
        for detail, labels in groups:
            lines.append(f"Detail: {detail}")
            lines.extend(f"- {label}" for label in labels)
        lines.extend(extras)
    else:
        lines.append("Evidence: No additional evidence was included.")
    lines.extend([
        "",
        "Action:",
        "Reauth the listed account(s), then check Health alerts.",
    ])
    return "\n".join(lines)


def build_alert_message(alert):
    alert_id = str(alert.alert_id or "")
    if alert_id == "auth:quota-inspection-failed":
        return build_reauth_alert_message(alert)
    compact_actions = {
        "auth:codex-free-plan": "Replace the account or renew Plus.",
        "capacity:gpt-pool-5h-low": "Add more codex/GPT accounts or reduce demand.",
    }
    if alert_id in compact_actions:
        return "\n".join([
            f"{severity_icon(alert.severity)} {alert_display_title(alert)}",
            "",
            "Evidence:",
            str(alert.body or "No additional evidence was included."),
            "",
            "Action:",
            compact_actions[alert_id],
        ])

    impact, action = alert_impact_and_action(alert)
    lines = [
        f"{severity_icon(alert.severity)} {alert_display_title(alert)}",
        "",
        "Impact:",
        impact,
        "",
        "Evidence:",
        str(alert.body or "No additional evidence was included."),
        "",
        "Action:",
        action,
    ]
    return "\n".join(lines)

def build_resolved_message(alert_id, old):
    if alert_id == "auth:quota-inspection-failed":
        labels = []
        affected_labels = old.get("affected_labels") if isinstance(old, dict) else None
        if isinstance(affected_labels, dict):
            for identity_key, value in affected_labels.items():
                label = alert_account_label_from_value(value, identity_key)
                if label not in labels:
                    labels.append(label)
        lines = [
            "[OK] Proxy accounts reauth",
            "",
        ]
        if labels:
            lines.append("Recovered:")
            lines.extend(f"- {label}" for label in sorted(labels, key=str.lower))
            lines.append("")
        else:
            lines.append("Recovered: accounts are available again.")
        lines.append("Evidence: latest inspection is healthy.")
        return "\n".join(lines)
    if alert_id == "capacity:gpt-pool-5h-low":
        return "\n".join([
            "[OK] GPT Pool 5h Capacity",
            "",
            "Recovered: 5h GPT pool margin is back above the recovery threshold."
        ])
    if alert_id == "auth:quota-inspection-unavailable":
        return "\n".join([
            "[OK] Proxy Auth Inspection Unavailable",
            "",
            "Recovered from previous warning alert.",
        ])
    title = old.get("title", alert_id)
    severity = old.get("severity", "info")
    return f"[OK] {ALERT_HOSTNAME}: {title}\n\nRecovered from previous {severity} alert."
