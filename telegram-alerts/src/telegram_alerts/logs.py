"""Sanitized log summarizer for the Telegram Errors Today screen."""

import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .settings import CLIPROXY_LOG_DIR, ENFORCER_LOG, USAGE_DB, USAGE_KEEPER_LOG_DIR
from .quota_config import load_quotas_json, window_utc

LOG_PATTERNS = re.compile(r"\b(error|warn|warning|critical|failed|failure|panic|unhealthy|exception)\b", re.IGNORECASE)

SECRET_PATTERNS = [
    re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"([?&](?:key|token|auth_token)=)[^&\s]+", re.IGNORECASE),
    re.compile(r"((?:api[_-]?key|token|password|secret)[\"'=:\s]+)[^\"'\s,}]+", re.IGNORECASE),
]

HTTP_STATUS_TEXT = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    408: "Timeout",
    409: "Conflict",
    422: "Validation Error",
    429: "Rate Limited",
    500: "Internal Error",
    502: "Bad Gateway",
    503: "Unavailable",
    504: "Gateway Timeout",
}

HTTP_LOG_PATTERN = re.compile(r"\b([1-5]\d\d)\s*\|\s*[^|]*\|\s*([0-9a-fA-F:.]+)\s*\|\s*([A-Z]+)\s+\"([^\"]+)\"")

LOG_TS_PATTERN = re.compile(r"\[(\d{4}-\d{2}-\d{2} [^\]]+)\]")

RATE_LIMIT_BACKEND = "backend"
RATE_LIMIT_FRONTDOOR = "frontdoor"
RATE_LIMIT_AMBIGUOUS = "ambiguous"

def sanitize_log_line(line):
    line = str(line).strip()
    for pattern in SECRET_PATTERNS:
        line = pattern.sub(r"\1***", line)
    if len(line) > 360:
        line = line[:357] + "..."
    return line

def newest_log_files(paths, limit):
    return sorted(paths, key=lambda path: path.stat().st_mtime if path.exists() else 0, reverse=True)[:limit]

def log_files_for_source(source):
    source = str(source or "all").lower()
    files = []
    try:
        usage_logs = list(USAGE_KEEPER_LOG_DIR.glob("*.log"))
    except PermissionError:
        usage_logs = []
    try:
        cliproxy_logs = [path for path in CLIPROXY_LOG_DIR.glob("*.log") if not path.name.startswith("error-")]
    except PermissionError:
        cliproxy_logs = []

    if source == "all":
        files.extend(newest_log_files(usage_logs, 3))
        if ENFORCER_LOG.exists():
            files.append(ENFORCER_LOG)
        files.extend(newest_log_files(cliproxy_logs, 3))
        return sorted(files, key=lambda path: path.stat().st_mtime if path.exists() else 0, reverse=True)

    if source in {"usage", "usage-keeper"}:
        files.extend(usage_logs)
    if source in {"enforcer", "quota", "quota-enforcer"} and ENFORCER_LOG.exists():
        files.append(ENFORCER_LOG)
    if source in {"cliproxy", "proxy"}:
        files.extend(cliproxy_logs)
    return sorted(files, key=lambda path: path.stat().st_mtime if path.exists() else 0, reverse=True)

def tail_lines(path, max_lines=600, chunk_size=64 * 1024):
    try:
        with path.open("rb") as file:
            file.seek(0, os.SEEK_END)
            offset = file.tell()
            data = b""
            while offset > 0 and data.count(b"\n") <= max_lines:
                read_size = min(chunk_size, offset)
                offset -= read_size
                file.seek(offset)
                data = file.read(read_size) + data
        lines = data.splitlines()[-max_lines:]
        return [line.decode("utf-8", errors="replace") for line in lines]
    except Exception as exc:
        raise RuntimeError(f"unreadable ({exc})") from exc

def local_tz_name():
    try:
        cfg = load_quotas_json()
        return str(cfg.get("timezone") or "Asia/Ho_Chi_Minh")
    except Exception:
        return "Asia/Ho_Chi_Minh"

def format_local_hhmmss_from_ts(ts):
    if not ts:
        return "unknown"
    try:
        tz = ZoneInfo(local_tz_name())
    except Exception:
        tz = timezone(timedelta(hours=7))
    return datetime.fromtimestamp(int(ts), tz).strftime("%H:%M:%S")

def usage_request_summary_today():
    try:
        tz_name = local_tz_name()
        start, end = window_utc(tz_name, "daily")
        conn = sqlite3.connect(f"file:{USAGE_DB}?mode=ro", uri=True, timeout=4)
        try:
            row = conn.execute(
                """
                SELECT COUNT(*), COALESCE(SUM(CASE WHEN failed THEN 1 ELSE 0 END), 0)
                FROM usage_events
                WHERE datetime(timestamp) >= datetime(?)
                  AND datetime(timestamp) < datetime(?)
                """,
                (start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S")),
            ).fetchone()
        finally:
            conn.close()
        total = int(row[0] or 0)
        failed = int(row[1] or 0)
        success = max(0, total - failed)
        rate = (failed / total * 100) if total else 0
        return {"total": total, "success": success, "failed": failed, "failed_rate": rate, "error": ""}
    except Exception as exc:
        return {"total": 0, "success": 0, "failed": 0, "failed_rate": 0, "error": str(exc)}

def count_map_increment(counts, key, amount=1):
    if not key:
        return
    counts[key] = counts.get(key, 0) + amount

def top_counts(counts, limit=5):
    return sorted(counts.items(), key=lambda item: (-item[1], str(item[0])))[:limit]

def parse_error_event(path, line):
    clean = sanitize_log_line(line)
    try:
        mtime = int(path.stat().st_mtime)
    except Exception:
        mtime = 0
    event = {
        "file": path.name,
        "raw": f"{path.name}: {clean}",
        "timestamp": "",
        "mtime": mtime,
        "status": None,
        "method": "",
        "endpoint": "",
        "ip": "",
    }
    ts_match = LOG_TS_PATTERN.search(clean)
    if ts_match:
        event["timestamp"] = ts_match.group(1)
    http_match = HTTP_LOG_PATTERN.search(clean)
    if http_match:
        status = int(http_match.group(1))
        endpoint = http_match.group(4).split("?", 1)[0]
        event.update({
            "status": status,
            "ip": http_match.group(2),
            "method": http_match.group(3),
            "endpoint": endpoint,
        })
    return event

def recent_error_events(source="all", limit=80):
    events = []
    for path in log_files_for_source(source)[:8]:
        try:
            content = tail_lines(path, max_lines=900)
        except Exception as exc:
            events.append({
                "file": path.name,
                "raw": f"{path.name}: unreadable ({exc})",
                "timestamp": "",
                "mtime": 0,
                "status": None,
                "method": "",
                "endpoint": "",
                "ip": "",
            })
            continue

        for line in reversed(content):
            event = parse_error_event(path, line)
            if LOG_PATTERNS.search(line) or (event.get("status") and event["status"] >= 400):
                events.append(event)
                if len(events) >= limit:
                    return events
    return events

def describe_error_meaning(status):
    if status == 502:
        return "502 means upstream call failed after reaching cliproxy."
    if status == 504:
        return "504 means the upstream call timed out."
    if status == 503:
        return "503 means upstream service or provider is temporarily unavailable."
    if status == 429:
        return "429 means a provider, key, or quota limit is throttling requests."
    if status in {401, 403}:
        return "401/403 means auth, key, permission, or provider access rejected the request."
    if status and status >= 500:
        return "5xx means proxy/upstream handling failed."
    if status and status >= 400:
        return "4xx means the request was rejected before a successful model response."
    return ""

def event_upstream_status(event):
    for key in ("upstream_status", "us"):
        value = event.get(key)
        if value is not None:
            return str(value).strip().strip('"')
    return None

def is_cliproxy_app_log_event(event):
    file_name = str(event.get("file") or "").strip()
    source = str(event.get("source") or "").strip().lower()
    if source in {"cliproxy", "proxy"}:
        return True
    return file_name == "main.log" or file_name.startswith("main-")

def rate_limit_attribution(event):
    if event.get("status") != 429:
        return ""

    upstream_status = event_upstream_status(event)
    if upstream_status is not None:
        if upstream_status in {"", "-"}:
            return RATE_LIMIT_FRONTDOOR
        if upstream_status == "429":
            return RATE_LIMIT_BACKEND
        return RATE_LIMIT_AMBIGUOUS

    endpoint = str(event.get("endpoint") or "").strip().lower()
    if endpoint.startswith("/v1/") and is_cliproxy_app_log_event(event):
        return RATE_LIMIT_BACKEND

    return RATE_LIMIT_AMBIGUOUS

def status_label_for_event(event):
    status = event.get("status")
    if status == 429:
        attribution = rate_limit_attribution(event)
        if attribution == RATE_LIMIT_BACKEND:
            return "Backend/Upstream Rate Limited"
        if attribution == RATE_LIMIT_FRONTDOOR:
            return "Nginx/Frontdoor Rate Limited"
    return HTTP_STATUS_TEXT.get(status, "HTTP error")

def dominant_rate_limit_attribution(events):
    counts = {}
    for event in events:
        attribution = rate_limit_attribution(event)
        if attribution:
            count_map_increment(counts, attribution)
    top = top_counts(counts, 2)
    if not top:
        return RATE_LIMIT_AMBIGUOUS
    if len(top) > 1 and top[0][1] == top[1][1]:
        return RATE_LIMIT_AMBIGUOUS
    return top[0][0]

def describe_rate_limit_action(attribution):
    if attribution == RATE_LIMIT_BACKEND:
        return "429 came from backend/upstream; check provider/account throttling, model concurrency, or account rotation."
    if attribution == RATE_LIMIT_FRONTDOOR:
        return "429 came from nginx/frontdoor; check rate/connection limits and client burstiness."
    return "429 attribution is unclear; compare nginx upstream status with backend logs."

def is_proxy_traffic_error(event):
    status = event.get("status")
    endpoint = str(event.get("endpoint") or "").strip().lower()
    if not status or status < 400 or not endpoint:
        return False
    if endpoint.startswith("/v0/management"):
        return False
    if endpoint in {"/healthz", "/health", "/ready", "/metrics"}:
        return False
    if any(part in endpoint for part in ("/management", "/admin", "/auth", "/login")):
        return False
    return endpoint.startswith("/v1/")


def build_errors_reply(source="all"):
    """Build a secret-sanitized error summary that combines CPA failures with proxy traffic errors."""
    source = str(source or "all").lower()
    allowed = {"all", "usage", "usage-keeper", "enforcer", "quota", "quota-enforcer", "cliproxy", "proxy"}
    if source not in allowed:
        return "Open Errors today from /menu."
    events = recent_error_events(source=source)
    usage = usage_request_summary_today()
    proxy_events = [event for event in events if is_proxy_traffic_error(event)]

    status_counts = {}
    status_label_counts = {}
    endpoint_counts = {}
    for event in proxy_events:
        status = event.get("status")
        if status:
            count_map_increment(status_counts, status)
            count_map_increment(status_label_counts, f"{status} {status_label_for_event(event)}")
        endpoint = " ".join(part for part in [event.get("method"), event.get("endpoint")] if part)
        count_map_increment(endpoint_counts, endpoint)

    latest_source_events = proxy_events or events
    latest_mtime = max((int(event.get("mtime", 0) or 0) for event in latest_source_events), default=0)
    top_status = top_counts(status_counts, 1)
    main_status = top_status[0][0] if top_status else None
    lines = ["Errors Today", "", "Summary"]

    if usage.get("error"):
        lines.append(f"- CPA failed: unavailable ({usage['error']})")
    else:
        lines.append(
            f"- CPA failed: {int(usage['failed'] or 0):,} / {int(usage['total'] or 0):,} "
            f"({float(usage['failed_rate'] or 0):.2f}%)"
        )
    lines.append(f"- Proxy HTTP failures: {len(proxy_events)}")
    lines.append(f"- Latest error: {format_local_hhmmss_from_ts(latest_mtime)}")

    lines.extend(["", "Breakdown"])
    if proxy_events:
        for label, count in top_counts(status_label_counts):
            lines.append(f"- Status: {label} x{count}")
        for endpoint, count in top_counts(endpoint_counts):
            lines.append(f"- Endpoint: {endpoint} x{count}")
    else:
        lines.append("- No proxy traffic errors in recent logs")

    lines.extend(["", "Action"])
    if main_status == 429:
        rate_limit_events = [event for event in proxy_events if event.get("status") == 429]
        lines.append(f"- {describe_rate_limit_action(dominant_rate_limit_attribution(rate_limit_events))}")
    else:
        meaning = describe_error_meaning(main_status)
        if meaning:
            lines.append(f"- {meaning}")
        lines.append("- If failures keep rising, check provider/upstream or docker logs.")
    return "\n".join(lines)
