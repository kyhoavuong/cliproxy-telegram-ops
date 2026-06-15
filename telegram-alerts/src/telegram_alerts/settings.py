import os
import threading
import time
from pathlib import Path

def env_int(name, default):
    raw = os.environ.get(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default

def env_float(name, default):
    raw = os.environ.get(name, "")
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default

def env_bool(name, default=False):
    raw = os.environ.get(name, "")
    if raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}

BASE_DIR = Path(os.environ.get("CLIPROXY_BASE_DIR", "/opt/cliproxy"))

QUOTA_CONFIG = BASE_DIR / "quota-enforcer" / "quotas.json"

QUOTA_STATE = BASE_DIR / "quota-enforcer" / "state.json"

ENFORCER_LOG = BASE_DIR / "quota-enforcer" / "enforcer.log"

CLIPROXY_CONFIG = BASE_DIR / "config" / "config.yaml"

AUTH_DIR = BASE_DIR / "data" / "auth"

USAGE_DB = BASE_DIR / "usage-keeper" / "app.db"

STATE_FILE = Path(os.environ.get("ALERT_STATE_FILE", "/state/telegram_alerts_state.json"))

CLIPROXY_LOG_DIR = BASE_DIR / "logs"

USAGE_KEEPER_LOG_DIR = BASE_DIR / "usage-keeper" / "logs"

CHECKS = {
    "cliproxy": os.environ.get("ALERT_CLIPROXY_HEALTH_URL", "http://cliproxy:3000/healthz"),
    "usage-keeper": os.environ.get("ALERT_USAGE_KEEPER_HEALTH_URL", "http://usage-keeper:8080/usage/healthz"),
    "quota-gate": os.environ.get("ALERT_QUOTA_GATE_HEALTH_URL", "http://quota-gate:8081/quota/healthz"),
}

INTERVAL_SECONDS = env_int("ALERT_INTERVAL_SECONDS", 15)

HTTP_TIMEOUT_SECONDS = env_int("ALERT_HTTP_TIMEOUT_SECONDS", 8)

QUOTA_WARN_PERCENT = env_float("ALERT_QUOTA_WARN_PERCENT", 85.0)

QUOTA_CRITICAL_PERCENT = env_float("ALERT_QUOTA_CRITICAL_PERCENT", 98.0)

ENFORCER_MAX_AGE_SECONDS = env_int("ALERT_ENFORCER_MAX_AGE_SECONDS", 5 * 60)

DB_WAL_WARN_BYTES = env_int("ALERT_DB_WAL_WARN_BYTES", 512 * 1024 * 1024)

USAGE_KEEPER_BASE_URL = os.environ.get("USAGE_KEEPER_BASE_URL", "http://usage-keeper:8080/usage").rstrip("/")

USAGE_KEEPER_PASSWORD = os.environ.get("USAGE_KEEPER_PASSWORD", "")

CLIPROXY_MANAGEMENT_BASE_URL = os.environ.get("CLIPROXY_MANAGEMENT_BASE_URL", "http://cliproxy:3000/v0/management").rstrip("/")

CLIPROXY_MANAGEMENT_TOKEN = (os.environ.get("CLIPROXY_MANAGEMENT_TOKEN", "") or os.environ.get("CPA_MANAGEMENT_KEY", "")).strip()

API_PUBLIC_BASE_URL = os.environ.get("API_PUBLIC_BASE_URL", "http://localhost:3000").rstrip("/")

CLIPROXY_MANAGEMENT_FALLBACK_ENABLED = env_bool("CLIPROXY_MANAGEMENT_FALLBACK_ENABLED", bool(CLIPROXY_MANAGEMENT_TOKEN))

AUTH_QUOTA_REFRESH_BEFORE_CHECK = env_bool("AUTH_QUOTA_REFRESH_BEFORE_CHECK", True)

AUTH_QUOTA_REFRESH_COOLDOWN_SECONDS = env_int("AUTH_QUOTA_REFRESH_COOLDOWN_SECONDS", 5 * 60)

AUTH_QUOTA_INSPECTION_WAIT_SECONDS = env_int("AUTH_QUOTA_INSPECTION_WAIT_SECONDS", 60)

AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS = env_int("AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS", 30 * 60)

AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS = env_int("AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS", 5 * 60)

AUTH_INSPECTION_UNAVAILABLE_RECOVER_AFTER_SECONDS = env_int("AUTH_INSPECTION_UNAVAILABLE_RECOVER_AFTER_SECONDS", 5 * 60)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()

TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

TELEGRAM_ALLOWED_CHAT_IDS = os.environ.get("TELEGRAM_ALLOWED_CHAT_IDS", "").strip()

TELEGRAM_ALLOWED_USER_IDS = os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "").strip()

ALERT_HOSTNAME = os.environ.get("ALERT_HOSTNAME", "cliproxy")

DRY_RUN = os.environ.get("ALERT_DRY_RUN", "").lower() in {"1", "true", "yes", "on"}

COMMAND_POLL_SECONDS = env_float("ALERT_COMMAND_POLL_SECONDS", 0.25)

TELEGRAM_GET_UPDATES_TIMEOUT_SECONDS = env_int("TELEGRAM_GET_UPDATES_TIMEOUT_SECONDS", 5)

SNAPSHOT_MAX_AGE_SECONDS = env_int("ALERT_SNAPSHOT_MAX_AGE_SECONDS", 120)

CAPACITY_CHECK_FAST_CACHE_SECONDS = env_int("CAPACITY_CHECK_FAST_CACHE_SECONDS", 60)

QUOTA_MANAGEMENT_FAST_CACHE_SECONDS = env_int("QUOTA_MANAGEMENT_FAST_CACHE_SECONDS", 60)

ERRORS_FAST_CACHE_SECONDS = env_int("ERRORS_FAST_CACHE_SECONDS", 60)

USAGE_REPORT_CACHE_SECONDS = env_int("USAGE_REPORT_CACHE_SECONDS", 20)

TELEGRAM_CLEAR_MAX_MESSAGES = env_int("TELEGRAM_CLEAR_MAX_MESSAGES", 5000)

TELEGRAM_CLEAR_STOP_AFTER_MISSES = env_int("TELEGRAM_CLEAR_STOP_AFTER_MISSES", 120)

TELEGRAM_CLEAR_WORKERS = env_int("TELEGRAM_CLEAR_WORKERS", 16)

TELEGRAM_CLEAR_BATCH_SIZE = env_int("TELEGRAM_CLEAR_BATCH_SIZE", 80)

TELEGRAM_KNOWN_MESSAGES_MAX = env_int("TELEGRAM_KNOWN_MESSAGES_MAX", 600)

BOT_STARTED_AT = int(time.time())

BOT_COMMANDS_VERSION = 17

PENDING_ACTION_TTL_SECONDS = 5 * 60

TELEGRAM_MESSAGE_MAX_CHARS = env_int("TELEGRAM_MESSAGE_MAX_CHARS", 3900)

ACTION_BACKUP_KEEP = env_int("ACTION_BACKUP_KEEP", 50)

ACTION_BACKUP_MAX_AGE_DAYS = env_int("ACTION_BACKUP_MAX_AGE_DAYS", 3)

ACTION_BACKUP_INCLUDE_USAGE_DB = env_bool("ACTION_BACKUP_INCLUDE_USAGE_DB", False)

CHANGE_WATCH_INTERVAL_SECONDS = env_int("CHANGE_WATCH_INTERVAL_SECONDS", 2)

CHANGE_NOTIFICATION_DEBOUNCE_SECONDS = env_int("CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3)

CHANGE_REMOVAL_DEBOUNCE_SECONDS = env_int("CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8)

CPA_REGISTRY_SYNC_INTERVAL_SECONDS = env_int("CPA_REGISTRY_SYNC_INTERVAL_SECONDS", 30)

QUOTA_PICKER_PAGE_SIZE = env_int("QUOTA_PICKER_PAGE_SIZE", 12)

CLEAR_LOCK = threading.Lock()

CLEAR_ACTIVE_CHATS = set()

MESSAGES = {
    "confirm": "Confirm",
    "cancel": "Cancel",
    "cancelled": "Pending action cancelled.",
    "no_pending": "No pending action.",
    "confirmed": "Confirmed.",
    "invalid_code": "Invalid confirmation code.",
    "expired": "Pending action expired.",
    "pending_expired": "Pending action expired. Send the command again.",
    "pending_unknown": "Unknown pending action cancelled.",
    "confirm_hint": "Tap Confirm to apply or Cancel to discard. This expires in 5 minutes.",
    "confirm_mismatch": "This button belongs to an older action, so it was not applied.",
    "invalid_input": "Invalid input",
    "clear_invalid": "Usage: /clear or /clear 200",
    "clear_done": "Cleared {deleted} message(s).",
    "unknown_command": "Unknown command. Use /menu to choose an action.",
    "key_create_prompt": "\n".join([
        "Create Key",
        "",
        "Send one line:",
        "alias, name, tokens/day",
        "",
        "Examples:",
        "exampleuser, hung, 100M",
        "exampleuser, hung",
        "",
        "Use none or leave tokens/day empty for unlimited.",
    ]),
}
