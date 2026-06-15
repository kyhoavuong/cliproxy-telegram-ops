import hashlib
import secrets
import string
import time
from datetime import datetime

from .settings import MESSAGES, TELEGRAM_ALLOWED_CHAT_IDS, TELEGRAM_ALLOWED_USER_IDS, TELEGRAM_CHAT_ID

def now_ts():
    return int(time.time())

def msg(key):
    return MESSAGES.get(key, key)

def parse_csv_set(value):
    return {item.strip() for item in str(value or "").split(",") if item.strip()}

def allowed_chat_ids():
    ids = parse_csv_set(TELEGRAM_ALLOWED_CHAT_IDS)
    if TELEGRAM_CHAT_ID:
        ids.add(str(TELEGRAM_CHAT_ID))
    return ids

def alert_chat_ids():
    ids = allowed_chat_ids()
    if not ids and TELEGRAM_CHAT_ID:
        ids.add(str(TELEGRAM_CHAT_ID))
    return sorted(ids)

def allowed_user_ids():
    return parse_csv_set(TELEGRAM_ALLOWED_USER_IDS)

def is_authorized(chat_id, user_id):
    chat_id = str(chat_id or "")
    user_id = str(user_id or "")
    chats = allowed_chat_ids()
    users = allowed_user_ids()
    if users and user_id not in users:
        return False
    if chats and chat_id not in chats:
        return False
    return bool(chats or users)

def short_code(length=6):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def log(message):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)

def monotonic_ms():
    return int(time.monotonic() * 1000)

def log_timing(label, started_ms, **fields):
    elapsed = monotonic_ms() - int(started_ms)
    safe_fields = []
    for key, value in fields.items():
        if value is None:
            continue
        safe_fields.append(f"{key}={value}")
    suffix = " " + " ".join(safe_fields) if safe_fields else ""
    log(f"timing {label} ms={elapsed}{suffix}")
    return elapsed

def normalize_limit(value):
    if value is None:
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None

def mask_key(key):
    key = str(key or "")
    if len(key) <= 12:
        return key[:3] + "***" + key[-3:]
    return key[:5] + "***" + key[-5:]

def key_ref(key):
    return hashlib.sha256(str(key).encode("utf-8")).hexdigest()[:12]


def percent(used, limit):
    if not limit:
        return None
    return round((used / limit) * 100, 2)

def fmt_tokens(value):
    value = int(value or 0)
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(value)

def fmt_limit(value):
    if value is None:
        return "unlimited"
    return fmt_tokens(value)

def fmt_duration(seconds):
    seconds = max(0, int(seconds or 0))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    if days:
        return f"{days}d{hours}h"
    if hours:
        return f"{hours}h{minutes}m"
    if minutes:
        return f"{minutes}m{seconds}s"
    return f"{seconds}s"
