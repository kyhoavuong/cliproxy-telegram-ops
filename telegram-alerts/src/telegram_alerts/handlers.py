"""Telegram command/callback router and alert-delivery state machine."""

from __future__ import annotations
from typing import Any
from .contracts import TelegramReply

import hashlib
import shlex
import threading
from urllib.error import HTTPError, URLError

from .settings import (
    AUTH_INSPECTION_UNAVAILABLE_RECOVER_AFTER_SECONDS,
    AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS,
    AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS,
    CAPACITY_CHECK_FAST_CACHE_SECONDS,
    DRY_RUN,
    ERRORS_FAST_CACHE_SECONDS,
    STATE_FILE,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CLEAR_MAX_MESSAGES,
)
from .utils import alert_chat_ids, allowed_chat_ids, allowed_user_ids, is_authorized, log, log_timing, monotonic_ms, msg, now_ts
from .storage import save_json
from .keyboards import back_keyboard, errors_keyboard, key_status_keyboard, menu_keyboard, reply, silent_reply, top_users_keyboard
from .telegram_client import (
    delete_telegram_message_async,
    edit_telegram_message_result,
    remember_message,
    remember_sent_messages,
    send_reply,
    send_telegram,
    start_clear_chat_messages,
    telegram_api,
    telegram_get_updates,
)
from .snapshot import (
    build_alerts_reply,
    build_capacity_reply,
    build_health_alerts_snapshot,
    build_key_status_reply,
    build_overview_reply,
    build_quota_rows_snapshot,
    build_quota_management_reply,
    build_quota_reply,
    build_top_reply,
    get_capacity_check_snapshot,
    get_quota_management_snapshot,
    get_snapshot,
    capacity_demand_rate_estimate,
)
from .logs import build_errors_reply
from .actions import cancel_pending, cancel_token_for_pending, cleanup_message_ids_from, clear_pending_action, clear_pending_input, execute_pending_action, handle_pending_input, pending_scope
from .pickers import (
    build_daily_quota_limit_picker,
    create_key_management_from_picker,
    build_key_reveal_from_picker,
    build_quota_limit_picker,
    build_same_key_quota_limit_picker,
    build_weekly_quota_limit_picker,
    build_usage_report_from_picker,
    create_quota_update_from_picker,
    create_weekly_quota_update_from_picker,
    prompt_key_create,
    prompt_key_lookup,
    prompt_key_management_picker,
    prompt_key_reveal_picker,
    prompt_quota_picker,
    prompt_usage_picker,
)
from .health import build_alert_message, build_resolved_message, reauth_label_identity_key

def health_alerts_snapshot_for_reply(snapshot, state):
    filtered = dict(snapshot or {})
    alerts = dict(filtered.get("system_alerts") or {})
    active_state = state.get("active", {}) if isinstance(state, dict) else {}
    if not isinstance(active_state, dict):
        active_state = {}
    active_record = active_state.get(AUTH_INSPECTION_UNAVAILABLE_ID)
    active_record = active_record if isinstance(active_record, dict) else None

    if AUTH_INSPECTION_UNAVAILABLE_ID in alerts and not active_record:
        alerts.pop(AUTH_INSPECTION_UNAVAILABLE_ID, None)
    elif active_record and AUTH_INSPECTION_UNAVAILABLE_ID not in alerts:
        alerts[AUTH_INSPECTION_UNAVAILABLE_ID] = {
            "alert_id": AUTH_INSPECTION_UNAVAILABLE_ID,
            "severity": "warning",
            "title": str(active_record.get("title") or "Proxy auth inspection unavailable")[:120],
            "body": "",
            "fingerprint": str(active_record.get("fingerprint") or AUTH_INSPECTION_UNAVAILABLE_ID)[:120],
        }
    filtered["system_alerts"] = alerts
    return filtered


START_INITIALIZED_KEY = "start_initialized"
START_MENU_ONCE_AFTER_CLEAR_KEY = "start_menu_once_after_clear"
MENU_MESSAGES_KEY = "menu_messages"


def _cache_age_seconds(snapshot):
    try:
        return now_ts() - int((snapshot or {}).get("created_at", 0) or 0)
    except (AttributeError, TypeError, ValueError):
        return 10**9


def _fresh_cached_payload(payload, max_age_seconds):
    return isinstance(payload, dict) and _cache_age_seconds(payload) <= max(0, int(max_age_seconds or 0))


def prewarm_menu_fast_caches(state, snapshot, include_errors=False):
    """Prime cheap menu-adjacent caches after the Overview snapshot is already available."""
    if not isinstance(state, dict) or not isinstance(snapshot, dict):
        return
    cached_capacity = state.get("capacity_check_snapshot")
    if not _fresh_cached_payload(cached_capacity, CAPACITY_CHECK_FAST_CACHE_SECONDS):
        state["capacity_check_snapshot"] = snapshot

    if not include_errors:
        return
    cache = state.setdefault("errors_reply_cache", {})
    if not isinstance(cache, dict):
        cache = {}
        state["errors_reply_cache"] = cache
    cached_errors = cache.get("all")
    if _fresh_cached_payload(cached_errors, ERRORS_FAST_CACHE_SECONDS) and isinstance(cached_errors.get("text"), str):
        return
    try:
        cache["all"] = {"created_at": now_ts(), "text": build_errors_reply("all")}
    except Exception as exc:
        log(f"errors cache prewarm skipped: {exc}")


def build_menu_reply(state, live=False):
    snapshot = get_snapshot(state, live=live, interactive=True)
    snapshot = health_alerts_snapshot_for_reply(snapshot, state)
    prewarm_menu_fast_caches(state, snapshot)
    return reply(build_overview_reply(snapshot), menu_keyboard())


def prune_menu_messages(state, chat_id, keep_message_id=None):
    chat_key = str(chat_id or "")
    if not chat_key:
        return
    menu_messages = state.setdefault(MENU_MESSAGES_KEY, {})
    if not isinstance(menu_messages, dict):
        menu_messages = {}
        state[MENU_MESSAGES_KEY] = menu_messages
    old_ids = list(menu_messages.get(chat_key) or [])
    safe_ids = set()
    for item in old_ids:
        try:
            message_id = int(item or 0)
        except (TypeError, ValueError):
            continue
        if message_id > 0:
            safe_ids.add(message_id)
    try:
        keep_message_id = int(keep_message_id or 0)
    except (TypeError, ValueError):
        keep_message_id = 0
    for message_id in sorted(safe_ids):
        if keep_message_id and message_id == keep_message_id:
            continue
        delete_telegram_message_async(chat_key, message_id)
    menu_messages[chat_key] = [keep_message_id] if keep_message_id and keep_message_id in safe_ids else []


def remember_menu_message(state, chat_id, message_id):
    try:
        message_id = int(message_id or 0)
    except (TypeError, ValueError):
        return
    chat_id = str(chat_id or "")
    if not chat_id or message_id <= 0:
        return
    remember_menu_messages(state, [{"chat_id": chat_id, "message_id": message_id}])


def remember_menu_messages(state, sent_messages):
    if not isinstance(sent_messages, list):
        return
    grouped = {}
    for item in sent_messages:
        if not isinstance(item, dict):
            continue
        chat_id = str(item.get("chat_id") or "")
        try:
            message_id = int(item.get("message_id") or 0)
        except (TypeError, ValueError):
            continue
        if chat_id and message_id > 0:
            grouped.setdefault(chat_id, []).append(message_id)
    if not grouped:
        return
    menu_messages = state.setdefault(MENU_MESSAGES_KEY, {})
    if not isinstance(menu_messages, dict):
        menu_messages = {}
        state[MENU_MESSAGES_KEY] = menu_messages
    for chat_id, message_ids in grouped.items():
        menu_messages[chat_id] = sorted(set(message_ids))


def sent_message_ids_for_chat(sent_messages, chat_id):
    ids = []
    chat_key = str(chat_id or "")
    if not isinstance(sent_messages, list):
        return ids
    for item in sent_messages:
        if not isinstance(item, dict) or str(item.get("chat_id") or "") != chat_key:
            continue
        try:
            message_id = int(item.get("message_id") or 0)
        except (TypeError, ValueError):
            continue
        if message_id > 0 and message_id not in ids:
            ids.append(message_id)
    return ids


def remember_pending_input_prompt_messages(state, reply_data, chat_id=None, user_id=None, sent_messages=None, message_id=None):
    if not isinstance(reply_data, dict) or reply_data.get("track_pending_input_prompt") != "key_create":
        return
    ids = sent_message_ids_for_chat(sent_messages, chat_id)
    if not ids:
        try:
            current_id = int(message_id or 0)
        except (TypeError, ValueError):
            current_id = 0
        if current_id > 0:
            ids = [current_id]
    if not ids:
        return
    pending_inputs = state.get("pending_inputs")
    if not isinstance(pending_inputs, dict):
        return
    pending = pending_inputs.get(pending_scope(chat_id, user_id))
    if isinstance(pending, dict) and pending.get("type") == "key_create":
        pending["cleanup_message_ids"] = ids


def delete_reply_cleanup_messages(reply_data, chat_id, current_message_id=None):
    if not isinstance(reply_data, dict):
        return
    try:
        current_id = int(current_message_id or 0)
    except (TypeError, ValueError):
        current_id = 0
    for item in reply_data.get("delete_message_ids") or []:
        try:
            message_id = int(item or 0)
        except (TypeError, ValueError):
            continue
        if message_id > 0 and message_id != current_id:
            delete_telegram_message_async(chat_id, message_id)


def cached_capacity_demand_rate(snapshot):
    if isinstance(snapshot, dict):
        rate = snapshot.get("capacity_check_demand_rate") or snapshot.get("capacity_demand_rate")
        if isinstance(rate, dict):
            return rate
    return {
        "tokens": 0,
        "requests": 0,
        "hours": 0,
        "tokens_per_hour": 0,
        "lookback_hours": 0,
        "source": "unavailable",
        "error": "cached demand rate unavailable",
    }


def live_capacity_demand_rate(snapshot):
    rate = capacity_demand_rate_estimate()
    if isinstance(snapshot, dict):
        snapshot["capacity_check_demand_rate"] = rate
    return rate


def get_errors_reply(state, source="all", live=False):
    source = str(source or "all").lower()
    ts = now_ts()
    cache = state.setdefault("errors_reply_cache", {})
    if not isinstance(cache, dict):
        cache = {}
        state["errors_reply_cache"] = cache
    cached = cache.get(source)
    if not live and isinstance(cached, dict):
        try:
            age = ts - int(cached.get("created_at", 0) or 0)
        except (TypeError, ValueError):
            age = ERRORS_FAST_CACHE_SECONDS + 1
        text = cached.get("text")
        if isinstance(text, str) and age <= max(0, int(ERRORS_FAST_CACHE_SECONDS or 0)):
            return text
    text = build_errors_reply(source)
    cache[source] = {"created_at": ts, "text": text}
    return text


def scoped_start_maps(state, chat_id=None, user_id=None):
    scope = pending_scope(chat_id, user_id)
    maps = []
    for field in (START_INITIALIZED_KEY, START_MENU_ONCE_AFTER_CLEAR_KEY):
        value = state.setdefault(field, {})
        if not isinstance(value, dict):
            value = {}
            state[field] = value
        maps.append(value)
    return scope, maps[0], maps[1]


def should_open_start_menu(state, chat_id=None, user_id=None):
    scope, initialized, once_after_clear = scoped_start_maps(state, chat_id=chat_id, user_id=user_id)
    first_start = not bool(initialized.get(scope))
    after_clear = bool(once_after_clear.pop(scope, None))
    if first_start or after_clear:
        initialized[scope] = True
        return True
    return False


def mark_start_menu_once_after_clear(state, chat_id=None, user_id=None):
    scope, _, once_after_clear = scoped_start_maps(state, chat_id=chat_id, user_id=user_id)
    once_after_clear[scope] = True

def pending_interaction_active(state, chat_id=None, user_id=None):
    scope = pending_scope(chat_id, user_id)
    ts = now_ts()
    for field, legacy_field in (("pending_inputs", "pending_input"), ("pending_actions", "pending_action")):
        items = state.get(field)
        if isinstance(items, dict):
            pending = items.get(scope)
            if isinstance(pending, dict) and ts <= int(pending.get("expires_at", 0) or 0):
                return True
        legacy = state.get(legacy_field)
        if isinstance(legacy, dict) and ts <= int(legacy.get("expires_at", 0) or 0):
            return True
    return False

def send_auto_alert(message, state, dry_run=False):
    sent = 0
    for target_chat_id in alert_chat_ids():
        if send_telegram(message, dry_run=dry_run, chat_id=target_chat_id):
            sent += 1
    return sent, 0

def handle_command(text: str, state: dict[str, Any], chat_id: str | None = None, user_id: str | None = None, message_id: int | str | None = None) -> str | TelegramReply:
    """Handle the supported slash commands for one authorized operator.
    
    Returns either a plain text response or a TelegramReply dict; /start preserves
    active scoped Create/Edit flows by returning a silent reply instead of clearing state."""
    try:
        parts = shlex.split(text.strip())
    except ValueError as exc:
        return f"Invalid command syntax: {exc}"
    command = parts[0].split("@", 1)[0].lower() if parts else ""
    args_clean = parts[1:]

    if command == "/start":
        delete_telegram_message_async(chat_id, message_id)
        if pending_interaction_active(state, chat_id=chat_id, user_id=user_id):
            log(f"ignored /start during pending flow chat={chat_id or '-'} user={user_id or '-'} message_id={message_id or '-'}")
            return silent_reply()
        if not should_open_start_menu(state, chat_id=chat_id, user_id=user_id):
            return silent_reply()
        clear_pending_input(state, chat_id=chat_id, user_id=user_id)
        return build_menu_reply(state)
    if command == "/menu":
        delete_telegram_message_async(chat_id, message_id)
        prune_menu_messages(state, chat_id)
        clear_pending_input(state, chat_id=chat_id, user_id=user_id)
        result = build_menu_reply(state)
        result["track_menu"] = True
        return result
    if command == "/clear":
        if len(args_clean) > 1:
            return msg("clear_invalid")
        count = None
        if args_clean:
            if args_clean[0].lower() == "all":
                count = None
            else:
                try:
                    count = int(args_clean[0])
                except ValueError:
                    return msg("clear_invalid")
                count = max(1, min(TELEGRAM_CLEAR_MAX_MESSAGES, count))
        chat_key = str(chat_id or "")
        known_messages = list((state.get("known_messages") or {}).get(chat_key, []))
        start_clear_chat_messages(
            chat_id,
            message_id,
            count,
            ready_message=None,
            known_message_ids=known_messages,
        )
        if chat_key:
            state.setdefault("known_messages", {})[chat_key] = []
        mark_start_menu_once_after_clear(state, chat_id=chat_id, user_id=user_id)
        return silent_reply(remove_keyboard=True)
    return msg("unknown_command")

def answer_callback_query(callback_query_id, text=""):
    if not callback_query_id or not TELEGRAM_BOT_TOKEN:
        return
    params = {"callback_query_id": callback_query_id}
    if text:
        params["text"] = text
    try:
        telegram_api("answerCallbackQuery", params, max_retries=1, timeout=2)
    except Exception as exc:
        log(f"telegram answerCallbackQuery failed: {exc}")


def answer_callback_query_async(callback_query_id, text=""):
    if not callback_query_id or not TELEGRAM_BOT_TOKEN:
        return

    thread = threading.Thread(
        target=answer_callback_query,
        args=(callback_query_id, text),
        name=f"answer-callback-{callback_query_id}",
        daemon=True,
    )
    thread.start()


def callback_metadata(data):
    parts = str(data or "").split(":")
    kind = parts[0] if parts and parts[0] else "unknown"
    if kind == "after" and len(parts) > 1:
        return callback_metadata(":".join(parts[1:]))
    metadata = {"kind": kind, "picker_id": None, "page": None}
    if kind in {"kpage", "kmpage", "upage", "qpage", "kreveal", "kmanage", "uacct", "qacct", "qdaily", "qweekly", "qlimit", "qweek"} and len(parts) >= 2:
        metadata["picker_id"] = parts[1]
    if kind in {"kpage", "kmpage", "upage", "qpage"} and len(parts) >= 3:
        metadata["page"] = parts[2]
    return metadata


def callback_ack_text(data):
    data = str(data or "")
    if data.startswith("after:"):
        return callback_ack_text(data[len("after:"):])
    if data.endswith("_refresh"):
        return "Refreshing..."
    if data.startswith("uacct:"):
        return "Loading usage..."
    if data.startswith("qlimit:") or data.startswith("qweek:") or data.startswith("kmanage:"):
        return "Preparing confirmation..."
    if data.startswith("qsame:"):
        return "Loading..."
    if data in {"menu:usage", "menu:key_lookup", "menu:quota_set", "menu:key_disable", "menu:key_enable", "menu:key_delete"}:
        return "Loading..."
    return ""

def handle_callback(data: str, state: dict[str, Any], chat_id: str | None = None, user_id: str | None = None, message_id: int | str | None = None, telegram_username: str | None = None) -> str | TelegramReply:
    """Route one inline callback and mutate only the scoped state needed for that flow.
    
    Reply dicts with edit_message=True ask process_commands() to edit the tapped
    message first, then fall back to send/delete when Telegram cannot edit it."""
    data = str(data or "")
    if data.startswith("after:"):
        result = handle_callback(data[len("after:"):], state, chat_id=chat_id, user_id=user_id, message_id=message_id, telegram_username=telegram_username)
        if isinstance(result, dict):
            result = dict(result)
            result.pop("edit_message", None)
            result["delete_message"] = True
            return result
        return {"text": result, "delete_message": True}
    if data.startswith("confirm:"):
        code = data.split(":", 1)[1]
        result = execute_pending_action(state, code, chat_id=chat_id, user_id=user_id, telegram_username=telegram_username)
        if result is None:
            return silent_reply()
        if isinstance(result, dict):
            result = dict(result)
            result.setdefault("edit_message", True)
            return result
        return {"text": result, "edit_message": True}
    if data.startswith("cancel:"):
        code = data.split(":", 1)[1]
        pending_actions = state.get("pending_actions") if isinstance(state.get("pending_actions"), dict) else {}
        pending = pending_actions.get(pending_scope(chat_id, user_id))
        if not isinstance(pending, dict) and isinstance(state.get("pending_action"), dict):
            pending = state.get("pending_action")
        pending_type = str((pending or {}).get("type") or "")
        pending_code = cancel_token_for_pending(pending) if isinstance(pending, dict) else ""
        cleanup_message_ids = cleanup_message_ids_from((pending or {}).get("cleanup_message_ids"))
        cancel_pending(state, code=code, chat_id=chat_id, user_id=user_id)
        if pending_type in {"key_disable", "key_enable", "key_delete"} and pending_code == code:
            action = pending_type.removeprefix("key_")
            key_pickers = state.get("key_pickers")
            scoped_picker = key_pickers.get(pending_scope(chat_id, user_id), {}) if isinstance(key_pickers, dict) else {}
            picker_id = str((scoped_picker or {}).get("id") or "") if (scoped_picker or {}).get("action") == action else ""
            result = prompt_key_management_picker(
                state,
                action,
                chat_id=chat_id,
                user_id=user_id,
                picker_id=picker_id or None,
            )
            result["edit_message"] = True
            return result
        if pending_type == "quota_set" and pending_code == code:
            params = pending.get("params") if isinstance(pending, dict) else {}
            quota_kind = str((params or {}).get("quota_kind") or "")
            quota_pickers = state.get("quota_pickers")
            scoped_picker = quota_pickers.get(pending_scope(chat_id, user_id), {}) if isinstance(quota_pickers, dict) else {}
            picker_id = str((scoped_picker or {}).get("id") or "")
            if quota_kind == "daily" and picker_id:
                result = build_daily_quota_limit_picker(state, picker_id, None, chat_id=chat_id, user_id=user_id)
            elif quota_kind == "weekly" and picker_id:
                result = build_weekly_quota_limit_picker(state, picker_id, None, chat_id=chat_id, user_id=user_id)
            else:
                result = prompt_quota_picker(state, chat_id=chat_id, user_id=user_id)
            result["edit_message"] = True
            return result
        if pending_type == "key_create" and pending_code == code:
            result = prompt_key_create(state, chat_id=chat_id, user_id=user_id, message_id=message_id)
            result["edit_message"] = True
            if cleanup_message_ids:
                result["delete_message_ids"] = cleanup_message_ids
            return result
        result = build_menu_reply(state)
        result["edit_message"] = True
        return result
    if data == "cancel_input":
        cancel_pending(state, input_only=True, chat_id=chat_id, user_id=user_id)
        result = build_menu_reply(state)
        result["edit_message"] = True
        return result
    if data == "cancel":
        cancel_pending(state, chat_id=chat_id, user_id=user_id)
        result = build_menu_reply(state)
        result["edit_message"] = True
        return result
    if data == "menu:back":
        prune_menu_messages(state, chat_id, keep_message_id=message_id)
        clear_pending_input(state, chat_id=chat_id, user_id=user_id)
        result = build_menu_reply(state)
        result["edit_message"] = True
        result["track_menu"] = True
        return result
    if data == "menu:incidents":
        snapshot = health_alerts_snapshot_for_reply(get_snapshot(state, live=False, interactive=True), state)
        return {"text": build_alerts_reply(snapshot), "reply_markup": back_keyboard("menu:incidents_refresh"), "edit_message": True}
    if data == "menu:incidents_refresh":
        snapshot = health_alerts_snapshot_for_reply(
            build_health_alerts_snapshot(interactive=True, auth_inspection_state=state.get("auth_quota_inspection")),
            state,
        )
        return {"text": build_alerts_reply(snapshot), "reply_markup": back_keyboard("menu:incidents_refresh"), "edit_message": True}
    if data == "menu:quota":
        return {"text": build_quota_reply(get_snapshot(state, live=False, interactive=True)), "reply_markup": back_keyboard("menu:quota_refresh"), "edit_message": True}
    if data == "menu:quota_refresh":
        return {"text": build_quota_reply(build_quota_rows_snapshot()), "reply_markup": back_keyboard("menu:quota_refresh"), "edit_message": True}
    if data == "menu:quota_management":
        return {"text": build_quota_management_reply(get_quota_management_snapshot(state, live=False)), "reply_markup": back_keyboard("menu:quota_management_refresh"), "edit_message": True}
    if data == "menu:quota_management_refresh":
        return {"text": build_quota_management_reply(get_quota_management_snapshot(state, live=True)), "reply_markup": back_keyboard("menu:quota_management_refresh"), "edit_message": True}
    if data == "menu:capacity":
        snapshot = get_capacity_check_snapshot(state, live=False)
        return {"text": build_capacity_reply(snapshot, cached_capacity_demand_rate(snapshot)), "reply_markup": back_keyboard("menu:capacity_refresh"), "edit_message": True}
    if data == "menu:capacity_refresh":
        snapshot = get_capacity_check_snapshot(state, live=True)
        return {"text": build_capacity_reply(snapshot, live_capacity_demand_rate(snapshot)), "reply_markup": back_keyboard("menu:capacity_refresh"), "edit_message": True}
    if data == "menu:key_status":
        clear_pending_action(state, chat_id=chat_id, user_id=user_id)
        return {"text": build_key_status_reply(get_snapshot(state, live=False, interactive=True)), "reply_markup": key_status_keyboard(), "edit_message": True}
    if data == "menu:key_status_refresh":
        clear_pending_action(state, chat_id=chat_id, user_id=user_id)
        return {"text": build_key_status_reply(build_quota_rows_snapshot()), "reply_markup": key_status_keyboard(), "edit_message": True}
    if data == "menu:top":
        return {"text": build_top_reply(get_snapshot(state, live=False, interactive=True)), "reply_markup": top_users_keyboard(), "edit_message": True}
    if data == "menu:top_refresh":
        return {"text": build_top_reply(build_quota_rows_snapshot()), "reply_markup": top_users_keyboard(), "edit_message": True}
    if data.startswith("kpage:"):
        _, picker_id, page = data.split(":", 2)
        result = prompt_key_reveal_picker(state, chat_id=chat_id, user_id=user_id, page=int(page), picker_id=picker_id)
        result["edit_message"] = True
        return result
    if data.startswith("kmpage:"):
        _, picker_id, page = data.split(":", 2)
        key_pickers = state.get("key_pickers")
        scoped_picker = key_pickers.get(pending_scope(chat_id, user_id), {}) if isinstance(key_pickers, dict) else {}
        action = str((scoped_picker or {}).get("action") or "")
        result = prompt_key_management_picker(state, action, chat_id=chat_id, user_id=user_id, page=int(page), picker_id=picker_id)
        result["edit_message"] = True
        return result
    if data.startswith("kreveal:"):
        _, picker_id, account_index = data.split(":", 2)
        result = build_key_reveal_from_picker(state, picker_id, account_index, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data.startswith("kmanage:"):
        _, picker_id, account_index = data.split(":", 2)
        result = create_key_management_from_picker(state, picker_id, account_index, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data.startswith("upage:"):
        _, picker_id, page = data.split(":", 2)
        result = prompt_usage_picker(state, chat_id=chat_id, user_id=user_id, page=int(page), picker_id=picker_id)
        result["edit_message"] = True
        return result
    if data.startswith("uacct:"):
        _, picker_id, account_index = data.split(":", 2)
        result = build_usage_report_from_picker(state, picker_id, account_index, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data == "key:type_alias":
        result = prompt_key_lookup(state, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data.startswith("qpage:"):
        _, picker_id, page = data.split(":", 2)
        result = prompt_quota_picker(state, chat_id=chat_id, user_id=user_id, page=int(page), picker_id=picker_id)
        result["edit_message"] = True
        return result
    if data.startswith("qacct:"):
        _, picker_id, account_index = data.split(":", 2)
        result = build_quota_limit_picker(state, picker_id, account_index, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data.startswith("qdaily:"):
        _, picker_id, account_index = data.split(":", 2)
        result = build_daily_quota_limit_picker(state, picker_id, account_index, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data.startswith("qweekly:"):
        _, picker_id, account_index = data.split(":", 2)
        result = build_weekly_quota_limit_picker(state, picker_id, account_index, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data.startswith("qsame:"):
        _, ref, quota_kind = data.split(":", 2)
        result = build_same_key_quota_limit_picker(state, ref, quota_kind, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data.startswith("qlimit:"):
        _, picker_id, limit_code = data.split(":", 2)
        result = create_quota_update_from_picker(state, picker_id, limit_code, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data.startswith("qweek:"):
        _, picker_id, limit_code = data.split(":", 2)
        result = create_weekly_quota_update_from_picker(state, picker_id, limit_code, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data == "menu:errors":
        return {"text": get_errors_reply(state, "all", live=False), "reply_markup": errors_keyboard(), "edit_message": True}
    if data == "menu:errors_refresh":
        return {"text": get_errors_reply(state, "all", live=True), "reply_markup": errors_keyboard(), "edit_message": True}
    if data == "menu:usage":
        clear_pending_action(state, chat_id=chat_id, user_id=user_id)
        clear_pending_input(state, chat_id=chat_id, user_id=user_id)
        result = prompt_usage_picker(state, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data == "menu:key_lookup":
        clear_pending_action(state, chat_id=chat_id, user_id=user_id)
        clear_pending_input(state, chat_id=chat_id, user_id=user_id)
        result = prompt_key_reveal_picker(state, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data == "menu:key_disable":
        clear_pending_action(state, chat_id=chat_id, user_id=user_id)
        clear_pending_input(state, chat_id=chat_id, user_id=user_id)
        result = prompt_key_management_picker(state, "disable", chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data == "menu:key_enable":
        clear_pending_action(state, chat_id=chat_id, user_id=user_id)
        clear_pending_input(state, chat_id=chat_id, user_id=user_id)
        result = prompt_key_management_picker(state, "enable", chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data == "menu:key_delete":
        clear_pending_action(state, chat_id=chat_id, user_id=user_id)
        clear_pending_input(state, chat_id=chat_id, user_id=user_id)
        result = prompt_key_management_picker(state, "delete", chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    if data == "menu:key_create":
        clear_pending_action(state, chat_id=chat_id, user_id=user_id)
        clear_pending_input(state, chat_id=chat_id, user_id=user_id)
        result = prompt_key_create(state, chat_id=chat_id, user_id=user_id, message_id=message_id)
        result["edit_message"] = True
        return result
    if data == "menu:quota_set":
        clear_pending_action(state, chat_id=chat_id, user_id=user_id)
        clear_pending_input(state, chat_id=chat_id, user_id=user_id)
        result = prompt_quota_picker(state, chat_id=chat_id, user_id=user_id)
        result["edit_message"] = True
        return result
    return "Unknown button action."

def process_commands(state: dict[str, Any], dry_run: bool = False) -> int:
    """Poll one Telegram update batch, enforce allowlists, and dispatch messages/callbacks.
    
    Mutates telegram_offset and known_messages in monitor state; callers own saving
    the state after this loop tick."""
    if dry_run or DRY_RUN or not TELEGRAM_BOT_TOKEN or not (allowed_chat_ids() or allowed_user_ids()):
        return 0

    try:
        updates = telegram_get_updates(state.get("telegram_offset", 0))
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        log(f"telegram getUpdates skipped after transient network error: {exc}")
        return 0
    handled = 0
    for update in updates:
        update_id = int(update.get("update_id", 0))
        state["telegram_offset"] = max(int(state.get("telegram_offset", 0) or 0), update_id + 1)
        callback = update.get("callback_query") or {}
        if callback:
            callback_id = str(callback.get("id", ""))
            message = callback.get("message") or {}
            chat = message.get("chat") or {}
            sender = callback.get("from") or {}
            chat_id = str(chat.get("id", ""))
            user_id = str(sender.get("id", ""))
            if not is_authorized(chat_id, user_id):
                answer_callback_query_async(callback_id, "Unauthorized")
                if chat_id or user_id:
                    log(f"ignored unauthorized telegram callback chat={chat_id or '-'} user={user_id or '-'}")
                continue
            remember_message(state, chat_id, message.get("message_id"))
            callback_started = monotonic_ms()
            data_text = str(callback.get("data", ""))
            callback_meta = callback_metadata(data_text)
            callback_kind = callback_meta.get("kind") or "unknown"
            answer_started = monotonic_ms()
            answer_callback_query_async(callback_id, callback_ack_text(data_text))
            answer_ms = monotonic_ms() - answer_started
            handle_started = monotonic_ms()
            try:
                reply_data = handle_callback(
                    data_text,
                    state,
                    chat_id=chat_id,
                    user_id=user_id,
                    message_id=message.get("message_id"),
                    telegram_username=sender.get("username"),
                )
            except Exception as exc:
                reply_data = f"Command failed: {exc}"
                answer_callback_query_async(callback_id, "Failed")
            handle_ms = monotonic_ms() - handle_started
            edit_ms = None
            send_ms = None
            edit_ok = None
            edit_reason = None
            fallback_send = 0
            sent_messages = None
            if isinstance(reply_data, dict) and reply_data.get("delete_message"):
                delete_telegram_message_async(chat_id, message.get("message_id"))
                send_started = monotonic_ms()
                sent_messages = send_reply(reply_data, chat_id=chat_id)
                send_ms = monotonic_ms() - send_started
                remember_sent_messages(state, sent_messages)
                remember_pending_input_prompt_messages(state, reply_data, chat_id=chat_id, user_id=user_id, sent_messages=sent_messages)
                delete_reply_cleanup_messages(reply_data, chat_id, current_message_id=message.get("message_id"))
            elif isinstance(reply_data, dict) and reply_data.get("edit_message"):
                edit_started = monotonic_ms()
                edit_result = edit_telegram_message_result(
                    chat_id,
                    message.get("message_id"),
                    str(reply_data.get("text", "")),
                    reply_markup=reply_data.get("reply_markup"),
                )
                edit_ms = monotonic_ms() - edit_started
                edit_ok = 1 if edit_result.get("ok") else 0
                edit_reason = edit_result.get("reason")
                if not edit_result.get("ok"):
                    fallback_send = 1
                    send_started = monotonic_ms()
                    sent_messages = send_reply(reply_data, chat_id=chat_id)
                    send_ms = monotonic_ms() - send_started
                    remember_sent_messages(state, sent_messages)
                    remember_pending_input_prompt_messages(state, reply_data, chat_id=chat_id, user_id=user_id, sent_messages=sent_messages)
                    delete_telegram_message_async(chat_id, message.get("message_id"))
                elif reply_data.get("track_menu"):
                    remember_menu_message(state, chat_id, message.get("message_id"))
                else:
                    remember_pending_input_prompt_messages(state, reply_data, chat_id=chat_id, user_id=user_id, message_id=message.get("message_id"))
                delete_reply_cleanup_messages(reply_data, chat_id, current_message_id=message.get("message_id"))
            else:
                send_started = monotonic_ms()
                sent_messages = send_reply(reply_data, chat_id=chat_id)
                send_ms = monotonic_ms() - send_started
                remember_sent_messages(state, sent_messages)
                remember_pending_input_prompt_messages(state, reply_data, chat_id=chat_id, user_id=user_id, sent_messages=sent_messages)
            if isinstance(reply_data, dict) and reply_data.get("track_menu") and sent_messages:
                remember_menu_messages(state, sent_messages)
            log_timing(
                "callback_total",
                callback_started,
                kind=callback_kind,
                message_id=message.get("message_id"),
                picker_id=callback_meta.get("picker_id"),
                page=callback_meta.get("page"),
                answer_ms=answer_ms,
                handle_ms=handle_ms,
                edit_ms=edit_ms,
                edit_ok=edit_ok,
                edit_reason=edit_reason,
                send_ms=send_ms,
                fallback_send=fallback_send,
            )
            handled += 1
            continue

        message = update.get("message") or update.get("edited_message") or {}
        chat = message.get("chat") or {}
        sender = message.get("from") or {}
        chat_id = str(chat.get("id", ""))
        user_id = str(sender.get("id", ""))
        message_id = message.get("message_id")
        text = str(message.get("text", "")).strip()
        if not is_authorized(chat_id, user_id):
            if chat_id or user_id:
                log(f"ignored unauthorized telegram message chat={chat_id or '-'} user={user_id or '-'}")
            continue
        remember_message(state, chat_id, message_id)
        if not text.startswith("/"):
            reply = handle_pending_input(text, state, chat_id=chat_id, user_id=user_id, message_id=message_id)
            if reply is None:
                continue
            sent_messages = send_reply(reply, chat_id=chat_id)
            remember_sent_messages(state, sent_messages)
            handled += 1
            continue
        try:
            reply = handle_command(text, state, chat_id=chat_id, user_id=user_id, message_id=message_id)
        except Exception as exc:
            reply = f"Command failed: {exc}"
        sent_messages = send_reply(reply, chat_id=chat_id)
        remember_sent_messages(state, sent_messages)
        if isinstance(reply, dict) and reply.get("track_menu"):
            remember_menu_messages(state, sent_messages)
        handled += 1
    return handled

AUTH_REAUTH_ALERT_ID = "auth:quota-inspection-failed"
AUTH_INSPECTION_UNAVAILABLE_ID = "auth:quota-inspection-unavailable"
AUTH_STABILITY_ALERT_IDS = {AUTH_REAUTH_ALERT_ID}
AUTH_REAUTH_CONFIRM_OBSERVATIONS = 2
GPT_POOL_5H_LOW_ALERT_ID = "capacity:gpt-pool-5h-low"
GPT_POOL_CONFIRM_OBSERVATIONS = 2
ALERT_DELIVERY_HISTORY_KEY = "alert_delivery_history"
ALERT_DELIVERY_HISTORY_TTL_SECONDS = 7 * 24 * 60 * 60


def normalized_identity_keys(value):
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {str(item).strip() for item in value if str(item or "").strip()}


def auth_observation_complete(auth_quota_observation):
    return isinstance(auth_quota_observation, dict) and bool(auth_quota_observation.get("complete"))


def auth_observation_failed_keys(auth_quota_observation):
    if not isinstance(auth_quota_observation, dict):
        return set()
    return normalized_identity_keys(auth_quota_observation.get("failed_identity_keys"))


def auth_observation_failed_labels(auth_quota_observation, affected_keys):
    if not isinstance(auth_quota_observation, dict):
        return {}
    labels = auth_quota_observation.get("failed_labels")
    if not isinstance(labels, dict):
        return {}
    return {
        str(key): str(value)[:80]
        for key, value in labels.items()
        if str(key) in affected_keys
    }


def reauth_affected_signature(affected_keys, labels):
    labels = labels if isinstance(labels, dict) else {}
    label_signature = sorted({
        reauth_label_identity_key(value)
        for key, value in labels.items()
        if str(key) in set(affected_keys or []) and str(value or "").strip()
    })
    if label_signature:
        return label_signature
    return sorted(f"key:{key}" for key in normalized_identity_keys(affected_keys))


def reauth_recovery_observed(old, auth_quota_observation):
    if not auth_observation_complete(auth_quota_observation):
        return False
    affected = normalized_identity_keys(old.get("affected_identity_keys"))
    if not affected:
        return False
    healthy = normalized_identity_keys(auth_quota_observation.get("healthy_identity_keys"))
    return affected.issubset(healthy)


def auth_unavailable_recovery_observed(auth_quota_observation):
    return auth_observation_complete(auth_quota_observation)


def auth_unavailable_observation_reason(auth_quota_observation):
    if not isinstance(auth_quota_observation, dict):
        return ""
    return str(auth_quota_observation.get("reason") or "")[:80]


def recent_complete_auth_inspection_state(state, ts):
    if not isinstance(state, dict):
        return False
    item = state.get("auth_quota_inspection")
    if not isinstance(item, dict):
        return False
    try:
        last_complete_at = int(item.get("last_complete_at", 0) or 0)
    except (TypeError, ValueError):
        last_complete_at = 0
    return last_complete_at > 0 and ts - last_complete_at < max(0, int(AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS or 0))


def auth_unavailable_duration_met(candidate, ts):
    try:
        first_seen = int(candidate.get("first_seen", ts) or ts)
    except (TypeError, ValueError):
        first_seen = ts
    return ts - first_seen >= max(0, int(AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS or 0))


def auth_unavailable_recovery_duration_met(old, ts):
    try:
        started = int(old.get("unavailable_recovery_started_at", 0) or 0)
    except (TypeError, ValueError):
        started = 0
    if started <= 0:
        return False
    return ts - started >= max(0, int(AUTH_INSPECTION_UNAVAILABLE_RECOVER_AFTER_SECONDS or 0))


def gpt_pool_observation_complete(gpt_pool_5h_observation):
    return isinstance(gpt_pool_5h_observation, dict) and bool(gpt_pool_5h_observation.get("complete"))


def gpt_pool_observation_low(gpt_pool_5h_observation):
    return gpt_pool_observation_complete(gpt_pool_5h_observation) and bool(gpt_pool_5h_observation.get("low"))


def gpt_pool_recovery_observed(gpt_pool_5h_observation):
    return gpt_pool_observation_complete(gpt_pool_5h_observation) and bool(gpt_pool_5h_observation.get("recovered"))


def alert_candidate_map(state):
    candidates = state.setdefault("alert_candidates", {})
    if not isinstance(candidates, dict):
        candidates = {}
        state["alert_candidates"] = candidates
    return candidates


def alert_delivery_history(state):
    history = state.setdefault(ALERT_DELIVERY_HISTORY_KEY, {})
    if not isinstance(history, dict):
        history = {}
        state[ALERT_DELIVERY_HISTORY_KEY] = history
    return history


def alert_message_hash(message):
    return hashlib.sha256(str(message or "").encode("utf-8", errors="replace")).hexdigest()[:16]


def prune_alert_delivery_history(state, active_state, ts):
    history = alert_delivery_history(state)
    active_ids = set(active_state.keys()) if isinstance(active_state, dict) else set()
    for alert_id, item in list(history.items()):
        if not isinstance(item, dict):
            history.pop(alert_id, None)
            continue
        try:
            last_sent = int(item.get("last_sent", 0) or 0)
        except (TypeError, ValueError):
            last_sent = 0
        if alert_id not in active_ids and last_sent > 0 and ts - last_sent > ALERT_DELIVERY_HISTORY_TTL_SECONDS:
            history.pop(alert_id, None)
    return history


def sync_alert_delivery_history_from_active(state, active_state, ts):
    history = prune_alert_delivery_history(state, active_state, ts)
    if not isinstance(active_state, dict):
        return history
    for alert_id, item in active_state.items():
        if not isinstance(item, dict):
            continue
        try:
            last_sent = int(item.get("last_sent", 0) or 0)
        except (TypeError, ValueError):
            last_sent = 0
        fingerprint = str(item.get("fingerprint") or "")
        if last_sent > 0 and fingerprint:
            current = history.get(alert_id) if isinstance(history.get(alert_id), dict) else {}
            if current.get("fingerprint") != fingerprint or not current.get("last_sent"):
                history[alert_id] = {
                    "fingerprint": fingerprint,
                    "last_sent": last_sent,
                    "affected_signature": list(item.get("affected_signature") or []),
                }
    return history


def duplicate_alert_delivery_last_sent(history, alert_id, fingerprint, message_hash, affected_signature, ts):
    item = history.get(alert_id) if isinstance(history, dict) else None
    if not isinstance(item, dict):
        return 0
    try:
        last_sent = int(item.get("last_sent", 0) or 0)
    except (TypeError, ValueError):
        last_sent = 0
    if last_sent <= 0 or ts - last_sent > ALERT_DELIVERY_HISTORY_TTL_SECONDS:
        return 0
    if str(item.get("fingerprint") or "") == str(fingerprint or ""):
        return last_sent
    if affected_signature and list(item.get("affected_signature") or []) == list(affected_signature):
        return last_sent
    if message_hash and str(item.get("message_hash") or "") == str(message_hash):
        return last_sent
    return 0


def remember_alert_delivery(history, alert_id, fingerprint, message_hash, affected_signature, ts):
    if isinstance(history, dict):
        history[alert_id] = {
            "fingerprint": str(fingerprint or ""),
            "last_sent": int(ts),
            "message_hash": str(message_hash or ""),
            "affected_signature": list(affected_signature or []),
        }


def forget_alert_delivery(history, alert_id):
    if isinstance(history, dict):
        history.pop(alert_id, None)


# System alerts have no manual ack state: each active fingerprint sends once,
# then a recovery sends once after a previously sent incident clears. Reauth
# and GPT capacity alerts need short two-observation stability gates so one
# stale or incomplete data point cannot create alert/OK spam.
def process_alerts(
    alerts: dict[str, Any],
    state: dict[str, Any],
    dry_run: bool = False,
    auth_quota_observation: dict[str, Any] | None = None,
    gpt_pool_5h_observation: dict[str, Any] | None = None,
) -> None:
    """Apply the no-ack incident lifecycle to the active alert map.

    Each active fingerprint sends once. Reauth and GPT-capacity alerts need two
    matching observations before sending; their recovery requires positive stable evidence."""
    effective_dry_run = dry_run or DRY_RUN
    active_state = state.get("active", {})
    if not isinstance(active_state, dict):
        active_state = {}
    next_active = {}
    ts = now_ts()
    sent = 0
    silenced = 0
    candidates = alert_candidate_map(state)
    delivery_history = sync_alert_delivery_history_from_active(state, active_state, ts)

    for alert_id, alert in sorted(alerts.items()):
        old = active_state.get(alert_id, {})
        first_seen = old.get("first_seen", ts)
        if alert_id == GPT_POOL_5H_LOW_ALERT_ID and not old.get("last_sent"):
            candidate = candidates.get(alert_id) if isinstance(candidates.get(alert_id), dict) else {}
            if candidate.get("fingerprint") != alert.fingerprint:
                candidate = {"first_seen": ts, "seen_count": 0, "fingerprint": alert.fingerprint}
            if not gpt_pool_observation_low(gpt_pool_5h_observation):
                candidates.pop(alert_id, None)
                continue
            candidate["seen_count"] = int(candidate.get("seen_count", 0) or 0) + 1
            candidate["last_seen"] = ts
            candidate["title"] = alert.title
            candidate["severity"] = alert.severity
            candidates[alert_id] = candidate
            if int(candidate.get("seen_count", 0) or 0) < GPT_POOL_CONFIRM_OBSERVATIONS:
                continue
            first_seen = candidate.get("first_seen", ts)
            candidates.pop(alert_id, None)
        elif alert_id == AUTH_INSPECTION_UNAVAILABLE_ID and not old.get("last_sent"):
            if recent_complete_auth_inspection_state(state, ts):
                candidates.pop(alert_id, None)
                continue
            candidate = candidates.get(alert_id) if isinstance(candidates.get(alert_id), dict) else {}
            if candidate.get("fingerprint") != alert.fingerprint:
                candidate = {"first_seen": ts, "fingerprint": alert.fingerprint}
            candidate["last_seen"] = ts
            candidate["title"] = alert.title
            candidate["severity"] = alert.severity
            reason = auth_unavailable_observation_reason(auth_quota_observation)
            if reason:
                candidate["observation_reason"] = reason
            candidates[alert_id] = candidate
            if not auth_unavailable_duration_met(candidate, ts):
                continue
            first_seen = candidate.get("first_seen", ts)
            candidates.pop(alert_id, None)
        elif alert_id in AUTH_STABILITY_ALERT_IDS and not old.get("last_sent"):
            candidate = candidates.get(alert_id) if isinstance(candidates.get(alert_id), dict) else {}
            if candidate.get("fingerprint") != alert.fingerprint:
                candidate = {"first_seen": ts, "seen_count": 0, "fingerprint": alert.fingerprint}
            candidate["seen_count"] = int(candidate.get("seen_count", 0) or 0) + 1
            candidate["last_seen"] = ts
            candidate["title"] = alert.title
            candidate["severity"] = alert.severity
            candidates[alert_id] = candidate
            if int(candidate.get("seen_count", 0) or 0) < AUTH_REAUTH_CONFIRM_OBSERVATIONS:
                continue
            first_seen = candidate.get("first_seen", ts)
            candidates.pop(alert_id, None)
        else:
            candidates.pop(alert_id, None)

        last_sent = int(old.get("last_sent", 0) or 0)
        current_reauth_affected_keys = set()
        current_reauth_affected_labels = {}
        current_reauth_affected_signature = []
        if alert_id == AUTH_REAUTH_ALERT_ID:
            current_reauth_affected_keys = auth_observation_failed_keys(auth_quota_observation)
            current_reauth_affected_labels = auth_observation_failed_labels(auth_quota_observation, current_reauth_affected_keys)
            current_reauth_affected_signature = reauth_affected_signature(current_reauth_affected_keys, current_reauth_affected_labels)
        should_send = not old or not last_sent or old.get("fingerprint") != alert.fingerprint
        if (
            should_send
            and alert_id == AUTH_REAUTH_ALERT_ID
            and old
            and last_sent
            and current_reauth_affected_signature
            and list(old.get("affected_signature") or []) == current_reauth_affected_signature
        ):
            should_send = False

        if should_send:
            message = build_alert_message(alert)
            message_hash = alert_message_hash(message)
            duplicate_last_sent = duplicate_alert_delivery_last_sent(
                delivery_history,
                alert_id,
                alert.fingerprint,
                message_hash,
                current_reauth_affected_signature,
                ts,
            )
            if duplicate_last_sent:
                last_sent = duplicate_last_sent
            else:
                sent_chats, silenced_chats = send_auto_alert(message, state, dry_run=effective_dry_run)
                silenced += silenced_chats
                if sent_chats:
                    last_sent = ts
                    remember_alert_delivery(delivery_history, alert_id, alert.fingerprint, message_hash, current_reauth_affected_signature, ts)
                    sent += sent_chats

        active_record = {
            "first_seen": first_seen,
            "last_seen": ts,
            "last_sent": last_sent,
            "severity": alert.severity,
            "title": alert.title,
            "fingerprint": alert.fingerprint,
        }
        if alert_id == AUTH_REAUTH_ALERT_ID:
            affected_keys = current_reauth_affected_keys
            if not affected_keys:
                affected_keys = normalized_identity_keys(old.get("affected_identity_keys"))
            active_record["affected_identity_keys"] = sorted(affected_keys)
            labels = current_reauth_affected_labels or auth_observation_failed_labels(auth_quota_observation, affected_keys)
            if labels:
                active_record["affected_labels"] = labels
            active_record["affected_signature"] = reauth_affected_signature(affected_keys, labels)
            active_record["reauth_recovery_seen_count"] = 0
        if alert_id == AUTH_INSPECTION_UNAVAILABLE_ID:
            active_record["unavailable_first_seen"] = int(first_seen or ts)
            active_record["unavailable_last_seen"] = ts
            active_record["unavailable_recovery_started_at"] = 0
            reason = auth_unavailable_observation_reason(auth_quota_observation)
            if reason:
                active_record["observation_reason"] = reason
        if alert_id == GPT_POOL_5H_LOW_ALERT_ID:
            active_record["gpt_recovery_seen_count"] = 0
        next_active[alert_id] = active_record

    for alert_id in list(candidates.keys()):
        if alert_id not in alerts:
            candidates.pop(alert_id, None)

    resolution_blocked = AUTH_INSPECTION_UNAVAILABLE_ID in alerts
    for alert_id, old in sorted(active_state.items()):
        if str(alert_id).startswith("quota:"):
            continue
        if alert_id not in alerts and alert_id == GPT_POOL_5H_LOW_ALERT_ID:
            old = dict(old)
            old["last_seen"] = ts
            if not gpt_pool_recovery_observed(gpt_pool_5h_observation):
                old["gpt_recovery_seen_count"] = 0
                next_active[alert_id] = old
                continue
            old["gpt_recovery_seen_count"] = int(old.get("gpt_recovery_seen_count", 0) or 0) + 1
            if int(old.get("gpt_recovery_seen_count", 0) or 0) < GPT_POOL_CONFIRM_OBSERVATIONS:
                next_active[alert_id] = old
                continue
            if old.get("last_sent"):
                sent_chats, silenced_chats = send_auto_alert(build_resolved_message(alert_id, old), state, dry_run=effective_dry_run)
                silenced += silenced_chats
                if sent_chats:
                    sent += sent_chats
                    forget_alert_delivery(delivery_history, alert_id)
            continue
        if alert_id not in alerts and alert_id == AUTH_INSPECTION_UNAVAILABLE_ID:
            old = dict(old)
            old["last_seen"] = ts
            if not auth_unavailable_recovery_observed(auth_quota_observation):
                old["unavailable_recovery_started_at"] = 0
                next_active[alert_id] = old
                continue
            if not int(old.get("unavailable_recovery_started_at", 0) or 0):
                old["unavailable_recovery_started_at"] = ts
                next_active[alert_id] = old
                continue
            if not auth_unavailable_recovery_duration_met(old, ts):
                next_active[alert_id] = old
                continue
            if old.get("last_sent"):
                sent_chats, silenced_chats = send_auto_alert(build_resolved_message(alert_id, old), state, dry_run=effective_dry_run)
                silenced += silenced_chats
                if sent_chats:
                    sent += sent_chats
                    forget_alert_delivery(delivery_history, alert_id)
            continue
        if alert_id not in alerts and alert_id == AUTH_REAUTH_ALERT_ID:
            old = dict(old)
            old["last_seen"] = ts
            if resolution_blocked or not reauth_recovery_observed(old, auth_quota_observation):
                old["reauth_recovery_seen_count"] = 0
                next_active[alert_id] = old
                continue
            old["reauth_recovery_seen_count"] = int(old.get("reauth_recovery_seen_count", 0) or 0) + 1
            if int(old.get("reauth_recovery_seen_count", 0) or 0) < AUTH_REAUTH_CONFIRM_OBSERVATIONS:
                next_active[alert_id] = old
                continue
            if old.get("last_sent"):
                sent_chats, silenced_chats = send_auto_alert(build_resolved_message(alert_id, old), state, dry_run=effective_dry_run)
                silenced += silenced_chats
                if sent_chats:
                    sent += sent_chats
                    forget_alert_delivery(delivery_history, alert_id)
            continue
        if alert_id not in alerts and old.get("last_sent"):
            sent_chats, silenced_chats = send_auto_alert(build_resolved_message(alert_id, old), state, dry_run=effective_dry_run)
            silenced += silenced_chats
            if sent_chats:
                sent += sent_chats
                forget_alert_delivery(delivery_history, alert_id)

    if not effective_dry_run:
        state["updated_at"] = ts
        state["active"] = next_active
        if not candidates:
            state.pop("alert_candidates", None)
        save_json(STATE_FILE, state)
    log(f"checked alerts={len(alerts)} sent={sent} silenced_chats={silenced}")
