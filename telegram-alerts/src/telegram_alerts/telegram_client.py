"""Small Telegram Bot API client with retry, edit, send, and chat-clear helpers."""

from __future__ import annotations
from typing import Any
from .contracts import SentMessage, TelegramEditResult, TelegramReply, TelegramReplyMarkup

from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .settings import (
    BOT_COMMANDS_VERSION,
    CLEAR_ACTIVE_CHATS,
    CLEAR_LOCK,
    DRY_RUN,
    HTTP_TIMEOUT_SECONDS,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CLEAR_BATCH_SIZE,
    TELEGRAM_CLEAR_MAX_MESSAGES,
    TELEGRAM_CLEAR_STOP_AFTER_MISSES,
    TELEGRAM_CLEAR_WORKERS,
    TELEGRAM_GET_UPDATES_TIMEOUT_SECONDS,
    TELEGRAM_KNOWN_MESSAGES_MAX,
    TELEGRAM_MESSAGE_MAX_CHARS,
)
from .utils import alert_chat_ids, log, now_ts

def telegram_api(method: str, params: dict[str, Any], max_retries: int = 3, timeout: int | None = None) -> dict[str, Any]:
    """Call one Telegram Bot API method with bounded retry behavior.
    
    HTTPError exceptions keep parsed telegram_body/telegram_data attributes so callers
    can decide whether to suppress or fall back."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}"
    payload = urlencode(params).encode("utf-8")
    request_timeout = HTTP_TIMEOUT_SECONDS if timeout is None else max(1, int(timeout))
    last_exc = None
    for attempt in range(max(1, max_retries)):
        request = Request(url, data=payload, method="POST")
        try:
            with urlopen(request, timeout=request_timeout) as response:
                body = response.read(2 * 1024 * 1024)
            return json.loads(body.decode("utf-8"))
        except HTTPError as exc:
            last_exc = exc
            retry_after = None
            body = b""
            data = None
            try:
                body = exc.read(256 * 1024)
                data = json.loads(body.decode("utf-8", errors="replace"))
                retry_after = int((data.get("parameters") or {}).get("retry_after") or 0)
            except Exception:
                pass
            exc.telegram_body = body
            exc.telegram_data = data
            if exc.code == 429 and attempt < max_retries - 1:
                delay = min(30, max(1, retry_after or 3))
                log(f"telegram API rate limited for {method}; retrying in {delay}s")
                time.sleep(delay)
                continue
            if exc.code >= 500 and attempt < max_retries - 1:
                time.sleep(min(8, 2 ** attempt))
                continue
            raise
        except (URLError, TimeoutError, OSError) as exc:
            last_exc = exc
            if attempt < max_retries - 1:
                time.sleep(min(8, 2 ** attempt))
                continue
            raise
    raise last_exc or RuntimeError(f"telegram API {method} failed")

def split_telegram_message(message, max_chars=TELEGRAM_MESSAGE_MAX_CHARS):
    text = str(message)
    if len(text) <= max_chars:
        return [text]
    chunks = []
    current = []
    current_len = 0
    for line in text.splitlines(keepends=True):
        if len(line) > max_chars:
            if current:
                chunks.append("".join(current))
                current = []
                current_len = 0
            for index in range(0, len(line), max_chars):
                chunks.append(line[index:index + max_chars])
            continue
        if current_len + len(line) > max_chars and current:
            chunks.append("".join(current))
            current = []
            current_len = 0
        current.append(line)
        current_len += len(line)
    if current:
        chunks.append("".join(current))
    return chunks or [""]

REPLY_KEYBOARD_REMOVE_MESSAGE = chr(0x2060)


def send_telegram(message: object, dry_run: bool = False, chat_id: str | None = None, reply_markup: TelegramReplyMarkup | None = None) -> bool | list[SentMessage]:
    """Send a Telegram message, splitting long text into multiple sendMessage calls.

    Current return convention is preserved: True for dry-run success, False for no
    target/config or total failure, otherwise a list of sent message ids."""
    chunks = split_telegram_message(message)
    if dry_run or DRY_RUN:
        for chunk in chunks:
            log("DRY RUN telegram message:\n" + chunk)
        if reply_markup:
            log("DRY RUN telegram reply_markup:\n" + json.dumps(reply_markup, ensure_ascii=False))
        return True

    if not TELEGRAM_BOT_TOKEN:
        log("telegram token not configured; skipping send")
        return False

    target_chat_ids = [str(chat_id)] if chat_id else alert_chat_ids()
    if not target_chat_ids:
        log("telegram chat allowlist not configured; skipping send")
        return False

    sent_messages = []
    for target_chat_id in target_chat_ids:
        for index, chunk in enumerate(chunks):
            params = {
                "chat_id": target_chat_id,
                "text": chunk,
                "disable_web_page_preview": "true",
            }
            if reply_markup and index == len(chunks) - 1:
                params["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
            try:
                data = telegram_api("sendMessage", params)
                result = data.get("result") if isinstance(data, dict) else {}
                message_id = result.get("message_id") if isinstance(result, dict) else None
                if message_id:
                    sent_messages.append({"chat_id": str(target_chat_id), "message_id": int(message_id)})
                else:
                    sent_messages.append({"chat_id": str(target_chat_id), "message_id": 0})
            except Exception as exc:
                log(f"telegram send failed for chat {target_chat_id}: {exc}")
    return sent_messages or False


def remove_telegram_reply_keyboard(chat_id: str | None, dry_run: bool = False) -> bool:
    if not chat_id:
        return False
    sent_messages = send_telegram(
        REPLY_KEYBOARD_REMOVE_MESSAGE,
        dry_run=dry_run,
        chat_id=chat_id,
        reply_markup={"remove_keyboard": True},
    )
    if isinstance(sent_messages, list):
        for item in sent_messages:
            delete_telegram_message(item.get("chat_id"), item.get("message_id"))
    return bool(sent_messages)

def edit_telegram_message_result(chat_id: str | None, message_id: int | str | None, text: object, reply_markup: TelegramReplyMarkup | None = None) -> TelegramEditResult:
    """Try to edit one Telegram message and return a small result contract.
    
    Callers use reason values such as too_long, not_modified, missing_target, or http_*
    to decide whether to fall back to sending a new message."""
    if DRY_RUN:
        log(f"DRY RUN telegram edit chat={chat_id} message={message_id}:\n{text}")
        return {"ok": True, "reason": "dry_run"}
    if not TELEGRAM_BOT_TOKEN or not chat_id or not message_id:
        return {"ok": False, "reason": "missing_target"}
    chunks = split_telegram_message(text)
    # Telegram can send long replies as multiple messages, but editMessageText
    # can only replace one message. Let the caller fall back to sending a fresh
    # split reply when the edited text would exceed one Telegram message.
    if len(chunks) != 1:
        return {"ok": False, "reason": "too_long"}
    params = {
        "chat_id": str(chat_id),
        "message_id": int(message_id),
        "text": chunks[0],
        "disable_web_page_preview": "true",
    }
    if reply_markup:
        params["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    try:
        data = telegram_api("editMessageText", params)
        ok = bool(data.get("ok"))
        return {"ok": ok, "reason": "ok" if ok else "api_not_ok"}
    except HTTPError as exc:
        data = getattr(exc, "telegram_data", None)
        description = str((data or {}).get("description") or "")
        if exc.code == 400 and "message is not modified" in description.lower():
            return {"ok": True, "reason": "not_modified", "description": description}
        body = getattr(exc, "telegram_body", b"")
        try:
            body_text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body or "")
        except Exception:
            body_text = ""
        detail = f"{exc}: {body_text}" if body_text else str(exc)
        log(f"telegram editMessageText failed chat={chat_id} message={message_id}: {detail}")
        return {"ok": False, "reason": f"http_{exc.code}", "description": description}
    except Exception as exc:
        log(f"telegram editMessageText failed chat={chat_id} message={message_id}: {exc}")
        return {"ok": False, "reason": "exception", "description": str(exc)}


def send_reply(reply_data: TelegramReply | str, dry_run: bool = False, chat_id: str | None = None) -> bool | list[SentMessage]:
    """Send a router reply contract through Telegram.

    A reply with skip_send=True is treated as successfully handled without calling
    the main Telegram reply send."""
    if isinstance(reply_data, dict):
        if reply_data.get("remove_keyboard"):
            try:
                remove_telegram_reply_keyboard(chat_id, dry_run=dry_run)
            except Exception:
                log("telegram reply keyboard cleanup failed")
        if reply_data.get("skip_send"):
            return True
        return send_telegram(
            str(reply_data.get("text", "")),
            dry_run=dry_run,
            chat_id=chat_id,
            reply_markup=reply_data.get("reply_markup"),
        )
    return send_telegram(str(reply_data), dry_run=dry_run, chat_id=chat_id)

def remember_message(state, chat_id, message_id):
    try:
        message_id = int(message_id or 0)
    except (TypeError, ValueError):
        return
    if message_id <= 0:
        return
    chat_key = str(chat_id or "")
    if not chat_key:
        return
    known = state.setdefault("known_messages", {})
    items = known.setdefault(chat_key, [])
    items.append(message_id)
    known[chat_key] = sorted(set(int(item) for item in items if int(item or 0) > 0))[-TELEGRAM_KNOWN_MESSAGES_MAX:]

def remember_sent_messages(state, sent_messages):
    if not isinstance(sent_messages, list):
        return
    for item in sent_messages:
        if isinstance(item, dict):
            remember_message(state, item.get("chat_id"), item.get("message_id"))

def delete_telegram_message(chat_id, message_id):
    try:
        data = telegram_api("deleteMessage", {
            "chat_id": str(chat_id),
            "message_id": int(message_id),
        })
        return bool(data.get("ok"))
    except Exception:
        return False

def delete_telegram_message_async(chat_id, message_id):
    if not chat_id or not message_id:
        return

    def worker():
        delete_telegram_message(chat_id, message_id)

    thread = threading.Thread(target=worker, name=f"delete-message-{chat_id}-{message_id}", daemon=True)
    thread.start()

def delete_message_batch(chat_id, candidates):
    candidates = [int(item) for item in candidates if int(item or 0) > 0]
    if not candidates:
        return 0
    workers = max(1, min(TELEGRAM_CLEAR_WORKERS, len(candidates)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return sum(1 for ok in executor.map(lambda item: delete_telegram_message(chat_id, item), candidates) if ok)

def clear_chat_messages(chat_id: str, message_id: int | str, count: int | None = None, known_message_ids: list[int] | None = None) -> tuple[int, int]:
    """Best-effort delete recent chat messages using known ids plus backward scanning.
    
    Telegram has no bulk clear-history endpoint, so the returned tuple reports how
    many candidates were deleted and scanned."""
    deleted = 0
    scanned = 0
    start_id = int(message_id or 0)
    if start_id <= 0:
        return deleted, scanned
    limit = start_id if count is None else int(count)
    limit = max(1, min(TELEGRAM_CLEAR_MAX_MESSAGES, limit))

    seen = set()
    known = []
    for item in known_message_ids or []:
        try:
            candidate = int(item)
        except (TypeError, ValueError):
            continue
        if 0 < candidate <= start_id and candidate not in seen:
            known.append(candidate)
            seen.add(candidate)
    if start_id not in seen:
        known.append(start_id)
        seen.add(start_id)
    known.sort(reverse=True)

    if known:
        scanned += len(known)
        deleted += delete_message_batch(chat_id, known)

    empty_batches = 0
    batch = []
    lower_bound = max(0, start_id - limit)
    for candidate_id in range(start_id, lower_bound, -1):
        if candidate_id in seen:
            continue
        seen.add(candidate_id)
        batch.append(candidate_id)
        if len(batch) < TELEGRAM_CLEAR_BATCH_SIZE:
            continue
        scanned += len(batch)
        batch_deleted = delete_message_batch(chat_id, batch)
        deleted += batch_deleted
        if batch_deleted:
            empty_batches = 0
        else:
            empty_batches += 1
        batch = []
        if count is None and empty_batches * TELEGRAM_CLEAR_BATCH_SIZE >= TELEGRAM_CLEAR_STOP_AFTER_MISSES:
            break
    if batch:
        scanned += len(batch)
        deleted += delete_message_batch(chat_id, batch)
    return deleted, scanned

def start_clear_chat_messages(chat_id, message_id, count=None, ready_message=None, known_message_ids=None):
    chat_key = str(chat_id or "")
    with CLEAR_LOCK:
        if chat_key in CLEAR_ACTIVE_CHATS:
            log(f"telegram clear already running chat={chat_key}")
            return False
        CLEAR_ACTIVE_CHATS.add(chat_key)

    def worker():
        try:
            started = now_ts()
            deleted, scanned = clear_chat_messages(chat_id, message_id, count, known_message_ids=known_message_ids)
            log(
                f"telegram clear chat={chat_key} deleted={deleted} "
                f"scanned={scanned} duration={now_ts() - started}s"
            )
            if ready_message:
                send_telegram(ready_message, chat_id=chat_id)
        finally:
            with CLEAR_LOCK:
                CLEAR_ACTIVE_CHATS.discard(chat_key)

    thread = threading.Thread(target=worker, name=f"clear-chat-{chat_key}", daemon=True)
    thread.start()
    return True

def set_bot_commands(state, dry_run=False):
    if dry_run or DRY_RUN or not TELEGRAM_BOT_TOKEN:
        return
    if int(state.get("bot_commands_version", 0) or 0) >= BOT_COMMANDS_VERSION:
        return

    commands = json.dumps([
        {"command": "menu", "description": "Open control panel"},
        {"command": "clear", "description": "Clear this chat"},
    ], ensure_ascii=False)
    telegram_api("setMyCommands", {"commands": commands})
    state["bot_commands_version"] = BOT_COMMANDS_VERSION
    log("telegram bot command menu set: /menu, /clear")

def telegram_get_updates(offset, timeout=None):
    if not TELEGRAM_BOT_TOKEN:
        return []
    poll_timeout = TELEGRAM_GET_UPDATES_TIMEOUT_SECONDS if timeout is None else timeout
    poll_timeout = max(0, int(poll_timeout or 0))
    params = {"timeout": poll_timeout}
    if offset:
        params["offset"] = int(offset)
    data = telegram_api("getUpdates", params, max_retries=1, timeout=poll_timeout + 5)
    if not data.get("ok"):
        raise RuntimeError(f"getUpdates failed: {data}")
    return data.get("result", [])
