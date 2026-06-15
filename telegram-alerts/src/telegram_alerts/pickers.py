"""Inline picker builders for account-scoped key, usage, and quota flows."""

from .settings import QUOTA_PICKER_PAGE_SIZE
from .utils import log, log_timing, mask_key, msg, monotonic_ms, now_ts, short_code
from .keyboards import button, inline_keyboard, key_reveal_actions_keyboard, reply
from .quota_config import (
    format_effective_weekly_for_reply,
    format_limit_for_reply,
    format_operator_quota_limit,
    active_manually_disabled_keys,
    key_accounts_for_picker,
    manually_disabled_keys,
    quota_account_by_key,
    quota_accounts_for_picker,
    quota_update_summary,
    short_button_label,
)
from .usage import build_usage_report, get_usage_breakdown_for_key, usage_accounts_for_picker
from .actions import create_pending_action, execute_key_reveal, pending_scope, scoped_pending_map

def prompt_key_create(state, chat_id=None, user_id=None, message_id=None):
    pending_inputs, scope = scoped_pending_map(state, "pending_inputs", "pending_input", chat_id, user_id)
    pending = {
        "type": "key_create",
        "expires_at": now_ts() + 5 * 60,
    }
    try:
        prompt_message_id = int(message_id or 0)
    except (TypeError, ValueError):
        prompt_message_id = 0
    if prompt_message_id > 0:
        pending["cleanup_message_ids"] = [prompt_message_id]
    pending_inputs[scope] = pending
    result = reply(msg("key_create_prompt"), inline_keyboard([[
        button(msg("cancel"), "cancel_input"),
    ]]))
    result["track_pending_input_prompt"] = "key_create"
    return result

def prompt_key_lookup(state, chat_id=None, user_id=None):
    pending_inputs, scope = scoped_pending_map(state, "pending_inputs", "pending_input", chat_id, user_id)
    pending_inputs[scope] = {
        "type": "key_lookup",
        "expires_at": now_ts() + 5 * 60,
    }
    return reply("Enter the exact user to show the full API key.", inline_keyboard([[
        button(msg("cancel"), "cancel_input"),
    ]]))

def quota_picker_state(state, chat_id=None, user_id=None):
    pickers = state.setdefault("quota_pickers", {})
    if not isinstance(pickers, dict):
        pickers = {}
        state["quota_pickers"] = pickers
    scope = pending_scope(chat_id, user_id)
    return pickers, scope

def key_picker_state(state, chat_id=None, user_id=None):
    pickers = state.setdefault("key_pickers", {})
    if not isinstance(pickers, dict):
        pickers = {}
        state["key_pickers"] = pickers
    scope = pending_scope(chat_id, user_id)
    return pickers, scope

def usage_picker_state(state, chat_id=None, user_id=None):
    pickers = state.setdefault("usage_pickers", {})
    if not isinstance(pickers, dict):
        pickers = {}
        state["usage_pickers"] = pickers
    scope = pending_scope(chat_id, user_id)
    return pickers, scope

PICKER_TTL_SECONDS = 10 * 60
DAILY_PRESET_LIMITS = {
    "20m": 20_000_000,
    "40m": 40_000_000,
    "60m": 60_000_000,
    "80m": 80_000_000,
    "100m": 100_000_000,
    "200m": 200_000_000,
}


def picker_is_valid(picker, picker_id, required_fields):
    if not isinstance(picker, dict) or picker.get("id") != picker_id:
        return False
    if now_ts() > int(picker.get("expires_at", 0) or 0):
        return False
    for field in required_fields:
        value = picker.get(field)
        if not isinstance(value, list):
            return False
    return True


def extend_picker_ttl(picker):
    if isinstance(picker, dict):
        picker["expires_at"] = now_ts() + PICKER_TTL_SECONDS


def expired_picker_reply(label, callback):
    return reply(
        f"This {label.lower()} picker expired. Open {label} again.",
        inline_keyboard([[button(label, callback), button("Menu", "menu:back")]]),
    )


def render_account_picker_page(title, aliases, picker_id, item_prefix, page_prefix, page=0, status_callback=None, cancel_callback=None, include_menu=True):
    """Render one bounded picker page using stable callback indexes from the cached picker state."""
    page_size = max(4, QUOTA_PICKER_PAGE_SIZE)
    max_page = max(0, (len(aliases) - 1) // page_size)
    page = max(0, min(int(page or 0), max_page))
    start = page * page_size
    visible = aliases[start:start + page_size]
    rows = []
    for index, alias in enumerate(visible, start=start):
        rows.append([button(short_button_label(alias), f"{item_prefix}:{picker_id}:{index}")])
    nav = []
    if page > 0:
        nav.append(button("Prev", f"{page_prefix}:{picker_id}:{page - 1}"))
    if page < max_page:
        nav.append(button("Next", f"{page_prefix}:{picker_id}:{page + 1}"))
    if nav:
        if cancel_callback:
            nav.insert(0, button("Cancel", cancel_callback))
        elif status_callback:
            nav.insert(0, button("Key Status", status_callback))
        rows.append(nav)
    if include_menu or not nav:
        rows.append([button("Menu", "menu:back")])
    return reply(title, inline_keyboard(rows)), page, max_page


def add_picker_cancel_menu_row(result, cancel_callback):
    rows = ((result.get("reply_markup") or {}).get("inline_keyboard") or []) if isinstance(result, dict) else []
    if not rows:
        return result
    last_row = rows[-1]
    if len(last_row) == 1 and last_row[0].get("callback_data") == "menu:back":
        rows[-1] = [button("Cancel", cancel_callback), last_row[0]]
    return result


def log_picker_event(kind, event, picker_id, page=0, items=0, max_page=0, reason=""):
    parts = [
        f"picker {kind} {event}",
        f"picker_id={picker_id or '-'}",
        f"page={page}",
        f"items={items}",
        f"max_page={max_page}",
    ]
    if reason:
        parts.append(f"reason={reason}")
    log(" ".join(parts))

def prompt_key_reveal_picker(state, chat_id=None, user_id=None, page=0, picker_id=None):
    """Build or reuse a Show key picker; the full key is revealed only after account selection."""
    pickers, scope = key_picker_state(state, chat_id, user_id)
    current = pickers.get(scope) if isinstance(pickers.get(scope), dict) else {}
    title = "Show Key\n\nChoose a user to show the full API key."
    if picker_id:
        if not picker_is_valid(current, picker_id, ("keys", "aliases")):
            log_picker_event("key", "page_cache_miss", picker_id, page=page, reason="expired")
            return expired_picker_reply("Show key", "menu:key_lookup")
        extend_picker_ttl(current)
        result, page, max_page = render_account_picker_page(
            title,
            current.get("aliases") or [],
            picker_id,
            "kreveal",
            "kpage",
            page,
            cancel_callback="menu:key_status",
        )
        log_picker_event("key", "page_cache_hit", picker_id, page=page, items=len(current.get("aliases") or []), max_page=max_page)
        return result

    accounts = key_accounts_for_picker()
    if not accounts:
        return reply("No API keys found.", inline_keyboard([[button("Menu", "menu:back")]]))
    picker_id = current.get("id") or short_code()
    pickers[scope] = {
        "id": picker_id,
        "keys": [account["key"] for account in accounts],
        "aliases": [account["alias"] for account in accounts],
        "expires_at": now_ts() + PICKER_TTL_SECONDS,
    }
    result, page, max_page = render_account_picker_page(
        title,
        pickers[scope]["aliases"],
        picker_id,
        "kreveal",
        "kpage",
        page,
        cancel_callback="menu:key_status",
    )
    log_picker_event("key", "fresh", picker_id, page=page, items=len(accounts), max_page=max_page)
    return result

def build_key_reveal_from_picker(state, picker_id, account_index, chat_id=None, user_id=None):
    pickers, scope = key_picker_state(state, chat_id, user_id)
    picker = pickers.get(scope)
    if not isinstance(picker, dict) or picker.get("id") != picker_id:
        return reply("This key picker expired. Open Show key again.", inline_keyboard([[button("Show key", "menu:key_lookup"), button("Menu", "menu:back")]]))
    try:
        index = int(account_index)
        key = str((picker.get("keys") or [])[index])
        alias = str((picker.get("aliases") or [])[index])
    except Exception:
        return reply("Invalid key selection. Open Show key again.", inline_keyboard([[button("Show key", "menu:key_lookup"), button("Menu", "menu:back")]]))
    return reply(execute_key_reveal({"alias": alias, "key": key}), key_reveal_actions_keyboard())


KEY_MANAGEMENT_ACTIONS = {
    "disable": {
        "title": "Disable Key",
        "callback": "menu:key_disable",
        "pending_type": "key_disable",
        "confirm_title": "Pending key disable",
        "verb": "disable",
    },
    "enable": {
        "title": "Enable Key",
        "callback": "menu:key_enable",
        "pending_type": "key_enable",
        "confirm_title": "Pending key enable",
        "verb": "enable",
    },
    "delete": {
        "title": "Delete Key",
        "callback": "menu:key_delete",
        "pending_type": "key_delete",
        "confirm_title": "Pending key deletion",
        "verb": "delete",
    },
}


def key_management_accounts_for_action(action):
    accounts = quota_accounts_for_picker()
    manual_keys = active_manually_disabled_keys(manually_disabled_keys())
    if action == "enable":
        return [
            account
            for account in accounts
            if str(account.get("key") or "").strip() in manual_keys
        ]
    if action == "disable":
        return [
            account
            for account in accounts
            if str(account.get("key") or "").strip() not in manual_keys
        ]
    return accounts


def prompt_key_management_picker(state, action, chat_id=None, user_id=None, page=0, picker_id=None):
    config = KEY_MANAGEMENT_ACTIONS.get(str(action or ""))
    if not config:
        return reply("Unknown key action. Open Key Status again.", inline_keyboard([[button("Key Status", "menu:key_status"), button("Menu", "menu:back")]]))
    pickers, scope = key_picker_state(state, chat_id, user_id)
    current = pickers.get(scope) if isinstance(pickers.get(scope), dict) else {}
    title = f"{config['title']}\n\nChoose a user to {config['verb']}."
    if picker_id:
        if not picker_is_valid(current, picker_id, ("keys", "aliases")) or current.get("action") != action:
            log_picker_event("key_manage", "page_cache_miss", picker_id, page=page, reason="expired")
            return expired_picker_reply(config["title"], config["callback"])
        extend_picker_ttl(current)
        cancel_callback = "menu:key_status" if current.get("action") in {"disable", "delete"} else None
        result, page, max_page = render_account_picker_page(title, current.get("aliases") or [], picker_id, "kmanage", "kmpage", page, cancel_callback=cancel_callback)
        if current.get("action") == "enable":
            result = add_picker_cancel_menu_row(result, "menu:key_status")
        log_picker_event("key_manage", "page_cache_hit", picker_id, page=page, items=len(current.get("aliases") or []), max_page=max_page)
        return result

    accounts = key_management_accounts_for_action(action)
    if not accounts:
        if action == "enable":
            if manually_disabled_keys():
                return reply(
                    "Manual disabled key state is stale. Open Key Status or restore the key from backup.",
                    inline_keyboard([[button("Cancel", "menu:key_status"), button("Menu", "menu:back")]]),
                )
            return reply(
                "No manually disabled keys found.",
                inline_keyboard([[button("Cancel", "menu:key_status"), button("Menu", "menu:back")]]),
            )
        return reply("No quota-managed API keys found.", inline_keyboard([[button("Menu", "menu:back")]]))
    picker_id = short_code()
    pickers[scope] = {
        "id": picker_id,
        "action": action,
        "keys": [account["key"] for account in accounts],
        "aliases": [account["alias"] for account in accounts],
        "expires_at": now_ts() + PICKER_TTL_SECONDS,
    }
    cancel_callback = "menu:key_status" if action in {"disable", "delete"} else None
    result, page, max_page = render_account_picker_page(title, pickers[scope]["aliases"], picker_id, "kmanage", "kmpage", page, cancel_callback=cancel_callback)
    if action == "enable":
        result = add_picker_cancel_menu_row(result, "menu:key_status")
    log_picker_event("key_manage", "fresh", picker_id, page=page, items=len(accounts), max_page=max_page)
    return result


def create_key_management_from_picker(state, picker_id, account_index, chat_id=None, user_id=None):
    pickers, scope = key_picker_state(state, chat_id, user_id)
    picker = pickers.get(scope)
    if not isinstance(picker, dict) or picker.get("id") != picker_id:
        return reply("This key picker expired. Open Key Status again.", inline_keyboard([[button("Key Status", "menu:key_status"), button("Menu", "menu:back")]]))
    action = str(picker.get("action") or "")
    config = KEY_MANAGEMENT_ACTIONS.get(action)
    if not config:
        return reply("Unknown key action. Open Key Status again.", inline_keyboard([[button("Key Status", "menu:key_status"), button("Menu", "menu:back")]]))
    try:
        index = int(account_index)
        key = str((picker.get("keys") or [])[index])
        alias = str((picker.get("aliases") or [])[index])
    except Exception:
        return reply("Invalid key selection. Open Key Status again.", inline_keyboard([[button("Key Status", "menu:key_status"), button("Menu", "menu:back")]]))
    extend_picker_ttl(picker)
    summary_lines = [
        config["confirm_title"],
        "",
        f"User: {alias}",
        f"Key preview: {mask_key(key)}",
    ]
    if action == "disable":
        summary_lines.extend([
            "Current status: Active",
            "New status: Disabled",
        ])
    elif action == "enable":
        summary_lines.extend([
            "Current status: Disabled",
            "New status: Active",
        ])
    summary = "\n".join(summary_lines)
    return create_pending_action(
        state,
        config["pending_type"],
        {"key": key, "alias": alias},
        summary,
        chat_id=chat_id,
        user_id=user_id,
    )

def prompt_usage_picker(state, chat_id=None, user_id=None, page=0, picker_id=None):
    """Build or reuse a usage picker that caches account metadata, not usage query results."""
    pickers, scope = usage_picker_state(state, chat_id, user_id)
    current = pickers.get(scope) if isinstance(pickers.get(scope), dict) else {}
    title = "Usage\n\nChoose a user:"
    required = ("keys", "aliases", "daily_limits", "weekly_limits", "statuses", "masked")
    if picker_id:
        if not picker_is_valid(current, picker_id, required):
            log_picker_event("usage", "page_cache_miss", picker_id, page=page, reason="expired")
            return expired_picker_reply("Usage", "menu:usage")
        extend_picker_ttl(current)
        result, page, max_page = render_account_picker_page(
            title,
            current.get("aliases") or [],
            picker_id,
            "uacct",
            "upage",
            page,
            cancel_callback="menu:top",
        )
        log_picker_event("usage", "page_cache_hit", picker_id, page=page, items=len(current.get("aliases") or []), max_page=max_page)
        return result

    tz_name, accounts = usage_accounts_for_picker()
    if not accounts:
        return reply("No usage accounts found.", inline_keyboard([[button("Menu", "menu:back")]]))
    picker_id = current.get("id") or short_code()
    pickers[scope] = {
        "id": picker_id,
        "keys": [account["key"] for account in accounts],
        "aliases": [account["alias"] for account in accounts],
        "daily_limits": [account.get("daily") for account in accounts],
        "weekly_limits": [account.get("weekly") for account in accounts],
        "statuses": [account.get("status", "") for account in accounts],
        "masked": [account.get("masked", "") for account in accounts],
        "tz_name": tz_name,
        "expires_at": now_ts() + PICKER_TTL_SECONDS,
    }
    result, page, max_page = render_account_picker_page(
        title,
        pickers[scope]["aliases"],
        picker_id,
        "uacct",
        "upage",
        page,
        cancel_callback="menu:top",
    )
    log_picker_event("usage", "fresh", picker_id, page=page, items=len(accounts), max_page=max_page)
    return result

def build_usage_report_from_picker(state, picker_id, account_index, chat_id=None, user_id=None):
    started = monotonic_ms()
    pickers, scope = usage_picker_state(state, chat_id, user_id)
    picker = pickers.get(scope)
    if not isinstance(picker, dict) or picker.get("id") != picker_id:
        return reply("This usage picker expired. Open Usage again.", inline_keyboard([[button("Usage", "menu:usage"), button("Menu", "menu:back")]]))
    try:
        index = int(account_index)
        account = {
            "key": str((picker.get("keys") or [])[index]),
            "alias": str((picker.get("aliases") or [])[index]),
            "daily": (picker.get("daily_limits") or [])[index],
            "weekly": (picker.get("weekly_limits") or [])[index],
            "status": str((picker.get("statuses") or [])[index]),
            "masked": str((picker.get("masked") or [])[index]),
        }
    except Exception:
        return reply("Invalid usage selection. Open Usage again.", inline_keyboard([[button("Usage", "menu:usage"), button("Menu", "menu:back")]]))
    tz_name = str(picker.get("tz_name") or "Asia/Ho_Chi_Minh")
    picker["expires_at"] = now_ts() + 10 * 60
    usage = get_usage_breakdown_for_key(account["key"], tz_name)
    text = build_usage_report(account, usage, tz_name)
    log_timing("usage_report", started, status=account.get("status", ""))
    return reply(
        text,
        inline_keyboard([
            [button("Menu", "menu:back"), button("Another user", "menu:usage")],
            [button("Refresh", f"uacct:{picker_id}:{index}")],
        ]),
    )

def prompt_quota_picker(state, chat_id=None, user_id=None, page=0, picker_id=None):
    """Build or reuse an Edit quota picker whose selection feeds the later Confirm step."""
    pickers, scope = quota_picker_state(state, chat_id, user_id)
    current = pickers.get(scope) if isinstance(pickers.get(scope), dict) else {}
    title = "Edit Quota\n\nChoose a user:"
    if picker_id:
        if not picker_is_valid(current, picker_id, ("keys", "aliases")):
            log_picker_event("quota", "page_cache_miss", picker_id, page=page, reason="expired")
            return expired_picker_reply("Edit quota", "menu:quota_set")
        extend_picker_ttl(current)
        result, page, max_page = render_account_picker_page(
            title,
            current.get("aliases") or [],
            picker_id,
            "qacct",
            "qpage",
            page,
            cancel_callback="menu:back",
            include_menu=False,
        )
        log_picker_event("quota", "page_cache_hit", picker_id, page=page, items=len(current.get("aliases") or []), max_page=max_page)
        return result

    accounts = quota_accounts_for_picker()
    if not accounts:
        return reply("No quota accounts found.", inline_keyboard([[button("Menu", "menu:back")]]))
    picker_id = current.get("id") or short_code()
    pickers[scope] = {
        "id": picker_id,
        "keys": [account["key"] for account in accounts],
        "aliases": [account["alias"] for account in accounts],
        "expires_at": now_ts() + PICKER_TTL_SECONDS,
    }
    result, page, max_page = render_account_picker_page(
        title,
        pickers[scope]["aliases"],
        picker_id,
        "qacct",
        "qpage",
        page,
        cancel_callback="menu:back",
        include_menu=False,
    )
    log_picker_event("quota", "fresh", picker_id, page=page, items=len(accounts), max_page=max_page)
    return result

def quota_picker_expired_reply():
    return reply("This quota picker expired. Open Edit quota again.", inline_keyboard([[button("Edit quota", "menu:quota_set"), button("Menu", "menu:back")]]))


def invalid_quota_selection_reply():
    return reply("Invalid account selection. Open Edit quota again.", inline_keyboard([[button("Edit quota", "menu:quota_set"), button("Menu", "menu:back")]]))


def invalid_quota_option_reply():
    return reply("Invalid quota option. Open Edit quota again.", inline_keyboard([[button("Edit quota", "menu:quota_set"), button("Menu", "menu:back")]]))


def build_same_key_quota_limit_picker(state, ref, quota_kind, chat_id=None, user_id=None):
    edits = state.get("quota_same_key_edits", {})
    if not isinstance(edits, dict):
        return quota_picker_expired_reply()
    scope = pending_scope(chat_id, user_id)
    scoped_edits = edits.get(scope)
    if not isinstance(scoped_edits, dict):
        return quota_picker_expired_reply()
    item = scoped_edits.get(str(ref or ""))
    if not isinstance(item, dict):
        return quota_picker_expired_reply()
    if now_ts() > int(item.get("expires_at", 0) or 0):
        scoped_edits.pop(str(ref or ""), None)
        return quota_picker_expired_reply()
    key = str(item.get("key") or "").strip()
    if not key:
        return quota_picker_expired_reply()
    pickers, picker_scope = quota_picker_state(state, chat_id, user_id)
    pickers[picker_scope] = {
        "id": str(ref or ""),
        "selected_key": key,
        "expires_at": now_ts() + PICKER_TTL_SECONDS,
    }
    if quota_kind == "daily":
        return build_daily_quota_limit_picker(state, ref, None, chat_id=chat_id, user_id=user_id)
    if quota_kind == "weekly":
        return build_weekly_quota_limit_picker(state, ref, None, chat_id=chat_id, user_id=user_id)
    return invalid_quota_option_reply()


def quota_account_from_picker(state, picker_id, account_index=None, chat_id=None, user_id=None):
    pickers, scope = quota_picker_state(state, chat_id, user_id)
    picker = pickers.get(scope)
    if not isinstance(picker, dict) or picker.get("id") != picker_id:
        return None, None, quota_picker_expired_reply()
    key = picker.get("selected_key")
    if account_index is not None:
        keys = picker.get("keys") or []
        try:
            key = keys[int(account_index)]
        except Exception:
            return None, None, invalid_quota_selection_reply()
    account = quota_account_by_key(key)
    if not account:
        return None, None, reply("Quota account no longer exists. Open Edit quota again.", inline_keyboard([[button("Edit quota", "menu:quota_set"), button("Menu", "menu:back")]]))
    picker["selected_key"] = key
    picker["expires_at"] = now_ts() + 10 * 60
    return picker, account, None


def build_quota_limit_picker(state, picker_id, account_index, chat_id=None, user_id=None):
    _picker, account, error = quota_account_from_picker(state, picker_id, account_index, chat_id=chat_id, user_id=user_id)
    if error:
        return error
    rows = [
        [button("Daily quota", f"qdaily:{picker_id}:{account_index}"), button("Weekly quota", f"qweekly:{picker_id}:{account_index}")],
        [button("Cancel", f"qpage:{picker_id}:0"), button("Menu", "menu:back")],
    ]
    return reply(
        "\n".join([
            "Edit Quota",
            "",
            f"User: {account['alias']}",
            f"Daily quota: {format_operator_quota_limit(account.get('daily'))}",
            f"Weekly quota: {format_effective_weekly_for_reply(account.get('daily'), account.get('weekly'))}",
            "",
            "Choose quota to edit:",
        ]),
        inline_keyboard(rows),
    )


def build_daily_quota_limit_picker(state, picker_id, account_index, chat_id=None, user_id=None):
    _picker, account, error = quota_account_from_picker(state, picker_id, account_index, chat_id=chat_id, user_id=user_id)
    if error:
        return error
    rows = [
        [button("20M", f"qlimit:{picker_id}:20m"), button("40M", f"qlimit:{picker_id}:40m")],
        [button("60M", f"qlimit:{picker_id}:60m"), button("80M", f"qlimit:{picker_id}:80m")],
        [button("100M", f"qlimit:{picker_id}:100m"), button("200M", f"qlimit:{picker_id}:200m")],
        [button("Menu", "menu:back"), button("Custom", f"qlimit:{picker_id}:custom")],
    ]
    return reply(
        "\n".join([
            "Edit Quota",
            "",
            f"User: {account['alias']}",
            f"Current daily: {format_operator_quota_limit(account.get('daily'))}",
            f"Current weekly: {format_effective_weekly_for_reply(account.get('daily'), account.get('weekly'))}",
            "",
            "Choose new daily quota:",
        ]),
        inline_keyboard(rows),
    )


def build_weekly_quota_limit_picker(state, picker_id, account_index, chat_id=None, user_id=None):
    _picker, account, error = quota_account_from_picker(state, picker_id, account_index, chat_id=chat_id, user_id=user_id)
    if error:
        return error
    rows = [
        [button("Default", f"qweek:{picker_id}:default"), button("Unlimited", f"qweek:{picker_id}:none")],
        [button("Menu", "menu:back"), button("Custom", f"qweek:{picker_id}:custom")],
    ]
    return reply(
        "\n".join([
            "Edit Weekly Quota",
            "",
            f"User: {account['alias']}",
            f"Current daily: {format_operator_quota_limit(account.get('daily'))}",
            f"Current weekly: {format_effective_weekly_for_reply(account.get('daily'), account.get('weekly'))}",
            "",
            "Choose new weekly quota:",
        ]),
        inline_keyboard(rows),
    )

def create_quota_update_from_picker(state, picker_id, limit_code, chat_id=None, user_id=None):
    picker, account, error = quota_account_from_picker(state, picker_id, chat_id=chat_id, user_id=user_id)
    if error:
        return error
    key = picker.get("selected_key")
    weekly = account.get("weekly", "default")
    if limit_code == "custom":
        pending_inputs, input_scope = scoped_pending_map(state, "pending_inputs", "pending_input", chat_id, user_id)
        pending_inputs[input_scope] = {
            "type": "quota_custom",
            "key": key,
            "weekly": weekly,
            "expires_at": now_ts() + 5 * 60,
        }
        return reply(
            "\n".join([
                "Custom quota",
                "",
                f"User: {account['alias']}",
                f"Current daily: {format_operator_quota_limit(account.get('daily'))}",
                f"Current weekly: {format_effective_weekly_for_reply(account.get('daily'), account.get('weekly'))}",
                "",
                "Send the new daily quota, for example: 10M, 150M, or none.",
            ]),
            inline_keyboard([[button(msg("cancel"), "cancel_input")]]),
        )
    try:
        daily = DAILY_PRESET_LIMITS[limit_code]
    except KeyError:
        return invalid_quota_option_reply()
    return create_pending_action(
        state,
        "quota_set",
        {"query": key, "daily": daily, "weekly": weekly, "quota_kind": "daily"},
        quota_update_summary(account, daily, weekly),
        chat_id=chat_id,
        user_id=user_id,
    )

def create_weekly_quota_update_from_picker(state, picker_id, limit_code, chat_id=None, user_id=None):
    picker, account, error = quota_account_from_picker(state, picker_id, chat_id=chat_id, user_id=user_id)
    if error:
        return error
    key = picker.get("selected_key")
    daily = account.get("daily")
    if limit_code == "custom":
        pending_inputs, input_scope = scoped_pending_map(state, "pending_inputs", "pending_input", chat_id, user_id)
        pending_inputs[input_scope] = {
            "type": "quota_weekly_custom",
            "key": key,
            "expires_at": now_ts() + 5 * 60,
        }
        return reply(
            "\n".join([
                "Custom weekly quota",
                "",
                f"User: {account['alias']}",
                f"Current daily: {format_operator_quota_limit(account.get('daily'))}",
                f"Current weekly: {format_effective_weekly_for_reply(account.get('daily'), account.get('weekly'))}",
                "",
                "Send the new weekly quota, for example: 400M, 800M, default, or unlimited.",
            ]),
            inline_keyboard([[button(msg("cancel"), "cancel_input")]]),
        )
    if limit_code == "default":
        weekly = "default"
    elif limit_code == "none":
        weekly = None
    else:
        return invalid_quota_option_reply()
    return create_pending_action(
        state,
        "quota_set",
        {"query": key, "daily": daily, "weekly": weekly, "quota_kind": "weekly"},
        quota_update_summary(account, daily, weekly),
        chat_id=chat_id,
        user_id=user_id,
    )
