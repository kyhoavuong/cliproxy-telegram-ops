"""Pending input/action handlers for key reveal, key creation, and quota edits."""

from __future__ import annotations
from typing import Any
from .contracts import TelegramReply

from .settings import CLIPROXY_CONFIG, PENDING_ACTION_TTL_SECONDS, QUOTA_STATE
from .storage import load_json
from .utils import log, log_timing, mask_key, monotonic_ms, msg, now_ts, short_code
from .keyboards import (
    button,
    inline_keyboard,
    key_create_actions_keyboard,
    key_reveal_actions_keyboard,
    key_management_success_actions_keyboard,
    key_status_keyboard,
    quota_update_actions_keyboard,
    reply,
)
from .quota_config import (
    apply_weekly_limit,
    backup_action_files,
    describe_quota_match,
    format_effective_weekly_for_reply,
    format_limit_for_reply,
    format_operator_quota_limit,
    format_weekly_behavior,
    generate_api_key,
    load_cpa_alias_map,
    load_quotas_json,
    parse_api_keys_block,
    parse_key_create_answer,
    parse_limit,
    quota_account_by_key,
    quota_update_summary,
    save_quota_state_json,
    save_quotas_json,
    slugify_name,
    soft_delete_cpa_api_key,
    upsert_cpa_api_key_alias,
    write_config_api_keys,
)

# Pending inputs/actions are scoped by chat and user so two authorized
# operators can use the bot at the same time without stealing each other's
# Confirm/Cancel buttons or typed replies.
def pending_scope(chat_id=None, user_id=None):
    return f"{chat_id or 'default'}:{user_id or 'default'}"

def scoped_pending_map(state: dict[str, Any], field: str, legacy_field: str | None = None, chat_id: str | None = None, user_id: str | None = None) -> tuple[dict[str, Any], str]:
    """Return the pending-state bucket for one chat/user scope.
    
    If a legacy global pending item exists, migrate it into the caller scope once
    so concurrent operators do not share Confirm/Cancel state."""
    scoped = state.setdefault(field, {})
    if not isinstance(scoped, dict):
        scoped = {}
        state[field] = scoped
    scope = pending_scope(chat_id, user_id)
    # Older bot versions stored one global pending action/input. Migrate that
    # state into the caller's scope once, then remove the legacy field so future
    # interactions stay private per operator.
    if legacy_field and scope not in scoped and isinstance(state.get(legacy_field), dict):
        scoped[scope] = state.pop(legacy_field)
    return scoped, scope

def cleanup_message_ids_from(value) -> list[int]:
    ids = []
    if not isinstance(value, (list, tuple, set)):
        return ids
    for item in value:
        try:
            message_id = int(item or 0)
        except (TypeError, ValueError):
            continue
        if message_id > 0 and message_id not in ids:
            ids.append(message_id)
    return ids


def create_pending_action(
    state: dict[str, Any],
    action_type: str,
    params: dict[str, Any],
    summary: str,
    chat_id: str | None = None,
    user_id: str | None = None,
    cleanup_message_ids: list[int] | None = None,
) -> TelegramReply:
    """Store a short-lived scoped Confirm/Cancel action and return its prompt.
    
    The stored shape is intentionally JSON-compatible because it lives in Telegram
    monitor state between polling ticks."""
    code = short_code()
    pending_actions, scope = scoped_pending_map(state, "pending_actions", "pending_action", chat_id, user_id)
    pending_action = {
        "code": code,
        "type": action_type,
        "params": params,
        "summary": summary,
        "expires_at": now_ts() + PENDING_ACTION_TTL_SECONDS,
        "created_at": now_ts(),
    }
    cleanup_ids = cleanup_message_ids_from(cleanup_message_ids)
    if cleanup_ids:
        pending_action["cleanup_message_ids"] = cleanup_ids
    pending_actions[scope] = pending_action
    return reply("\n".join([
        summary,
        "",
        msg("confirm_hint"),
    ]), inline_keyboard([[
        button(msg("cancel"), f"cancel:{code}"),
        button(msg("confirm"), f"confirm:{code}"),
    ]]))

def find_keys_by_exact_alias(alias):
    target = str(alias or "").strip().lower()
    if not target:
        return []
    aliases = load_cpa_alias_map()
    results = []
    seen = set()
    for key, key_alias in aliases.items():
        if str(key_alias or "").strip().lower() == target and key not in seen:
            results.append((str(key_alias), str(key)))
            seen.add(str(key))
    try:
        quotas = load_quotas_json()
        for item in quotas.get("keys", []):
            key = str(item.get("key", ""))
            name = str(item.get("name", ""))
            if key and key not in seen and name.strip().lower() == target:
                results.append((name, key))
                seen.add(key)
    except Exception:
        pass
    return results

def build_key_lookup_reply(alias):
    # This is the intentional authorized reveal path; generated/pending summaries
    # must stay masked, but the final reply may contain the full key.
    matches = find_keys_by_exact_alias(alias)
    if not matches:
        return f"No API key found for exact alias '{alias}'."
    lines = [f"API key lookup for '{alias}':", ""]
    for key_alias, key in matches:
        lines.extend([
            f"User: {key_alias}",
            f"API key: {key}",
            "",
        ])
    lines.append("Keep this key private.")
    return reply("\n".join(lines).strip(), key_reveal_actions_keyboard())


def execute_key_reveal(params):
    alias = str(params.get("alias") or "unknown")
    key = str(params.get("key") or "")
    if not key:
        raise ValueError("missing API key for reveal")
    return "\n".join([
        "API key",
        "",
        f"User: {alias}",
        f"API key: {key}",
        "",
        "Keep this key private.",
    ])


def build_key_create_summary(alias, name, daily, weekly, new_key):
    # Backend write targets are implementation details and should not appear in
    # mobile-visible pending text; change-watch keeps source evidence internally.
    return "\n".join([
        "Pending API key creation",
        "",
        f"User: {alias}",
        f"Key prefix: {name}",
        f"Daily quota: {format_limit_for_reply(daily)}",
        f"Weekly quota: {format_weekly_behavior(daily, weekly)}",
        f"Key preview: {mask_key(new_key)}",
    ])

def handle_pending_input(
    text: str,
    state: dict[str, Any],
    chat_id: str | None = None,
    user_id: str | None = None,
    message_id: int | str | None = None,
) -> str | TelegramReply | None:
    """Consume a typed reply for the scoped pending input, if one exists.
    
    Returns None when the message is unrelated, plain text for validation failures,
    or a TelegramReply/pending confirmation for recognized input flows."""
    pending_inputs, scope = scoped_pending_map(state, "pending_inputs", "pending_input", chat_id, user_id)
    pending = pending_inputs.get(scope)
    if not isinstance(pending, dict):
        return None
    if now_ts() > int(pending.get("expires_at", 0) or 0):
        pending_inputs.pop(scope, None)
        return msg("pending_expired")
    cleanup_ids = cleanup_message_ids_from(pending.get("cleanup_message_ids"))
    try:
        input_message_id = int(message_id or 0)
    except (TypeError, ValueError):
        input_message_id = 0
    if input_message_id > 0 and input_message_id not in cleanup_ids:
        cleanup_ids.append(input_message_id)
    pending_type = pending.get("type")
    if pending_type == "key_lookup":
        pending_inputs.pop(scope, None)
        return build_key_lookup_reply(text)
    if pending_type == "quota_custom":
        try:
            daily = parse_limit(text)
        except ValueError as exc:
            return f"{msg('invalid_input')}: {exc}"
        key = pending.get("key", "")
        weekly = pending.get("weekly", "default")
        account = quota_account_by_key(key)
        if not account:
            pending_inputs.pop(scope, None)
            return "Quota account no longer exists. Open /menu and choose Edit quota again."
        pending_inputs.pop(scope, None)
        return create_pending_action(
            state,
            "quota_set",
            {"query": key, "daily": daily, "weekly": weekly, "quota_kind": "daily"},
            quota_update_summary(account, daily, weekly),
            chat_id=chat_id,
            user_id=user_id,
            cleanup_message_ids=cleanup_ids,
        )
    if pending_type == "quota_weekly_custom":
        try:
            weekly = parse_limit(text, allow_default=True)
        except ValueError as exc:
            return f"{msg('invalid_input')}: {exc}"
        key = pending.get("key", "")
        account = quota_account_by_key(key)
        if not account:
            pending_inputs.pop(scope, None)
            return "Quota account no longer exists. Open /menu and choose Edit quota again."
        daily = account.get("daily")
        pending_inputs.pop(scope, None)
        return create_pending_action(
            state,
            "quota_set",
            {"query": key, "daily": daily, "weekly": weekly, "quota_kind": "weekly"},
            quota_update_summary(account, daily, weekly),
            chat_id=chat_id,
            user_id=user_id,
            cleanup_message_ids=cleanup_ids,
        )
    if pending_type != "key_create":
        pending_inputs.pop(scope, None)
        return msg("pending_unknown")

    try:
        alias, name, daily = parse_key_create_answer(text)
    except ValueError as exc:
        return f"{msg('invalid_input')}: {exc}"

    weekly = "default"
    existing_config_keys = parse_api_keys_block(CLIPROXY_CONFIG.read_text(encoding="utf-8"))
    quotas = load_quotas_json()
    existing_quota_keys = {str(item.get("key", "")) for item in quotas.get("keys", [])}
    for _ in range(20):
        new_key = generate_api_key(name)
        if new_key not in existing_config_keys and new_key not in existing_quota_keys:
            break
    else:
        return "Failed to generate unique API key. Try again."

    pending_inputs.pop(scope, None)
    summary = build_key_create_summary(alias, name, daily, weekly, new_key)
    return create_pending_action(
        state,
        "key_create",
        {"alias": alias, "name": name, "daily": daily, "weekly": weekly, "key": new_key},
        summary,
        chat_id=chat_id,
        user_id=user_id,
        cleanup_message_ids=cleanup_ids,
    )

def execute_key_create(params: dict[str, Any]) -> str:
    """Create one shared API key across proxy config, quota config, and CPA alias rows.
    
    Callers must have already created a rollback backup and confirmed operator intent;
    the returned string intentionally includes the final full key."""
    name = slugify_name(params["name"])
    alias = str(params.get("alias") or name).strip()
    daily = params["daily"]
    weekly = params.get("weekly", "default")
    new_key = str(params.get("key", "")).strip()
    existing_config_keys = parse_api_keys_block(CLIPROXY_CONFIG.read_text(encoding="utf-8"))
    quotas = load_quotas_json()
    existing_quota_keys = {str(item.get("key", "")) for item in quotas.get("keys", [])}

    if not new_key:
        for _ in range(20):
            new_key = generate_api_key(name)
            if new_key not in existing_config_keys and new_key not in existing_quota_keys:
                break
        else:
            raise RuntimeError("failed to generate unique API key")

    backup_action_files("key-create", include_usage_db=True, cpa_api_keys=[new_key])

    new_config_keys = list(existing_config_keys)
    if new_key not in new_config_keys:
        new_config_keys.append(new_key)
        write_config_api_keys(new_config_keys)

    quota_item = next(
        (item for item in quotas.get("keys", []) if str(item.get("key", "")) == new_key),
        None,
    )
    if quota_item is None:
        quota_item = {
            "name": alias,
            "key": new_key,
            "daily_token_limit": daily,
        }
        apply_weekly_limit(quota_item, weekly)
        quotas["keys"].append(quota_item)
    else:
        quota_item["name"] = alias
        quota_item["daily_token_limit"] = daily
        apply_weekly_limit(quota_item, weekly)
    save_quotas_json(quotas)
    upsert_cpa_api_key_alias(new_key, alias)

    return "\n".join([
        "API key created.",
        "",
        f"User: {alias}",
        "Base URL: https://api.example.com",
        f"API key: {new_key}",
        "",
        "Keep this key private.",
    ])

def execute_quota_set(params: dict[str, Any], return_key: bool = False) -> str | tuple[str, str]:
    """Apply one confirmed quota update after creating a rollback backup.
    
    The weekly value preserves quota semantics: default removes the explicit field,
    None disables the weekly cap, and integers set a finite weekly cap."""
    query = params["query"]
    daily = params["daily"]
    weekly = params["weekly"]
    quotas = load_quotas_json()
    alias_by_key = load_cpa_alias_map()
    matches = []
    for item in quotas.get("keys", []):
        key = str(item.get("key", ""))
        name = str(item.get("name", ""))
        alias = alias_by_key.get(key) or name
        masked = mask_key(key)
        query_l = str(query).lower()
        if (
            query_l == key.lower()
            or key.lower().startswith(query_l)
            or query_l == alias.lower()
            or query_l in alias.lower()
            or query_l == name.lower()
            or query_l in masked.lower()
        ):
            matches.append(item)

    if not matches:
        raise ValueError(f"no quota key matched '{query}'")
    if len(matches) > 1:
        choices = "\n".join(f"- {describe_quota_match(item)}" for item in matches[:10])
        raise ValueError(f"'{query}' matched multiple keys; use a more specific alias or key prefix:\n{choices}")

    item = matches[0]
    backup_dir = backup_action_files("quota-set", include_usage_db=False)
    item["daily_token_limit"] = daily
    apply_weekly_limit(item, weekly)
    save_quotas_json(quotas)

    changed_key = str(item.get("key", ""))
    account_label = alias_by_key.get(changed_key) or item.get("name") or "unknown"
    log(f"quota_set backup={backup_dir} account={account_label}")
    # Keep the operator result distinct from the automatic "Quota updated"
    # watcher notification so the two messages do not look like duplicates.
    message = "\n".join([
        "Quota update applied.",
        "",
        f"User: {account_label}",
        f"Daily: {format_operator_quota_limit(daily)}",
        f"Weekly: {format_effective_weekly_for_reply(daily, weekly)}",
        "Backup created for rollback.",
    ])
    if return_key:
        return message, changed_key
    return message


MANUALLY_DISABLED_KEYS_FIELD = "manually_disabled_keys"


def quota_state_data():
    data = load_json(QUOTA_STATE, {})
    return data if isinstance(data, dict) else {}


def quota_state_key_set(data: dict[str, Any], field: str) -> set[str]:
    value = data.get(field)
    if isinstance(value, dict):
        source = value.keys()
    elif isinstance(value, list):
        source = value
    else:
        source = []
    return {str(item or "").strip() for item in source if str(item or "").strip()}


def set_quota_state_key_set(data: dict[str, Any], field: str, keys: set[str]) -> None:
    data[field] = sorted(str(key) for key in keys if str(key or "").strip())


def key_alias_for_message(params: dict[str, Any]) -> str:
    return str(params.get("alias") or "selected key").strip() or "selected key"


def config_api_keys() -> list[str]:
    return parse_api_keys_block(CLIPROXY_CONFIG.read_text(encoding="utf-8"))


def quota_item_for_key(quotas: dict[str, Any], key: str) -> dict[str, Any] | None:
    for item in quotas.get("keys", []):
        if isinstance(item, dict) and str(item.get("key") or "").strip() == key:
            return item
    return None


def remove_key_from_quota_state(data: dict[str, Any], key: str) -> bool:
    changed = False
    for field in ("disabled_by_quota", MANUALLY_DISABLED_KEYS_FIELD, "cpa_deleted_while_quota_disabled"):
        keys = quota_state_key_set(data, field)
        if key in keys:
            keys.discard(key)
            set_quota_state_key_set(data, field, keys)
            changed = True
    return changed


def execute_key_management(action_type: str, params: dict[str, Any]) -> None:
    key = str(params.get("key") or "").strip()
    alias = key_alias_for_message(params)
    if not key:
        raise ValueError("Selected key no longer exists. Open Key Status again.")

    quotas = load_quotas_json()
    quota_item = quota_item_for_key(quotas, key)
    state_data = quota_state_data()
    quota_disabled = quota_state_key_set(state_data, "disabled_by_quota")
    manually_disabled = quota_state_key_set(state_data, MANUALLY_DISABLED_KEYS_FIELD)

    if action_type == "key_disable":
        if key in quota_disabled:
            raise ValueError("This key is already disabled by quota exhaustion.")
        if quota_item is None:
            raise ValueError("Selected key no longer exists. Open Key Status again.")
        backup_action_files("key-disable", include_usage_db=False)
        keys = [item for item in config_api_keys() if item != key]
        write_config_api_keys(keys)
        manually_disabled.add(key)
        set_quota_state_key_set(state_data, MANUALLY_DISABLED_KEYS_FIELD, manually_disabled)
        save_quota_state_json(state_data)
        log(f"key_disable account={alias}")
        return None

    if action_type == "key_enable":
        if key in quota_disabled:
            raise ValueError("This key is disabled by quota exhaustion and cannot be manually enabled from this action.")
        if key not in manually_disabled:
            raise ValueError("This key is not marked as manually disabled.")
        if quota_item is None:
            raise ValueError("Selected key no longer exists. Open Key Status again.")
        backup_action_files("key-enable", include_usage_db=False)
        keys = config_api_keys()
        if key not in keys:
            keys.append(key)
            write_config_api_keys(keys)
        manually_disabled.discard(key)
        set_quota_state_key_set(state_data, MANUALLY_DISABLED_KEYS_FIELD, manually_disabled)
        save_quota_state_json(state_data)
        log(f"key_enable account={alias}")
        return None

    if action_type == "key_delete":
        backup_action_files("key-delete", include_usage_db=False, cpa_api_keys=[key])
        keys = [item for item in config_api_keys() if item != key]
        write_config_api_keys(keys)
        quota_items = quotas.get("keys", [])
        quotas["keys"] = [
            item for item in quota_items
            if not (isinstance(item, dict) and str(item.get("key") or "").strip() == key)
        ]
        save_quotas_json(quotas)
        if remove_key_from_quota_state(state_data, key):
            save_quota_state_json(state_data)
        soft_delete_cpa_api_key(key)
        log(f"key_delete account={alias}")
        return None

    raise ValueError(f"unknown key management action: {action_type}")


def key_management_success_message(action_type: str, params: dict[str, Any]) -> str:
    alias = str(params.get("alias") or "unknown").strip() or "unknown"
    masked = mask_key(params.get("key") or "")
    if action_type == "key_disable":
        return "\n".join([
            "API key disabled.",
            "",
            f"User: {alias}",
            f"API key: {masked}",
            "Status: Disabled",
            "",
            "This key can no longer be used for API requests.",
        ])
    if action_type == "key_enable":
        return "\n".join([
            "API key enabled.",
            "",
            f"User: {alias}",
            f"API key: {masked}",
            "Status: Active",
            "",
            "This key is now active and ready for use.",
        ])
    if action_type == "key_delete":
        return "\n".join([
            "API key deleted.",
            "",
            f"User: {alias}",
            f"API key: {masked}",
            "",
            "This key has been permanently removed from the system.",
        ])
    raise ValueError(f"unknown key management action: {action_type}")

def completed_action_seen(state, scope, code):
    if code is None:
        return False
    completed = state.get("completed_actions")
    if not isinstance(completed, dict):
        return False
    key = f"{scope}:{str(code or '').strip()}"
    item = completed.get(key)
    if not isinstance(item, dict):
        return False
    if now_ts() > int(item.get("expires_at", 0) or 0):
        completed.pop(key, None)
        return False
    return True


def remember_completed_action(state, scope, code):
    if code is None:
        return
    completed = state.setdefault("completed_actions", {})
    if not isinstance(completed, dict):
        completed = {}
        state["completed_actions"] = completed
    ts = now_ts()
    for key, item in list(completed.items()):
        if not isinstance(item, dict) or ts > int(item.get("expires_at", 0) or 0):
            completed.pop(key, None)
    completed[f"{scope}:{str(code or '').strip()}"] = {
        "expires_at": ts + 10 * 60,
    }


def register_quota_same_key_edit(state: dict[str, Any], key: str, chat_id: str | None = None, user_id: str | None = None) -> str:
    ref = short_code()
    edits = state.setdefault("quota_same_key_edits", {})
    if not isinstance(edits, dict):
        edits = {}
        state["quota_same_key_edits"] = edits
    scope = pending_scope(chat_id, user_id)
    scoped_edits = edits.setdefault(scope, {})
    if not isinstance(scoped_edits, dict):
        scoped_edits = {}
        edits[scope] = scoped_edits
    scoped_edits[ref] = {
        "key": key,
        "expires_at": now_ts() + 10 * 60,
    }
    return ref


def execute_pending_action(state: dict[str, Any], code: str | None = None, chat_id: str | None = None, user_id: str | None = None) -> TelegramReply | str | None:
    """Validate and execute the scoped pending action for a Confirm callback.
    
    Successful mutations invalidate the cached snapshot and keep duplicate Confirm
    callbacks idempotent without suppressing automatic change-watch notifications."""
    started = monotonic_ms()
    pending_actions, scope = scoped_pending_map(state, "pending_actions", "pending_action", chat_id, user_id)
    pending = pending_actions.get(scope)
    if not isinstance(pending, dict):
        if completed_action_seen(state, scope, code):
            return None
        return msg("no_pending")
    if now_ts() > int(pending.get("expires_at", 0) or 0):
        pending_actions.pop(scope, None)
        return msg("expired")
    if code is not None and str(code or "").strip() != str(pending.get("code", "")):
        return msg("invalid_code")

    action_type = pending.get("type")
    params = pending.get("params", {})
    changed_key = str(params.get("key") or "").strip()
    if action_type == "key_create":
        result = reply(execute_key_create(params), key_create_actions_keyboard())
    elif action_type == "quota_set":
        message, changed_key = execute_quota_set(params, return_key=True)
        changed_key = str(changed_key or "").strip()
        quota_kind = params.get("quota_kind")
        if quota_kind == "daily" and changed_key:
            same_key_callback = f"qsame:{register_quota_same_key_edit(state, changed_key, chat_id=chat_id, user_id=user_id)}:weekly"
        elif quota_kind == "weekly" and changed_key:
            same_key_callback = f"qsame:{register_quota_same_key_edit(state, changed_key, chat_id=chat_id, user_id=user_id)}:daily"
        else:
            same_key_callback = None
        result = reply(message, quota_update_actions_keyboard(quota_kind, same_key_callback))
    elif action_type in {"key_disable", "key_enable", "key_delete"}:
        try:
            execute_key_management(action_type, params)
            result = reply(
                key_management_success_message(action_type, params),
                key_management_success_actions_keyboard(action_type),
            )
        except ValueError as exc:
            result = reply(str(exc), key_status_keyboard())
    elif action_type == "key_reveal":
        result = reply(execute_key_reveal(params), key_reveal_actions_keyboard())
    else:
        raise ValueError(f"unknown pending action type: {action_type}")

    cleanup_ids = cleanup_message_ids_from(pending.get("cleanup_message_ids"))
    if cleanup_ids and isinstance(result, dict):
        result["delete_message_ids"] = cleanup_ids
    remember_completed_action(state, scope, pending.get("code"))
    pending_actions.pop(scope, None)
    state.pop("snapshot", None)
    state["snapshot_invalidated_at"] = now_ts()
    state["snapshot_invalidated_reason"] = action_type
    audit = state.setdefault("action_audit", [])
    audit_item = {
        "at": now_ts(),
        "type": action_type,
        "summary": pending.get("summary", ""),
    }
    # Keep an operator audit trail, but do not suppress change-watch notifications:
    # bot-created keys and bot-edited quotas still need one automatic alert.
    if changed_key and action_type in {"key_create", "quota_set", "key_disable", "key_enable", "key_delete"}:
        audit_item["key"] = changed_key
    audit.append(audit_item)
    del audit[:-20]
    log_timing("execute_pending_action", started, action=action_type)
    return result

def clear_pending_input(state, chat_id=None, user_id=None):
    pending_inputs, scope = scoped_pending_map(state, "pending_inputs", "pending_input", chat_id, user_id)
    return bool(pending_inputs.pop(scope, None))

def cancel_pending(state, code=None, input_only=False, chat_id=None, user_id=None):
    cancelled = False
    if not input_only:
        pending_actions, scope = scoped_pending_map(state, "pending_actions", "pending_action", chat_id, user_id)
        pending = pending_actions.get(scope)
        if isinstance(pending, dict):
            if code is not None and str(code or "").strip() != str(pending.get("code", "")):
                return msg("confirm_mismatch")
            pending_actions.pop(scope, None)
            cancelled = True
    pending_inputs, scope = scoped_pending_map(state, "pending_inputs", "pending_input", chat_id, user_id)
    if pending_inputs.pop(scope, None):
        cancelled = True
    if cancelled:
        return msg("cancelled")
    return msg("no_pending")
