"""Main loop for polling Telegram, refreshing snapshots, and persisting monitor state."""

import argparse
import threading
import time
import traceback
from urllib.error import URLError

from .settings import (
    ALERT_HOSTNAME,
    AUTH_QUOTA_INSPECTION_WAIT_SECONDS,
    AUTH_QUOTA_REFRESH_COOLDOWN_SECONDS,
    AUTH_QUOTA_REFRESH_BEFORE_CHECK,
    COMMAND_POLL_SECONDS,
    CPA_REGISTRY_SYNC_INTERVAL_SECONDS,
    DRY_RUN,
    INTERVAL_SECONDS,
    STATE_FILE,
    TELEGRAM_KNOWN_MESSAGES_MAX,
)
from .utils import log, log_timing, monotonic_ms, now_ts
from .storage import load_json, save_json
from .quota_config import sync_cpa_registry_from_quotas
from .telegram_client import send_telegram, set_bot_commands
from .snapshot import build_snapshot, dict_to_alert
from .change_watch import process_change_notifications
from .handlers import prewarm_menu_fast_caches, process_alerts, process_commands

# Background workers return snapshot results through this small handoff object;
# the main loop remains the owner of persistent Telegram state mutations/saves.
_ALERT_SNAPSHOT_LOCK = threading.Lock()
_ALERT_SNAPSHOT_JOB = {"running": False, "result": None}
AUTH_INSPECTION_STATE_KEY = "auth_quota_inspection"


def auth_inspection_state(state):
    item = state.setdefault(AUTH_INSPECTION_STATE_KEY, {})
    if not isinstance(item, dict):
        item = {}
        state[AUTH_INSPECTION_STATE_KEY] = item
    return item


def auth_snapshot_options(state, ts=None):
    """Return auth inspection snapshot options using a low-frequency refresh cadence.

    Usage Keeper quota refresh is asynchronous; the alert loop may run frequently,
    but auth quota refresh is intentionally cooled down so partial post-refresh
    payloads are normal updating evidence instead of high-frequency incidents."""
    ts = now_ts() if ts is None else int(ts)
    item = auth_inspection_state(state)
    try:
        next_refresh_at = int(item.get("next_refresh_at", 0) or 0)
    except (TypeError, ValueError):
        next_refresh_at = 0
    refresh_due = bool(AUTH_QUOTA_REFRESH_BEFORE_CHECK) and ts >= next_refresh_at
    if refresh_due:
        item["last_refresh_started_at"] = ts
        item["next_refresh_at"] = ts + max(0, int(AUTH_QUOTA_REFRESH_COOLDOWN_SECONDS or 0))
    return {
        "auth_refresh_before_check": refresh_due,
        "auth_wait_for_refresh": refresh_due,
        "auth_wait_seconds": AUTH_QUOTA_INSPECTION_WAIT_SECONDS,
        "auth_inspection_state": dict(item),
        "auth_refresh_triggered": refresh_due,
    }


def update_auth_inspection_state(state, observation, refresh_triggered=False, ts=None):
    ts = now_ts() if ts is None else int(ts)
    item = auth_inspection_state(state)
    observation = observation if isinstance(observation, dict) else {}
    item["raw_current_complete"] = bool(observation.get("complete"))
    item["raw_current_reason"] = str(observation.get("reason") or "")[:80]
    if refresh_triggered:
        item["last_refresh_finished_at"] = ts
    if observation.get("complete"):
        observed = [str(key) for key in observation.get("observed_identity_keys") or [] if str(key or "").strip()]
        healthy = [str(key) for key in observation.get("healthy_identity_keys") or [] if str(key or "").strip()]
        failed = [str(key) for key in observation.get("failed_identity_keys") or [] if str(key or "").strip()]
        failed_auth_indexes = [
            str(key).strip().lower()
            for key in observation.get("failed_auth_index_keys") or []
            if len(str(key or "").strip()) == 16
            and all(ch in "0123456789abcdefABCDEF" for ch in str(key or "").strip())
        ]
        failed_labels = observation.get("failed_labels") if isinstance(observation.get("failed_labels"), dict) else {}
        item["last_complete_at"] = ts
        item["observed_count"] = len(set(observed))
        item["healthy_count"] = len(set(healthy))
        item["failed_count"] = len(set(failed))
        item["failed_identity_keys"] = sorted(set(failed))
        item["failed_auth_index_keys"] = sorted(set(failed_auth_indexes))
        item["failed_labels"] = {
            str(key): str(value)[:80]
            for key, value in failed_labels.items()
            if str(key) in set(failed)
        }
    return item


def start_alert_snapshot_job(auth_refresh_before_check, auth_wait_for_refresh, auth_wait_seconds=None, auth_inspection_state=None, auth_refresh_triggered=False):
    """Start one background snapshot refresh; the main loop owns consuming and saving the result."""
    with _ALERT_SNAPSHOT_LOCK:
        if _ALERT_SNAPSHOT_JOB.get("running") or _ALERT_SNAPSHOT_JOB.get("result") is not None:
            return False
        _ALERT_SNAPSHOT_JOB["running"] = True

    def worker():
        started = monotonic_ms()
        result = None
        try:
            snapshot = build_snapshot(
                auth_refresh_before_check=auth_refresh_before_check,
                auth_wait_for_refresh=auth_wait_for_refresh,
                auth_wait_seconds=auth_wait_seconds,
                auth_inspection_state=auth_inspection_state,
            )
            result = {"snapshot": snapshot, "error": "", "auth_refresh_triggered": bool(auth_refresh_triggered)}
            log_timing("alert_snapshot_worker", started, ok=1)
        except Exception as exc:
            frames = traceback.extract_tb(exc.__traceback__)
            frame = frames[-1] if frames else None
            location = "unknown"
            if frame is not None:
                location = f"{frame.filename}:{frame.lineno}:{frame.name}"
            log(f"alert snapshot worker exception {exc.__class__.__name__} location={location}")
            result = {"snapshot": None, "error": str(exc)}
            log_timing("alert_snapshot_worker", started, ok=0)
        finally:
            with _ALERT_SNAPSHOT_LOCK:
                _ALERT_SNAPSHOT_JOB["running"] = False
                _ALERT_SNAPSHOT_JOB["result"] = result

    thread = threading.Thread(target=worker, name="alert-snapshot-worker", daemon=True)
    thread.start()
    return True


def take_alert_snapshot_result():
    with _ALERT_SNAPSHOT_LOCK:
        result = _ALERT_SNAPSHOT_JOB.get("result")
        _ALERT_SNAPSHOT_JOB["result"] = None
    return result


def cleanup_state(state):
    """Prune expired scoped interaction state and remove legacy keys from removed features."""
    changed = False
    ts = now_ts()
    for field in ("pending_actions", "pending_inputs", "quota_pickers", "key_pickers", "usage_pickers"):
        items = state.get(field)
        if isinstance(items, dict):
            for key, value in list(items.items()):
                if not isinstance(value, dict) or ts > int(value.get("expires_at", 0) or 0):
                    items.pop(key, None)
                    changed = True
    # Removed features/old schemas are pruned here so stale persisted state cannot
    # re-enable hidden command behavior after a restart.
    for field in (
        "pending_action",
        "pending_input",
        "language",
        "silenced_until",
        "silenced_until_by_chat",
        "acked",
        "start_acknowledged",
        "recent_start",
        "suppress_start_until",
        "suppressed_change_keys",
    ):
        if field in state:
            state.pop(field, None)
            changed = True
    known = state.get("known_messages")
    if isinstance(known, dict):
        for chat_key, values in list(known.items()):
            trimmed = sorted(set(int(v) for v in values if int(v or 0) > 0))[-TELEGRAM_KNOWN_MESSAGES_MAX:]
            if trimmed:
                if trimmed != values:
                    known[chat_key] = trimmed
                    changed = True
            else:
                known.pop(chat_key, None)
                changed = True
    active = state.get("active")
    if isinstance(active, dict) and "auth:unavailable" in active:
        active.pop("auth:unavailable", None)
        changed = True
    audit = state.get("action_audit")
    if isinstance(audit, list) and len(audit) > 20:
        del audit[:-20]
        changed = True
    return changed

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="run one check and exit")
    parser.add_argument("--dry-run", action="store_true", help="print Telegram messages instead of sending")
    args = parser.parse_args()

    next_alert_check = 0
    next_cpa_registry_sync = 0
    while True:
        try:
            if now_ts() >= next_cpa_registry_sync:
                if not (args.dry_run or DRY_RUN):
                    try:
                        changed = sync_cpa_registry_from_quotas()
                        if changed:
                            log(f"synced CPA registry from quotas.json changed={changed}")
                    except Exception as exc:
                        log(f"failed to sync CPA registry from quotas.json: {exc}")
                next_cpa_registry_sync = now_ts() + max(5, CPA_REGISTRY_SYNC_INTERVAL_SECONDS)

            state = load_json(STATE_FILE, {"active": {}})
            cleaned = cleanup_state(state)
            set_bot_commands(state, dry_run=args.dry_run)
            change_sent_before = process_change_notifications(state, dry_run=args.dry_run)
            handled = process_commands(state, dry_run=args.dry_run)
            change_sent_after = process_change_notifications(state, dry_run=args.dry_run, force=bool(handled))
            if (handled or cleaned or change_sent_before or change_sent_after) and not (args.dry_run or DRY_RUN):
                save_json(STATE_FILE, state)

            alert_result = take_alert_snapshot_result()
            if alert_result:
                if alert_result.get("error"):
                    raise RuntimeError(f"alert snapshot worker failed: {alert_result['error']}")
                snapshot = alert_result.get("snapshot") or {}
                state["snapshot"] = snapshot
                prewarm_menu_fast_caches(state, snapshot, include_errors=True)
                update_auth_inspection_state(
                    state,
                    snapshot.get("auth_quota_observation"),
                    refresh_triggered=bool(alert_result.get("auth_refresh_triggered")),
                )
                alerts = {
                    alert_id: dict_to_alert(alert)
                    for alert_id, alert in snapshot.get("system_alerts", {}).items()
                }
                process_alerts(
                    alerts,
                    state,
                    dry_run=args.dry_run,
                    auth_quota_observation=snapshot.get("auth_quota_observation"),
                    gpt_pool_5h_observation=snapshot.get("gpt_pool_5h_observation"),
                )

            if now_ts() >= next_alert_check:
                auth_options = auth_snapshot_options(state)
                if args.once:
                    snapshot = build_snapshot(
                        auth_refresh_before_check=auth_options["auth_refresh_before_check"],
                        auth_wait_for_refresh=auth_options["auth_wait_for_refresh"],
                        auth_wait_seconds=auth_options["auth_wait_seconds"],
                        auth_inspection_state=auth_options["auth_inspection_state"],
                    )
                    state["snapshot"] = snapshot
                    prewarm_menu_fast_caches(state, snapshot, include_errors=True)
                    update_auth_inspection_state(
                        state,
                        snapshot.get("auth_quota_observation"),
                        refresh_triggered=auth_options["auth_refresh_triggered"],
                    )
                    alerts = {
                        alert_id: dict_to_alert(alert)
                        for alert_id, alert in snapshot.get("system_alerts", {}).items()
                    }
                    process_alerts(
                        alerts,
                        state,
                        dry_run=args.dry_run,
                        auth_quota_observation=snapshot.get("auth_quota_observation"),
                        gpt_pool_5h_observation=snapshot.get("gpt_pool_5h_observation"),
                    )
                else:
                    started = start_alert_snapshot_job(**auth_options)
                    if started and not (args.dry_run or DRY_RUN):
                        save_json(STATE_FILE, state)
                next_alert_check = now_ts() + max(5, INTERVAL_SECONDS)

            if handled:
                log(f"handled telegram commands={handled}")
        except (URLError, TimeoutError) as exc:
            log(f"monitor skipped transient network error: {exc}")
        except Exception as exc:
            log(f"monitor error: {exc}")
            send_telegram(
                f"[CRITICAL] {ALERT_HOSTNAME}: telegram alert monitor loop error\n\n{exc}",
                dry_run=args.dry_run,
            )

        if args.once:
            return 0
        time.sleep(max(0.1, COMMAND_POLL_SECONDS))
