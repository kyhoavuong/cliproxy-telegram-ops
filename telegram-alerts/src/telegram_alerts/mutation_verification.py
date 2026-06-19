"""Best-effort verification for Telegram-triggered key/quota mutations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import sqlite3

from . import quota_config
from .storage import load_json
from .utils import normalize_limit

STATE_MARKER_FIELDS = (
    "disabled_by_quota",
    "manually_disabled_keys",
    "cpa_deleted_while_quota_disabled",
    "cpa_deleted_restore_pending",
)


@dataclass
class MarkerSnapshot:
    markers: dict[str, set[str]] = field(default_factory=dict)
    unavailable: bool = False


@dataclass
class VerificationResult:
    unavailable: list[str] = field(default_factory=list)
    mismatches: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.unavailable and not self.mismatches

    def warning_line(self) -> str:
        if self.mismatches:
            return f"Saved, but verification found a mismatch: {self.mismatches[0]}."
        if self.unavailable:
            return f"Saved, but verification could not confirm {self.unavailable[0]}."
        return ""


def append_verification_warning(text: str, result: VerificationResult) -> str:
    warning = result.warning_line()
    if not warning:
        return text
    return f"{str(text).rstrip()}\n\n{warning}"


def _empty_markers() -> dict[str, set[str]]:
    return {field: set() for field in STATE_MARKER_FIELDS}


def quota_marker_snapshot() -> MarkerSnapshot:
    try:
        state = load_json(quota_config.QUOTA_STATE, {})
    except Exception:
        return MarkerSnapshot(_empty_markers(), unavailable=True)
    if not isinstance(state, dict):
        state = {}
    return MarkerSnapshot({field: quota_config.quota_state_key_set(state, field) for field in STATE_MARKER_FIELDS})


def _snapshot_markers(snapshot: MarkerSnapshot | dict[str, set[str]] | None) -> dict[str, set[str]]:
    if isinstance(snapshot, MarkerSnapshot):
        return snapshot.markers
    if isinstance(snapshot, dict):
        return {field: set(snapshot.get(field, set())) for field in STATE_MARKER_FIELDS}
    return _empty_markers()


def _snapshot_unavailable(snapshot: MarkerSnapshot | dict[str, set[str]] | None) -> bool:
    return isinstance(snapshot, MarkerSnapshot) and snapshot.unavailable


def _add_unavailable(result: VerificationResult, label: str) -> None:
    if label not in result.unavailable:
        result.unavailable.append(label)


def _proxy_keys(result: VerificationResult) -> set[str] | None:
    try:
        if not quota_config.CLIPROXY_CONFIG.exists():
            _add_unavailable(result, "proxy config")
            return None
        return set(quota_config.parse_api_keys_block(quota_config.CLIPROXY_CONFIG.read_text(encoding="utf-8")))
    except Exception:
        _add_unavailable(result, "proxy config")
        return None


def _quota_item(key: str, result: VerificationResult) -> tuple[dict[str, Any] | None, bool]:
    try:
        if not quota_config.QUOTA_CONFIG.exists():
            _add_unavailable(result, "quota config")
            return None, False
        quotas = quota_config.load_quotas_json()
        keys = quotas.get("keys", []) if isinstance(quotas, dict) else []
        for item in keys:
            if isinstance(item, dict) and str(item.get("key") or "").strip() == key:
                return item, True
    except Exception:
        _add_unavailable(result, "quota config")
        return None, False
    return None, True


def _cpa_status(key: str, result: VerificationResult) -> str:
    try:
        if not quota_config.USAGE_DB.exists():
            _add_unavailable(result, "usage registry")
            return "unavailable"
        con = sqlite3.connect(f"file:{quota_config.USAGE_DB}?mode=ro", uri=True, timeout=4)
        try:
            row = con.execute(
                "SELECT COALESCE(is_deleted, 0) FROM cpa_api_keys WHERE api_key = ?",
                (key,),
            ).fetchone()
        finally:
            con.close()
    except Exception:
        _add_unavailable(result, "usage registry")
        return "unavailable"
    if row is None:
        return "missing"
    return "deleted" if bool(row[0]) else "active"


def _requested_effective_weekly(daily: Any, weekly: Any) -> Any:
    return quota_config.effective_weekly_limit(normalize_limit(daily), weekly)


def _item_effective_weekly(item: dict[str, Any]) -> Any:
    daily = normalize_limit(item.get("daily_token_limit"))
    weekly = normalize_limit(item.get("weekly_token_limit")) if "weekly_token_limit" in item else "default"
    return quota_config.effective_weekly_limit(daily, weekly)


def _verify_cpa_active(key: str, result: VerificationResult) -> None:
    status = _cpa_status(key, result)
    if status not in {"active", "unavailable"}:
        result.mismatches.append("usage registry is not active for this key")


def _verify_cpa_deleted(key: str, result: VerificationResult) -> None:
    status = _cpa_status(key, result)
    if status not in {"deleted", "unavailable"}:
        result.mismatches.append("usage registry did not mark this key deleted")


def verify_mutation(
    action_type: str,
    params: dict[str, Any],
    *,
    changed_key: str = "",
    before_markers: MarkerSnapshot | dict[str, set[str]] | None = None,
) -> VerificationResult:
    result = VerificationResult()
    key = str(changed_key or params.get("key") or "").strip()
    if not key:
        _add_unavailable(result, "selected key")
        return result

    proxy_keys = _proxy_keys(result)
    quota_item, quota_available = _quota_item(key, result)
    marker_snapshot = quota_marker_snapshot()
    markers = _snapshot_markers(marker_snapshot)
    markers_available = not _snapshot_unavailable(marker_snapshot)
    if not markers_available:
        _add_unavailable(result, "quota state")
    manual_markers = markers.get("manually_disabled_keys", set())

    if action_type == "key_create":
        if proxy_keys is not None and key not in proxy_keys:
            result.mismatches.append("proxy config does not list this key")
        if quota_available and quota_item is None:
            result.mismatches.append("quota config is missing this key")
        _verify_cpa_active(key, result)
        return result

    if action_type == "key_disable":
        if proxy_keys is not None and key in proxy_keys:
            result.mismatches.append("proxy config still lists this key")
        if quota_available and quota_item is None:
            result.mismatches.append("quota config is missing this key")
        if markers_available and key not in manual_markers:
            result.mismatches.append("manual-disabled marker is missing")
        _verify_cpa_active(key, result)
        return result

    if action_type == "key_enable":
        if proxy_keys is not None and key not in proxy_keys:
            result.mismatches.append("proxy config does not list this key")
        if quota_available and quota_item is None:
            result.mismatches.append("quota config is missing this key")
        if markers_available and key in manual_markers:
            result.mismatches.append("manual-disabled marker still lists this key")
        _verify_cpa_active(key, result)
        return result

    if action_type == "key_delete":
        if proxy_keys is not None and key in proxy_keys:
            result.mismatches.append("proxy config still lists this key")
        if quota_available and quota_item is not None:
            result.mismatches.append("quota config still lists this key")
        if markers_available:
            for field in STATE_MARKER_FIELDS:
                if key in markers.get(field, set()):
                    result.mismatches.append("state markers still list this key")
                    break
        _verify_cpa_deleted(key, result)
        return result

    if action_type == "quota_set":
        if quota_available and quota_item is None:
            result.mismatches.append("quota config is missing this key")
        elif quota_item is not None:
            daily = normalize_limit(params.get("daily"))
            requested_weekly = params.get("weekly", "default")
            if normalize_limit(quota_item.get("daily_token_limit")) != daily:
                result.mismatches.append("quota daily limit does not match")
            elif _item_effective_weekly(quota_item) != _requested_effective_weekly(daily, requested_weekly):
                result.mismatches.append("quota weekly limit does not match")
        if before_markers is not None:
            before_unavailable = _snapshot_unavailable(before_markers)
            if before_unavailable or not markers_available:
                _add_unavailable(result, "quota state")
            else:
                comparable_before = {field: set(_snapshot_markers(before_markers).get(field, set())) for field in STATE_MARKER_FIELDS}
                comparable_after = {field: set(markers.get(field, set())) for field in STATE_MARKER_FIELDS}
                if comparable_before != comparable_after:
                    result.mismatches.append("state markers changed during quota update")
        return result

    return result
