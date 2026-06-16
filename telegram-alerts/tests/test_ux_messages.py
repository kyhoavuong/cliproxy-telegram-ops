from contextlib import contextmanager
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from unittest import mock

from telegram_alerts.actions import (
    build_key_create_summary,
    create_pending_action,
    execute_key_management,
    execute_key_create,
    execute_key_reveal,
    execute_quota_set,
    handle_pending_input,
)
from telegram_alerts.app import cleanup_state
from telegram_alerts.change_watch import build_change_events
from telegram_alerts.handlers import build_menu_reply, handle_callback, handle_command, process_commands
from telegram_alerts.health import Alert, build_alert_message, check_auth_quota_status
from telegram_alerts.keyboards import menu_keyboard, top_users_keyboard
from telegram_alerts.pickers import build_key_reveal_from_picker, build_usage_report_from_picker, prompt_key_lookup, prompt_key_management_picker, prompt_key_reveal_picker, prompt_quota_picker, prompt_usage_picker
from telegram_alerts.quota_config import quota_update_summary
from telegram_alerts.usage import build_usage_report, empty_usage_bucket
import telegram_alerts.logs as logs_module
import telegram_alerts.actions as actions_module
import telegram_alerts.handlers as handlers_module
import telegram_alerts.pickers as pickers_module
import telegram_alerts.quota_config as quota_config_module
import telegram_alerts.settings as settings_module
import telegram_alerts.snapshot as snapshot_module
from telegram_alerts.snapshot import (
    build_alerts_reply,
    build_overview_reply,
    build_quota_management_reply,
    build_quota_reply,
)


def auth_observation(healthy=None, failed=None, complete=True, reason=""):
    healthy = list(healthy or [])
    failed = list(failed or [])
    return {
        "complete": complete,
        "reason": reason,
        "observed_identity_keys": sorted(set(healthy) | set(failed)),
        "healthy_identity_keys": healthy,
        "failed_identity_keys": failed,
        "failed_labels": {key: key for key in failed},
    }


class TelegramUxMessageTests(unittest.TestCase):
    def setUp(self):
        @contextmanager
        def unlocked_runtime():
            yield

        self._runtime_lock_patch = mock.patch("telegram_alerts.actions.quota_runtime_lock", unlocked_runtime)
        self._runtime_lock_patch.start()
        self.addCleanup(self._runtime_lock_patch.stop)

    def test_menu_keyboard_matches_flat_top_level_layout(self):
        markup = menu_keyboard()
        labels = [button["text"] for row in markup["inline_keyboard"] for button in row]

        self.assertEqual(
            labels,
            [
                "Capacity Check",
                "Top Users",
                "Quota Management",
                "Key Status",
                "Health Alerts",
                "Errors Today",
                "Edit Quota",
                "Create Key",
            ],
        )
        self.assertNotIn("Usage", labels)
        self.assertNotIn("Accounts", labels)
        self.assertNotIn("Quota warnings", labels)
        self.assertNotIn("Show key", labels)
        self.assertNotIn("Overview", labels)
        self.assertNotIn("Refresh", labels)
        self.assertNotIn("Mute 30m", labels)
        self.assertNotIn("More", labels)
        callbacks = [button["callback_data"] for row in markup["inline_keyboard"] for button in row]
        self.assertEqual(
            callbacks,
            [
                "menu:capacity",
                "menu:top",
                "menu:quota_management",
                "menu:key_status",
                "menu:incidents",
                "menu:errors",
                "menu:quota_set",
                "menu:key_create",
            ],
        )

    def test_top_users_keyboard_keeps_usage_under_top_users_with_title_case(self):
        markup = top_users_keyboard()
        labels = [[button["text"] for button in row] for row in markup["inline_keyboard"]]
        callbacks = [[button["callback_data"] for button in row] for row in markup["inline_keyboard"]]

        self.assertEqual(labels, [["Menu", "Usage"], ["Refresh"]])
        self.assertEqual(callbacks, [["menu:back", "menu:usage"], ["menu:top_refresh"]])

    def test_overview_groups_health_attention_auth_accounts_and_freshness(self):
        snapshot = {
            "created_at": 0,
            "service_lines": ["- cliproxy: OK", "- usage-keeper: OK", "- quota-gate: OK"],
            "system_alerts": {},
            "auth_quota_observation": auth_observation(failed=["acct-a", "acct-b", "acct-c", "acct-d"]),
            "quota_signals": {},
            "quota_rows": [
                {
                    "alias": "alice",
                    "status": "active",
                    "daily_used": 2_000_000,
                    "daily_limit": 4_000_000,
                    "weekly_used": 2_000_000,
                    "weekly_limit": 16_000_000,
                    "effective_percent": 50.0,
                },
                {
                    "alias": "bob",
                    "status": "disabled",
                    "daily_used": 4_000_000,
                    "daily_limit": 4_000_000,
                    "weekly_used": 4_000_000,
                    "weekly_limit": 16_000_000,
                    "effective_percent": 100.0,
                },
            ],
            "quota_error": "",
            "enforcer_age": "5s",
        }

        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            (auth_dir / "codex-one.json").write_text(json.dumps({"type": "codex", "disabled": False}), encoding="utf-8")
            (auth_dir / "codex-two.json").write_text(json.dumps({"type": "codex", "disabled": True}), encoding="utf-8")
            (auth_dir / "antigravity-one.json").write_text(json.dumps({"disabled": False}), encoding="utf-8")
            with mock.patch.object(snapshot_module, "AUTH_DIR", auth_dir, create=True), \
                 mock.patch.object(snapshot_module, "now_ts", return_value=21), \
                 mock.patch.object(snapshot_module, "BOT_STARTED_AT", -(6 * 60 + 1)):
                text = build_overview_reply(snapshot)

        lines = text.splitlines()
        self.assertEqual(lines[0], "System Overview")
        self.assertNotIn("Cliproxy: Overview", text)
        self.assertNotIn("OK ", lines[0])
        self.assertNotIn("ALERT ", lines[0])
        self.assertEqual(lines[2], "Health")
        self.assertIn("- Cliproxy: OK", text)
        self.assertIn("- Usage Keeper: OK", text)
        self.assertIn("- Quota Gate: OK", text)
        self.assertNotIn("- Quota Enforcer log: updated 5s ago\n\nNeeds Attention", text)
        self.assertEqual(lines[7], "Needs Attention")
        self.assertNotIn("- Health alerts: 0 (0 critical, 0 warning)", text)
        self.assertIn("- Reauth needed: 4", text)
        self.assertIn("- Disabled keys: 1", text)
        self.assertEqual(lines[11], "Auth Accounts")
        self.assertIn("- Antigravity: 1 enabled, 0 disabled", text)
        self.assertIn("- Codex: 1 enabled, 1 disabled", text)
        self.assertEqual(lines[15], "Data Freshness")
        self.assertIn("- Updated 21s ago", text)
        self.assertIn("- Quota Enforcer log: updated 5s ago", text)
        self.assertLess(lines.index("- Updated 21s ago"), lines.index("- Quota Enforcer log: updated 5s ago"))
        self.assertLess(lines.index("- Quota Enforcer log: updated 5s ago"), lines.index("- Bot uptime: 6m 22s"))
        self.assertIn("- Bot uptime: 6m 22s", text)
        self.assertNotIn("Needs attention", text)
        self.assertNotIn("Auth accounts", text)
        self.assertNotIn("Data freshness", text)
        self.assertNotIn("quota warnings:", text)
        self.assertNotIn("shown here only", text)
        self.assertNotIn("Usage today", text)
        self.assertNotIn("top user", text.lower())
        self.assertNotIn("system incidents", text.lower())
        self.assertNotIn("quota signals", text.lower())
        self.assertNotIn("missing keys", text)

    def test_overview_hides_reauth_needed_when_zero(self):
        snapshot = {
            "created_at": 0,
            "service_lines": [],
            "system_alerts": {},
            "auth_quota_observation": auth_observation(),
            "quota_signals": {},
            "quota_rows": [],
            "quota_error": "",
            "enforcer_age": "5s",
        }

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(snapshot_module, "AUTH_DIR", Path(tmp), create=True), \
             mock.patch.object(snapshot_module, "now_ts", return_value=21), \
             mock.patch.object(snapshot_module, "BOT_STARTED_AT", 0):
            text = build_overview_reply(snapshot)

        self.assertNotIn("Reauth needed", text)

    def test_overview_hides_needs_attention_when_all_counts_are_zero(self):
        snapshot = {
            "created_at": 0,
            "service_lines": ["- cliproxy: OK"],
            "system_alerts": {},
            "auth_quota_observation": auth_observation(),
            "quota_signals": {},
            "quota_rows": [
                {
                    "alias": "alice",
                    "status": "active",
                    "daily_used": 1_000_000,
                    "daily_limit": 10_000_000,
                    "weekly_used": 2_000_000,
                    "weekly_limit": 40_000_000,
                    "effective_percent": 10.0,
                },
            ],
            "quota_error": "",
            "enforcer_age": "5s",
        }

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(snapshot_module, "AUTH_DIR", Path(tmp), create=True), \
             mock.patch.object(snapshot_module, "now_ts", return_value=21), \
             mock.patch.object(snapshot_module, "BOT_STARTED_AT", 0):
            text = build_overview_reply(snapshot)

        self.assertNotIn("Needs Attention", text)
        self.assertNotIn("- Health alerts: 0", text)
        self.assertNotIn("- Disabled keys: 0", text)
        self.assertIn("Auth Accounts", text)
        self.assertLess(text.index("Health"), text.index("Auth Accounts"))
        self.assertLess(text.index("Auth Accounts"), text.index("Data Freshness"))

    def test_overview_shows_health_alerts_only_when_nonzero(self):
        snapshot = {
            "created_at": 0,
            "service_lines": [],
            "system_alerts": {
                "x": {"alert_id": "x", "severity": "critical", "title": "X", "fingerprint": "x"},
                "y": {"alert_id": "y", "severity": "warning", "title": "Y", "fingerprint": "y"},
            },
            "auth_quota_observation": auth_observation(),
            "quota_signals": {},
            "quota_rows": [],
            "quota_error": "",
            "enforcer_age": "5s",
        }

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(snapshot_module, "AUTH_DIR", Path(tmp), create=True):
            text = build_overview_reply(snapshot)

        self.assertIn("Needs Attention", text)
        self.assertIn("- Health alerts: 2 (1 critical, 1 warning)", text)
        self.assertNotIn("- Disabled keys: 0", text)
        self.assertNotIn("Reauth needed", text)

    def test_snapshot_freshness_wording_uses_updated_ago_without_snapshot_duplication(self):
        cached_snapshot = self.capacity_snapshot(created_at=100, rows=self.healthy_user_key_rows())
        uncached_snapshot = {
            "created_at": 100,
            "service_lines": [],
            "system_alerts": {},
            "quota_signals": {},
            "quota_rows": [{"alias": "alice", "status": "active", "daily_used": 1, "daily_limit": 10}],
            "quota_error": "",
            "enforcer_age": "5s",
        }

        with mock.patch.object(snapshot_module, "now_ts", return_value=115), \
             mock.patch.object(snapshot_module, "hours_until_week_end", return_value=100.0):
            capacity_text = snapshot_module.build_capacity_reply(cached_snapshot, self.capacity_rate())
            key_status_text = snapshot_module.build_key_status_reply(cached_snapshot)
            alerts_text = build_alerts_reply({"created_at": 100, "system_alerts": {}})
            top_text = snapshot_module.build_top_reply(uncached_snapshot)

        with mock.patch.object(snapshot_module, "now_ts", return_value=105), \
             tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(snapshot_module, "AUTH_DIR", Path(tmp), create=True):
            overview_text = build_overview_reply(uncached_snapshot)

        self.assertIn("- Data: updated 15s ago.", capacity_text)
        self.assertIn("Data: updated 15s ago", key_status_text)
        self.assertIn("Data: updated 15s ago", alerts_text)
        self.assertIn("Data: updated 15s ago", top_text)
        self.assertIn("- Updated 5s ago", overview_text)
        combined = "\n".join([capacity_text, key_status_text, alerts_text, top_text, overview_text])
        self.assertNotIn("Data: cached,", combined)
        for old in ("snapshot 15s", "snapshot: snapshot", "Data: cached, snapshot", "Data: snapshot"):
            with self.subTest(old=old):
                self.assertNotIn(old, combined)

    def test_overview_auth_accounts_none_found_when_no_auth_files_exist(self):
        snapshot = {
            "created_at": 0,
            "service_lines": [],
            "system_alerts": {},
            "quota_signals": {},
            "quota_rows": [],
            "quota_error": "",
            "enforcer_age": "5s",
        }

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(snapshot_module, "AUTH_DIR", Path(tmp), create=True):
            text = build_overview_reply(snapshot)

        self.assertIn("Auth Accounts", text)
        self.assertIn("- None found", text)
        self.assertNotIn("Usage today", text)

    def test_empty_incidents_reply_lists_checks_performed(self):
        snapshot = {
            "created_at": 100,
            "system_alerts": {},
        }

        with mock.patch.object(snapshot_module, "now_ts", return_value=100):
            text = build_alerts_reply(snapshot)

        lines = text.splitlines()
        self.assertEqual(lines[0], "Health Alerts")
        self.assertIn("No active health alerts.", text)
        self.assertIn("Data: updated 0s ago", lines[1])
        self.assertNotIn("Data: snapshot", lines[1])
        self.assertIn("API health", text)
        self.assertIn("Usage Keeper health", text)
        self.assertIn("Quota Gate health", text)
        self.assertIn("Quota enforcer freshness", text)
        self.assertIn("Proxy auth quota inspection", text)
        self.assertNotIn("personal-cliproxy: No active health alerts", text)

    def test_active_health_alerts_reply_uses_standard_header_and_data_line(self):
        snapshot = {
            "created_at": 100,
            "system_alerts": {
                "service:cliproxy": {
                    "alert_id": "service:cliproxy",
                    "severity": "critical",
                    "title": "cliproxy is not reachable",
                    "body": "connect failed",
                    "fingerprint": "unreachable",
                }
            },
        }

        with mock.patch.object(snapshot_module, "now_ts", return_value=100):
            text = build_alerts_reply(snapshot)

        lines = text.splitlines()
        self.assertEqual(lines[0], "Health Alerts")
        self.assertIn("Data: updated 0s ago", lines[1])
        self.assertNotIn("Data: snapshot", lines[1])
        self.assertEqual(lines[2], "1 active health alert(s)")
        self.assertNotIn("personal-cliproxy: 1 active health alert", text)
        self.assertNotIn("Open Errors today for recent failed requests and raw log signals.", text)

    def test_transient_auth_unavailable_does_not_render_as_health_alert(self):
        state = {
            "snapshot": {
                "created_at": 1,
                "system_alerts": {
                    "auth:quota-inspection-unavailable": {
                        "alert_id": "auth:quota-inspection-unavailable",
                        "severity": "warning",
                        "title": "Proxy auth inspection unavailable",
                        "body": "quota inspection malformed payload: count-mismatch",
                        "fingerprint": "unavailable:malformed-payload",
                    }
                },
            },
            "active": {},
        }

        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]):
            result = handle_callback("menu:incidents", state, chat_id="chat", user_id="user", message_id=1)

        text = result["text"]
        self.assertIn("No active health alerts", text)
        self.assertNotIn("1 active health alert(s)", text)
        self.assertNotIn("Proxy auth inspection unavailable", text)

    def test_transient_auth_unavailable_does_not_increase_overview_health_count(self):
        state = {
            "snapshot": {
                "created_at": 1,
                "service_lines": [],
                "quota_signals": {},
                "quota_rows": [],
                "enforcer_age": "5s",
                "system_alerts": {
                    "auth:quota-inspection-unavailable": {
                        "alert_id": "auth:quota-inspection-unavailable",
                        "severity": "warning",
                        "title": "Proxy auth inspection unavailable",
                        "body": "quota inspection malformed payload: count-mismatch",
                        "fingerprint": "unavailable:malformed-payload",
                    }
                },
            },
            "active": {},
        }

        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]), \
             tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(snapshot_module, "AUTH_DIR", Path(tmp), create=True):
            result = build_menu_reply(state)

        text = result["text"]
        self.assertNotIn("- Health alerts: 0 (0 critical, 0 warning)", text)
        self.assertNotIn("Needs Attention", text)
        self.assertNotIn("- health alerts: 1", text)

    def test_sustained_auth_unavailable_renders_as_health_alert(self):
        state = {
            "snapshot": {
                "created_at": 1,
                "system_alerts": {
                    "auth:quota-inspection-unavailable": {
                        "alert_id": "auth:quota-inspection-unavailable",
                        "severity": "warning",
                        "title": "Proxy auth inspection unavailable",
                        "body": "quota inspection malformed payload: count-mismatch",
                        "fingerprint": "unavailable:malformed-payload",
                    }
                },
            },
            "active": {
                "auth:quota-inspection-unavailable": {
                    "severity": "warning",
                    "title": "Proxy auth inspection unavailable",
                    "fingerprint": "unavailable:malformed-payload",
                    "unavailable_first_seen": 100,
                    "unavailable_last_seen": 400,
                    "unavailable_recovery_started_at": 0,
                }
            },
        }

        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]):
            result = handle_callback("menu:incidents", state, chat_id="chat", user_id="user", message_id=1)

        text = result["text"]
        self.assertIn("1 active health alert(s)", text)
        self.assertIn("[WARN] Proxy Auth Inspection Unavailable", text)

    def test_active_auth_unavailable_remains_visible_during_recovery_grace(self):
        state = {
            "snapshot": {
                "created_at": 1,
                "system_alerts": {},
            },
            "active": {
                "auth:quota-inspection-unavailable": {
                    "severity": "warning",
                    "title": "Proxy auth inspection unavailable",
                    "fingerprint": "unavailable:malformed-payload",
                    "unavailable_first_seen": 100,
                    "unavailable_last_seen": 430,
                    "unavailable_recovery_started_at": 450,
                }
            },
        }

        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]):
            result = handle_callback("menu:incidents", state, chat_id="chat", user_id="user", message_id=1)

        text = result["text"]
        self.assertIn("1 active health alert(s)", text)
        self.assertIn("[WARN] Proxy Auth Inspection Unavailable", text)

    def test_auth_unavailable_clears_from_health_alerts_after_sustained_recovery(self):
        state = {
            "snapshot": {
                "created_at": 1,
                "system_alerts": {},
            },
            "active": {},
        }

        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]):
            result = handle_callback("menu:incidents", state, chat_id="chat", user_id="user", message_id=1)

        text = result["text"]
        self.assertIn("No active health alerts", text)
        self.assertNotIn("Proxy auth inspection unavailable", text)

    def test_reauth_health_alert_still_renders_immediately(self):
        state = {
            "snapshot": {
                "created_at": 1,
                "system_alerts": {
                    "auth:quota-inspection-failed": {
                        "alert_id": "auth:quota-inspection-failed",
                        "severity": "critical",
                        "title": "Proxy accounts need reauth",
                        "body": "1 proxy account needs reauth",
                        "fingerprint": "reauth:acct-a:unauthorized_401",
                    }
                },
            },
            "active": {},
        }

        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]):
            result = handle_callback("menu:incidents", state, chat_id="chat", user_id="user", message_id=1)

        self.assertIn("[CRITICAL] Proxy accounts need reauth", result["text"])

    def test_gpt_pool_health_alert_still_renders_from_snapshot(self):
        state = {
            "snapshot": {
                "created_at": 1,
                "system_alerts": {
                    "capacity:gpt-pool-5h-low": {
                        "alert_id": "capacity:gpt-pool-5h-low",
                        "severity": "warning",
                        "title": "GPT pool 5h capacity low",
                        "body": "5h margin below threshold",
                        "fingerprint": "gpt-pool-5h-low",
                    }
                },
            },
            "active": {},
        }

        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]):
            result = handle_callback("menu:incidents", state, chat_id="chat", user_id="user", message_id=1)

        self.assertIn("[WARN] GPT Pool 5h Capacity Low", result["text"])

    def test_empty_quota_reply_lists_checked_counts(self):
        snapshot = {
            "created_at": snapshot_module.now_ts(),
            "quota_error": "",
            "quota_rows": [
                {
                    "alias": "alice",
                    "status": "active",
                    "daily_used": 100,
                    "daily_limit": 4_000_000,
                    "weekly_used": 100,
                    "weekly_limit": 16_000_000,
                    "effective_percent": 0.01,
                }
            ],
        }

        text = build_quota_reply(snapshot)

        self.assertIn("No quota warnings", text)
        self.assertIn("Disabled by quota: 0", text)
        self.assertIn("Over 85% daily/weekly: 0", text)
        self.assertIn("Missing from proxy config: 0", text)

    def test_weekly_cap_disabled_wording_in_quota_and_usage_displays(self):
        snapshot = {
            "created_at": 0,
            "quota_error": "",
            "quota_rows": [
                {
                    "alias": "alice",
                    "status": "active",
                    "daily_used": 1_000_000,
                    "daily_limit": 4_000_000,
                    "weekly_used": 20_000_000,
                    "weekly_limit": None,
                    "effective_percent": 25.0,
                }
            ],
        }
        quota_text = build_quota_reply(snapshot, all_accounts=True)
        usage_text = build_usage_report(
            {"alias": "alice", "status": "active", "daily": 4_000_000, "weekly": None},
            {"daily": empty_usage_bucket(), "weekly": empty_usage_bucket()},
            "Asia/Ho_Chi_Minh",
        )

        self.assertIn("unlimited", usage_text)
        self.assertNotIn("weekly cap disabled", usage_text)
        self.assertIn("weekly cap disabled", quota_text)
        self.assertNotIn("weekly unlimited", quota_text.lower())

    def test_usage_report_uses_compact_sections_and_model_detail_lines(self):
        daily = empty_usage_bucket()
        daily.update({
            "total_tokens": 112_750_000,
            "requests": 1_176,
            "failed": 26,
            "models": [
                {
                    "model": "gpt-5.5",
                    "total_tokens": 110_300_000,
                    "input_tokens": 109_600_000,
                    "output_tokens": 774_800,
                    "cached_tokens": 94_500_000,
                    "cache_read_tokens": 0,
                    "cache_creation_tokens": 0,
                    "reasoning_tokens": 135_800,
                },
                {
                    "model": "gpt-5.4-mini",
                    "total_tokens": 2_400_000,
                    "input_tokens": 2_352_700,
                    "output_tokens": 47_300,
                    "cached_tokens": 1_200_000,
                    "cache_read_tokens": 0,
                    "cache_creation_tokens": 0,
                    "reasoning_tokens": 4_800,
                },
            ],
        })
        weekly = empty_usage_bucket()
        weekly.update({
            "total_tokens": 293_400_000,
            "requests": 3_902,
            "failed": 108,
            "models": [
                {
                    "model": "gpt-5.5",
                    "total_tokens": 280_700_000,
                    "input_tokens": 279_300_000,
                    "output_tokens": 1_400_000,
                    "cached_tokens": 250_000_000,
                    "cache_read_tokens": 0,
                    "cache_creation_tokens": 0,
                    "reasoning_tokens": 258_400,
                },
                {
                    "model": "gpt-5.4-mini",
                    "total_tokens": 12_700_000,
                    "input_tokens": 12_400_000,
                    "output_tokens": 299_800,
                    "cached_tokens": 7_500_000,
                    "cache_read_tokens": 0,
                    "cache_creation_tokens": 0,
                    "reasoning_tokens": 57_500,
                },
            ],
        })

        text = build_usage_report(
            {"alias": "huynhlehaiduong", "status": "active", "daily": 125_000_000, "weekly": 500_000_000},
            {"daily": daily, "weekly": weekly},
            "Asia/Ho_Chi_Minh",
        )

        expected_order = [
            "Usage: huynhlehaiduong",
            "Status: active",
            "Today",
            "Models today",
            "This week",
            "Models week",
        ]
        last_index = -1
        for marker in expected_order:
            index = text.index(marker)
            self.assertGreater(index, last_index)
            last_index = index
        self.assertIn("- Used: 112.8M / 125.0M (90.2%)", text)
        self.assertIn("- Requests: 1,176, failed: 26", text)
        self.assertIn("- gpt-5.5: 110.3M", text)
        self.assertIn("+ In 109.6M, out 774.8K", text)
        self.assertIn("+ Cache 94.5M, reasoning 135.8K", text)
        self.assertIn("- gpt-5.4-mini: 2.4M", text)
        self.assertIn("+ In 2.4M, out 47.3K", text)
        self.assertIn("+ Cache 1.2M, reasoning 4.8K", text)
        self.assertIn("- Used: 293.4M / 500.0M (58.7%)", text)
        self.assertIn("- Requests: 3,902, failed: 108", text)
        self.assertIn("- gpt-5.5: 280.7M", text)
        self.assertIn("+ In 279.3M, out 1.4M", text)
        self.assertIn("+ Cache 250.0M, reasoning 258.4K", text)
        self.assertIn("- gpt-5.4-mini: 12.7M", text)
        self.assertIn("+ In 12.4M, out 299.8K", text)
        self.assertIn("+ Cache 7.5M, reasoning 57.5K", text)
        self.assertNotIn("Window: Asia/Ho_Chi_Minh", text)
        self.assertNotIn("\nUsed:", text)
        self.assertNotIn("\nRequests:", text)
        self.assertNotIn("in 109.6M, out 774.8K, cache 94.5M, reasoning 135.8K", text)

    def capacity_pool(
        self,
        primary_lowest=60.0,
        secondary_lowest=60.0,
        checked=10,
        enabled=10,
        error="",
        primary_avg=72.7,
        secondary_avg=44.7,
        source="usage_keeper",
    ):
        return {
            "source": source,
            "enabled_codex_count": enabled,
            "primary": {
                "checked_count": checked,
                "avg_left_percent": primary_avg,
                "lowest_left_percent": primary_lowest,
                "left_tokens": round(primary_avg / 100.0 * 20_000_000 * checked, 1),
            },
            "secondary": {
                "checked_count": checked,
                "avg_left_percent": secondary_avg,
                "lowest_left_percent": secondary_lowest,
                "left_tokens": round(secondary_avg / 100.0 * 140_000_000 * checked, 1),
            },
            "error": error,
        }

    def capacity_snapshot(self, pool=None, rows=None, enforcer_age="12s", created_at=None):
        if created_at is None:
            created_at = snapshot_module.now_ts()
        return {
            "created_at": created_at,
            "quota_error": "",
            "enforcer_age": enforcer_age,
            "gpt_pool_capacity": pool if pool is not None else self.capacity_pool(),
            "quota_rows": rows if rows is not None else [
                {
                    "alias": "alice",
                    "status": "active",
                    "daily_used": 2_000_000,
                    "daily_limit": 10_000_000,
                    "weekly_used": 12_000_000,
                    "weekly_limit": 50_000_000,
                    "effective_percent": 24.0,
                },
                {
                    "alias": "bob",
                    "status": "active",
                    "daily_used": 1_000_000,
                    "daily_limit": None,
                    "weekly_used": 5_000_000,
                    "weekly_limit": None,
                    "effective_percent": None,
                },
                {
                    "alias": "erin",
                    "status": "active",
                    "daily_used": 3_000_000,
                    "daily_limit": 9_000_000,
                    "weekly_used": 30_000_000,
                    "weekly_limit": None,
                    "effective_percent": 33.3,
                },
                {
                    "alias": "carol",
                    "status": "disabled",
                    "daily_used": 4_000_000,
                    "daily_limit": 4_000_000,
                    "weekly_used": 16_000_000,
                    "weekly_limit": 16_000_000,
                    "effective_percent": 100.0,
                },
                {
                    "alias": "dave",
                    "status": "missing",
                    "daily_used": 0,
                    "daily_limit": 4_000_000,
                    "weekly_used": 0,
                    "weekly_limit": 16_000_000,
                    "effective_percent": 0.0,
                },
            ],
        }

    def capacity_rate(self, hourly=2_000_000, tokens=6_000_000, error=""):
        return {
            "tokens": tokens,
            "hours": 3.0,
            "tokens_per_hour": hourly,
            "lookback_hours": 3,
            "source": "recent",
            "requests": 7,
            "error": error,
        }

    def test_capacity_refresh_uses_realtime_demand_source_and_suffix(self):
        snapshot = self.capacity_snapshot(rows=self.healthy_user_key_rows())
        rate = {
            "tokens": 26_000_000,
            "requests": 0,
            "hours": 1.0,
            "tokens_per_hour": 26_000_000,
            "lookback_hours": 1.0,
            "source": "usage_keeper_realtime",
            "source_label": "Usage Keeper realtime 60m",
            "display_suffix": "60m realtime",
            "error": "",
        }
        state = {"capacity_check_snapshot": snapshot}

        with mock.patch("telegram_alerts.handlers.get_capacity_check_snapshot", return_value=snapshot), \
             mock.patch("telegram_alerts.handlers.capacity_demand_rate_estimate", return_value=rate), \
             mock.patch.object(snapshot_module, "hours_until_week_end", return_value=100.0):
            result = handle_callback("menu:capacity_refresh", state, chat_id="chat", user_id="user", message_id=1)

        text = result["text"]
        self.assertIn("- Demand rate: 26.0M/h (60m realtime)", text)
        self.assertIn("- 5h demand: 130.0M", text)
        self.assertIn("- Demand source: Usage Keeper realtime 60m.", text)
        self.assertNotIn("- Demand rate: 26.0M/h (3h avg)", text)
        self.assertNotIn("Cliproxy:", text)
        self.assertIn("(avg: ", text)
        self.assertNotIn("Avg:", text)
        self.assertNotIn("User API keys", text)

    def test_capacity_check_local_fallback_keeps_local_suffix_and_source(self):
        snapshot = self.capacity_snapshot(rows=self.healthy_user_key_rows())
        rate = self.capacity_rate(hourly=15_000_000)
        rate["source_label"] = "local usage estimate"

        with mock.patch.object(snapshot_module, "hours_until_week_end", return_value=100.0):
            text = snapshot_module.build_capacity_reply(snapshot, rate)

        self.assertIn("- Demand rate: 15.0M/h (3h avg)", text)
        self.assertIn("- Demand source: local usage estimate.", text)
        self.assertNotIn("60m realtime", text)
        self.assertNotIn("Cliproxy:", text)
        self.assertIn("(avg: ", text)
        self.assertNotIn("Avg:", text)
        self.assertNotIn("User API keys", text)

    def test_capacity_check_uses_short_demand_forecast_labels(self):
        snapshot = self.capacity_snapshot(rows=self.healthy_user_key_rows())
        with mock.patch.object(snapshot_module, "hours_until_week_end", return_value=95.34884):
            text = snapshot_module.build_capacity_reply(snapshot, self.capacity_rate(hourly=43_000_000))

        self.assertIn("Demand Forecast", text)
        self.assertIn("- Demand rate: 43.0M/h (3h avg)", text)
        self.assertIn("- 5h demand: 215.0M", text)
        self.assertIn("- Weekly demand: 4100.0M", text)
        self.assertNotIn("demand rate:", text)
        self.assertNotIn("5-hour demand:", text)
        self.assertNotIn("recent demand rate:", text)
        self.assertNotIn("/hour over last 3h", text)
        self.assertNotIn("Projected 5h demand:", text)
        self.assertNotIn("projected weekly demand:", text)

    def healthy_user_key_rows(self):
        return [
            {
                "name": "healthy",
                "alias": "healthy",
                "masked": "healthy***test",
                "status": "active",
                "daily_used": 1_000_000,
                "daily_limit": 500_000_000,
                "daily_percent": 0.2,
                "weekly_used": 5_000_000,
                "weekly_limit": 5_000_000_000,
                "weekly_percent": 0.1,
                "effective_percent": 1.0,
            }
        ]

    def test_capacity_check_shows_gpt_pool_user_keys_quota_forecast_and_evidence(self):
        snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(primary_lowest=32.0, secondary_lowest=3.0, checked=10, enabled=10),
            enforcer_age="8s",
        )
        rate = self.capacity_rate(hourly=15_000_000)

        self.assertTrue(hasattr(snapshot_module, "build_capacity_reply"))
        with mock.patch.object(snapshot_module, "hours_until_week_end", return_value=100.0):
            text = snapshot_module.build_capacity_reply(snapshot, rate)

        lines = text.splitlines()
        self.assertEqual(lines[0], "Capacity Check")
        self.assertEqual(lines[1], "")
        self.assertIn("Demand Forecast", text)
        self.assertIn("GPT Pool Capacity", text)
        self.assertLess(text.index("Demand Forecast"), text.index("GPT Pool Capacity"))
        self.assertNotIn("Data: cached,", "\n".join(lines[:3]))
        self.assertNotIn("Cliproxy:", text)
        self.assertNotIn("Capacity check: personal-cliproxy", text)
        self.assertNotIn("Demand forecast", text)
        self.assertNotIn("GPT pool capacity", text)
        self.assertIn("- 5h avail: 145.4M\n(avg: 72.7%, lowest: 32%)", text)
        self.assertIn("- Weekly avail: 625.8M\n(avg: 44.7%, lowest: 3%)", text)
        self.assertNotIn("Avg:", text)
        for line in lines:
            if " avail:" in line:
                self.assertNotIn("token-equivalent", line)
                self.assertNotIn("(", line)
            if "avg:" in line:
                self.assertFalse(line.startswith("- "))
        self.assertNotIn("10/10", text)
        self.assertIn("- 5h margin: 1.9x", text)
        self.assertIn("- Weekly margin: 0.4x", text)
        self.assertLess(text.index("- 5h margin: 1.9x"), text.index("User Key Quota (Remaining)"))
        self.assertLess(text.index("- Weekly margin: 0.4x"), text.index("User Key Quota (Remaining)"))
        self.assertNotIn("User API keys", text)
        self.assertNotIn("active keys:", text)
        self.assertNotIn("quota-exhausted keys:", text)
        self.assertNotIn("missing from proxy config:", text)
        self.assertNotIn("weekly cap disabled keys:", text)
        self.assertIn("User Key Quota (Remaining)", text)
        self.assertIn("- Daily: 14.0M / 19.0M (73.7%)", text)
        self.assertIn("- Weekly: 38.0M / 50.0M (76.0%)", text)
        self.assertIn("- Demand rate: 15.0M/h (3h avg)", text)
        self.assertIn("- 5h demand: 75.0M", text)
        self.assertIn("- Weekly demand: 1500.0M", text)
        self.assertNotIn("recent demand rate:", text)
        self.assertNotIn("/hour over last 3h", text)
        self.assertNotIn("Projected 5h demand:", text)
        self.assertNotIn("projected weekly demand:", text)
        self.assertNotIn("Recommendation:", text)
        self.assertIn("Evidence", text)
        self.assertIn("- Data: updated 0s ago.", text)
        self.assertNotIn("snapshot: snapshot", text)
        self.assertNotIn("Data: cached,", text)
        self.assertNotIn("snapshot 0s", text)
        self.assertIn("- Quota sync: updated 8s ago.", text)
        self.assertNotIn("quota enforcer log age", text)
        self.assertIn("- GPT pool uses Usage Keeper quota cache data.", text)
        self.assertNotIn("GPT pool uses complete enabled codex quota-cache coverage only", text)
        self.assertIn("- GPT pool token-equivalent assumes 20M per 5h quota and 140M per weekly quota per codex account.", text)
        self.assertNotIn("User key quota is quota assigned to user API keys, not backend GPT account capacity.", text)
        self.assertNotIn("Accounts", text)
        self.assertNotIn("Remaining quota", text)
        self.assertNotIn("Usage forecast", text)
        self.assertNotIn("finite daily remaining", text)
        self.assertNotIn("finite weekly remaining", text)
        self.assertNotIn("next 5h daily margin", text)

    def test_capacity_check_renders_usable_codex_identity_line_without_reauth_wording(self):
        excluded_pool = self.capacity_pool(checked=6, enabled=6)
        excluded_pool.update({
            "total_enabled_codex_count": 7,
            "excluded_reauth_count": 1,
            "usable_codex_count": 6,
            "debug_identity": "codex-secret@example.com",
            "debug_token": "sk-secret1234567890",
        })
        excluded_snapshot = self.capacity_snapshot(pool=excluded_pool, rows=self.healthy_user_key_rows())
        normal_snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(checked=10, enabled=10),
            rows=self.healthy_user_key_rows(),
        )

        with mock.patch.object(snapshot_module, "hours_until_week_end", return_value=100.0):
            excluded_text = snapshot_module.build_capacity_reply(excluded_snapshot, self.capacity_rate(hourly=1_000_000))
            normal_text = snapshot_module.build_capacity_reply(normal_snapshot, self.capacity_rate(hourly=1_000_000))

        self.assertIn("GPT Pool Capacity\n- Codex identities: 6 usable", excluded_text)
        self.assertNotIn("reauth", excluded_text.lower())
        self.assertNotIn("excluded", excluded_text.lower())
        self.assertNotIn("reauth-disabled", excluded_text.lower())
        self.assertNotIn("10 total, 1 excluded (reauth), 9 usable", excluded_text)
        self.assertLess(excluded_text.index("- Codex identities:"), excluded_text.index("- 5h avail:"))
        self.assertNotIn("Codex identities:", normal_text)
        self.assertNotIn("codex-secret@example.com", excluded_text)
        self.assertNotIn("sk-secret", excluded_text)
        self.assertIn("- GPT pool uses Usage Keeper quota cache data.", excluded_text)

    def test_capacity_check_renders_free_codex_count_as_non_usable_without_updating_fallback(self):
        pool = self.capacity_pool(checked=4, enabled=4, primary_avg=80.0, secondary_avg=70.0)
        pool.update({
            "usable_codex_count": 4,
            "free_codex_count": 1,
            "total_enabled_codex_count": 5,
        })
        snapshot = self.capacity_snapshot(pool=pool, rows=self.healthy_user_key_rows())

        with mock.patch.object(snapshot_module, "hours_until_week_end", return_value=100.0):
            text = snapshot_module.build_capacity_reply(snapshot, self.capacity_rate(hourly=1_000_000))

        self.assertIn("GPT Pool Capacity\n- Codex identities: 4 usable, 1 free", text)
        self.assertIn("- 5h avail: 64.0M", text)
        self.assertIn("- Weekly avail: 392.0M", text)
        self.assertIn("- 5h margin: 12.8x", text)
        self.assertNotIn("Quota data updating", text)
        self.assertNotIn("4/5 with weekly data", text)

    def test_capacity_check_renders_free_count_but_not_reauth_count(self):
        pool = self.capacity_pool(checked=4, enabled=4, primary_avg=80.0, secondary_avg=70.0)
        pool.update({
            "usable_codex_count": 4,
            "free_codex_count": 1,
            "excluded_reauth_count": 1,
            "total_enabled_codex_count": 6,
        })
        snapshot = self.capacity_snapshot(pool=pool, rows=self.healthy_user_key_rows())

        with mock.patch.object(snapshot_module, "hours_until_week_end", return_value=100.0):
            text = snapshot_module.build_capacity_reply(snapshot, self.capacity_rate(hourly=1_000_000))

        self.assertIn("GPT Pool Capacity\n- Codex identities: 4 usable, 1 free", text)
        self.assertNotIn("reauth", text.lower())
        self.assertNotIn("excluded", text.lower())
        self.assertLess(text.index("- Codex identities:"), text.index("- 5h avail:"))

    def test_capacity_gpt_pool_unavailable_renders_unavailable_and_recommends_watch(self):
        snapshot = self.capacity_snapshot(
            pool={
                "enabled_codex_count": 2,
                "primary": {"checked_count": 0, "avg_left_percent": None, "lowest_left_percent": None},
                "secondary": {"checked_count": 0, "avg_left_percent": None, "lowest_left_percent": None},
                "error": "quota cache unavailable for sk-secret-like-auth@example.com",
            },
            rows=self.healthy_user_key_rows(),
        )

        text = snapshot_module.build_capacity_reply(snapshot, self.capacity_rate(hourly=1_000_000))

        self.assertIn("5h avail: unavailable", text)
        self.assertIn("Weekly avail: unavailable", text)
        self.assertNotIn("Recommendation:", text)
        self.assertNotIn("sk-secret-like", text)
        self.assertNotIn("@example.com", text)

    def test_capacity_runtime_schema_renders_values_without_identity_leak(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "identities": [
                        {
                            "identity": "codex-runtime-secret@example.com",
                            "type": "codex",
                            "disabled": False,
                            "is_deleted": False,
                            "auth_type": 1,
                        },
                        {
                            "identity": "codex-runtime-2",
                            "type": "codex",
                            "disabled": False,
                            "is_deleted": False,
                            "auth_type": 1,
                        },
                        {
                            "identity": "antigravity-runtime-file.json",
                            "type": "antigravity",
                            "disabled": False,
                            "is_deleted": False,
                            "auth_type": 1,
                        },
                    ]
                }, ""
            if path == "quota/cache":
                return 200, {
                    "items": [
                        {
                            "auth_index": "codex-runtime-secret@example.com",
                            "status": "completed",
                            "quota": {
                                "quota": [
                                    {"key": "rate_limit.primary_window", "label": "5h", "usedPercent": 10},
                                    {"key": "rate_limit.secondary_window", "label": "Weekly", "usedPercent": 50},
                                ]
                            },
                        },
                        {
                            "auth_index": "codex-runtime-2",
                            "status": "completed",
                            "quota": {
                                "quota": [
                                    {"key": "rate_limit.primary_window", "label": "5h", "usedPercent": 30},
                                    {"key": "rate_limit.secondary_window", "label": "Weekly", "usedPercent": 70},
                                ]
                            },
                        },
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({}, auth_observation(healthy=["acct-ok"]))), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value={"items": []}), \
             mock.patch("telegram_alerts.snapshot.quota_alerts_from_context", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.quota_rows_from_context", return_value=self.healthy_user_key_rows()), \
             mock.patch("telegram_alerts.snapshot.hours_until_week_end", return_value=120.0):
            built = snapshot_module.build_snapshot(interactive=True)

        with mock.patch("telegram_alerts.snapshot.hours_until_week_end", return_value=120.0):
            text = snapshot_module.build_capacity_reply(built, self.capacity_rate(hourly=1_000_000))

        self.assertIn("5h avail: 32.0M\n(avg: 80.0%, lowest: 70%)", text)
        self.assertIn("Weekly avail: 112.0M\n(avg: 40.0%, lowest: 30%)", text)
        self.assertNotIn("2/2", text)
        self.assertIn("5h margin: 6.4x", text)
        self.assertIn("Weekly margin: 0.9x", text)
        self.assertNotIn("5h avail: unavailable", text)
        self.assertNotIn("Weekly avail: unavailable", text)
        self.assertNotIn("codex-runtime-secret", text)
        self.assertNotIn("@example.com", text)
        self.assertNotIn("antigravity-runtime-file.json", text)

    def test_capacity_check_uses_identity_values_for_quota_cache_coverage(self):
        identity_values = [f"quota-cache-row-{idx}" for idx in range(1, 10)]
        id_values = [f"internal-row-{idx}" for idx in range(1, 10)]

        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "items": [
                        {"id": id_value, "identity": identity_value, "type": "codex", "disabled": False}
                        for id_value, identity_value in zip(id_values, identity_values)
                    ]
                }, ""
            if path == "quota/cache":
                if payload != {"auth_indexes": identity_values}:
                    return 200, {"items": []}, ""
                return 200, {
                    "items": [
                        {
                            "id": id_value,
                            "identity": identity_value,
                            "quotas": [
                                {"key": "rate_limit.primary_window", "usedPercent": 20},
                                {"key": "rate_limit.secondary_window", "usedPercent": 30},
                            ],
                        }
                        for id_value, identity_value in zip(id_values[:8], identity_values[:8])
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({}, auth_observation(healthy=["acct-ok"]))), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value={"items": []}), \
             mock.patch("telegram_alerts.snapshot.quota_alerts_from_context", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.quota_rows_from_context", return_value=self.healthy_user_key_rows()):
            built = snapshot_module.build_snapshot(interactive=True, gpt_pool_management_fallback=False)

        text = snapshot_module.build_capacity_reply(built, self.capacity_rate(hourly=1_000_000))

        self.assertIn("Quota data updating: 8/9 with 5h data, 8/9 with weekly data", text)
        self.assertNotIn("Quota data updating: 0/9", text)
        self.assertNotIn("internal-row-", text)
        self.assertNotIn("quota-cache-row-", text)

    def test_capacity_check_counts_team_plan_as_usable_not_free(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [{"identity": "team-quota-cache-id", "type": "codex", "disabled": False}]}, ""
            if path == "quota/cache":
                self.assertEqual(payload, {"auth_indexes": ["team-quota-cache-id"]})
                return 200, {"items": [{
                    "identity": "team-quota-cache-id",
                    "quotas": [
                        {"key": "rate_limit.primary_window", "planType": "team", "window": {"seconds": 18000}, "usedPercent": 10},
                        {"key": "rate_limit.secondary_window", "planType": "team", "window": {"seconds": 604800}, "usedPercent": 20},
                    ],
                }]}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({}, auth_observation(healthy=["acct-ok"]))), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value={"items": []}), \
             mock.patch("telegram_alerts.snapshot.quota_alerts_from_context", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.quota_rows_from_context", return_value=self.healthy_user_key_rows()):
            built = snapshot_module.build_snapshot(interactive=True, gpt_pool_management_fallback=False)

        with mock.patch.object(snapshot_module, "hours_until_week_end", return_value=120.0):
            text = snapshot_module.build_capacity_reply(built, self.capacity_rate(hourly=1_000_000))

        self.assertIn("GPT Pool Capacity", text)
        self.assertNotIn("Codex identities:", text)
        self.assertNotIn("free", text.lower())
        self.assertNotIn("Quota data updating", text)
        self.assertIn("5h avail: 18.0M", text)
        self.assertIn("Weekly avail: 112.0M", text)
        self.assertNotIn("team-quota-cache-id", text)

    def test_capacity_check_counts_edu_plan_as_usable_not_free(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [{"identity": "edu-quota-cache-id", "type": "codex", "disabled": False}]}, ""
            if path == "quota/cache":
                self.assertEqual(payload, {"auth_indexes": ["edu-quota-cache-id"]})
                return 200, {"items": [{
                    "identity": "edu-quota-cache-id",
                    "quotas": [
                        {"key": "rate_limit.primary_window", "planType": "edu", "window": {"seconds": 18000}, "usedPercent": 0},
                        {"key": "rate_limit.secondary_window", "planType": "edu", "window": {"seconds": 604800}, "usedPercent": 0},
                    ],
                }]}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({}, auth_observation(healthy=["acct-ok"]))), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value={"items": []}), \
             mock.patch("telegram_alerts.snapshot.quota_alerts_from_context", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.quota_rows_from_context", return_value=self.healthy_user_key_rows()):
            built = snapshot_module.build_snapshot(interactive=True, gpt_pool_management_fallback=False)

        with mock.patch.object(snapshot_module, "hours_until_week_end", return_value=120.0):
            text = snapshot_module.build_capacity_reply(built, self.capacity_rate(hourly=1_000_000))

        self.assertIn("GPT Pool Capacity", text)
        self.assertNotIn("Codex identities:", text)
        self.assertNotIn("free", text.lower())
        self.assertNotIn("Quota data updating", text)
        self.assertIn("5h avail: 20.0M", text)
        self.assertIn("Weekly avail: 140.0M", text)
        self.assertNotIn("edu-quota-cache-id", text)

    def test_capacity_check_mixed_plus_team_and_true_free_renders_only_true_free(self):
        identities = [f"compat-quota-cache-{idx}" for idx in range(1, 9)] + ["true-free-quota-cache"]

        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [{"identity": identity, "type": "codex", "disabled": False} for identity in identities]}, ""
            if path == "quota/cache":
                self.assertEqual(payload, {"auth_indexes": identities})
                compat_items = []
                for idx, identity in enumerate(identities[:8], start=1):
                    plan = "team" if idx % 2 == 0 else "plus"
                    compat_items.append({
                        "identity": identity,
                        "quotas": [
                            {"key": "rate_limit.primary_window", "planType": plan, "window": {"seconds": 18000}, "usedPercent": 20},
                            {"key": "rate_limit.secondary_window", "planType": plan, "window": {"seconds": 604800}, "usedPercent": 30},
                        ],
                    })
                return 200, {"items": [
                    *compat_items,
                    {
                        "identity": "true-free-quota-cache",
                        "quotas": [
                            {"key": "rate_limit.primary_window", "planType": "free", "window": {"seconds": 2592000}, "usedPercent": 5},
                        ],
                    },
                ]}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({}, auth_observation(healthy=["acct-ok"]))), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value={"items": []}), \
             mock.patch("telegram_alerts.snapshot.quota_alerts_from_context", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.quota_rows_from_context", return_value=self.healthy_user_key_rows()):
            built = snapshot_module.build_snapshot(interactive=True, gpt_pool_management_fallback=False)

        with mock.patch.object(snapshot_module, "hours_until_week_end", return_value=120.0):
            text = snapshot_module.build_capacity_reply(built, self.capacity_rate(hourly=1_000_000))

        self.assertIn("GPT Pool Capacity\n- Codex identities: 8 usable, 1 free", text)
        self.assertIn("5h avail: 128.0M", text)
        self.assertIn("Weekly avail: 784.0M", text)
        self.assertNotIn("Quota data updating", text)
        self.assertNotIn("compat-quota-cache-", text)
        self.assertNotIn("true-free-quota-cache", text)

    def test_capacity_incomplete_gpt_pool_coverage_renders_updating_and_refresh_recommendation(self):
        snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(primary_lowest=32.0, secondary_lowest=3.0, checked=7, enabled=10),
            rows=self.healthy_user_key_rows(),
        )

        text = snapshot_module.build_capacity_reply(snapshot, self.capacity_rate(hourly=1_000_000))

        self.assertIn("Quota data updating: 7/10 with 5h data, 7/10 with weekly data", text)
        self.assertIn("Tap Refresh after quota cache finishes updating", text)
        self.assertNotIn("5h margin:", text)
        self.assertNotIn("Weekly margin:", text)
        self.assertNotIn("Recommendation:", text)

    def test_capacity_evidence_shows_management_quota_fallback_source_without_secrets(self):
        snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(source="management_fallback"),
            rows=self.healthy_user_key_rows(),
        )
        snapshot["gpt_pool_capacity"]["debug_identity"] = "codex-secret@example.com"
        snapshot["gpt_pool_capacity"]["debug_token"] = "sk-secret1234567890"

        text = snapshot_module.build_capacity_reply(snapshot, self.capacity_rate(hourly=1_000_000))

        self.assertIn("GPT pool uses management quota fallback data.", text)
        self.assertNotIn("GPT pool uses Usage Keeper quota cache data.", text)
        self.assertNotIn("codex-secret@example.com", text)
        self.assertNotIn("sk-secret", text)

    def test_capacity_no_checked_codex_quota_rows_recommends_refresh_quota_data(self):
        snapshot = self.capacity_snapshot(
            pool={
                "enabled_codex_count": 2,
                "primary": {"checked_count": 0, "avg_left_percent": None, "lowest_left_percent": None, "left_tokens": 0.0},
                "secondary": {"checked_count": 0, "avg_left_percent": None, "lowest_left_percent": None, "left_tokens": 0.0},
                "error": "",
            },
            rows=self.healthy_user_key_rows(),
        )

        text = snapshot_module.build_capacity_reply(snapshot, self.capacity_rate(hourly=1_000_000))

        self.assertIn("Quota data updating: 0/2 with 5h data, 0/2 with weekly data", text)
        self.assertNotIn("5h margin:", text)
        self.assertNotIn("Weekly margin:", text)
        self.assertNotIn("Recommendation:", text)

    def test_capacity_no_longer_exposes_recommendation_backend_or_text(self):
        snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(primary_avg=36.0, primary_lowest=32.0, secondary_avg=60.0, secondary_lowest=50.0),
            rows=self.healthy_user_key_rows(),
        )

        text = snapshot_module.build_capacity_reply(snapshot, self.capacity_rate(hourly=20_000_000))

        self.assertIn("5h margin: 0.7x", text)
        self.assertIn("Weekly margin:", text)
        self.assertNotIn("Recommendation:", text)
        self.assertFalse(hasattr(snapshot_module, "capacity_recommendation"))

    def test_key_status_weekly_cap_disabled_line_splits_active_and_disabled(self):
        rows = [
            {"alias": "active-weekly-off-1", "status": "active", "daily_used": 1, "daily_limit": 100, "weekly_used": 1, "weekly_limit": None, "effective_percent": 1.0},
            {"alias": "active-weekly-off-2", "status": "active", "daily_used": 1, "daily_limit": 100, "weekly_used": 1, "weekly_limit": None, "effective_percent": 1.0},
            {"alias": "disabled-weekly-off", "status": "disabled", "daily_used": 100, "daily_limit": 100, "weekly_used": 1, "weekly_limit": None, "effective_percent": 100.0},
            {"alias": "missing-weekly-off", "status": "missing", "daily_used": 0, "daily_limit": 100, "weekly_used": 0, "weekly_limit": None, "effective_percent": 0.0},
            {"alias": "active-weekly-on", "status": "active", "daily_used": 1, "daily_limit": 100, "weekly_used": 1, "weekly_limit": 100, "effective_percent": 1.0},
        ]
        snapshot = self.capacity_snapshot(rows=rows)

        text = snapshot_module.build_key_status_reply(snapshot)

        self.assertIn("Uncapped weekly: 2 active, 1 disabled", text)
        self.assertNotIn("No weekly cap", text)
        self.assertNotIn("weekly cap disabled keys", text)
        self.assertNotIn("quota-exhausted", text)
        self.assertIn("- disabled-weekly-off (quota exceeded)", text)
        self.assertNotIn("+ Daily quota:", text)
        self.assertNotIn("+ Weekly quota:", text)
        self.assertNotIn("missing-weekly-off", text)

    def test_capacity_low_5h_margin_creates_sanitized_warning_alert(self):
        snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(primary_avg=20.0, primary_lowest=10.0, secondary_avg=5.0, secondary_lowest=1.0, enabled=10, checked=10),
            rows=self.healthy_user_key_rows(),
        )

        alert = snapshot_module.gpt_pool_5h_low_capacity_alert(snapshot, self.capacity_rate(hourly=15_000_000))

        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_id, "capacity:gpt-pool-5h-low")
        self.assertEqual(alert.severity, "warning")
        self.assertEqual(alert.title, "GPT pool 5h capacity low")
        self.assertEqual(alert.fingerprint, "low-0.5-to-0.8:10")
        text = build_alert_message(alert)
        self.assertEqual(
            text,
            "[WARN] GPT pool 5h capacity low\n\n"
            "Evidence:\n"
            "- 5h pool left: 40.0M token-equivalent\n"
            "- 5h demand: 75.0M\n"
            "- 5h margin: 0.5x\n"
            "- Codex quota coverage: 10/10\n\n"
            "Action:\n"
            "Add more codex/GPT accounts or reduce demand.",
        )
        self.assertNotIn("Impact:", text)
        self.assertNotIn("Projected 5h demand", text)
        self.assertNotIn("weekly margin", text.lower())
        self.assertNotIn("---", text)
        self.assertNotIn("@example.com", text)
        self.assertNotIn("sk-", text)
        self.assertNotIn("auth_index", text)

    def test_capacity_low_5h_alert_uses_coarse_fingerprint_buckets(self):
        low_snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(primary_avg=21.0, primary_lowest=10.0, enabled=10, checked=10),
            rows=self.healthy_user_key_rows(),
        )
        slightly_lower_snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(primary_avg=19.0, primary_lowest=10.0, enabled=10, checked=10),
            rows=self.healthy_user_key_rows(),
        )
        critical_snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(primary_avg=10.0, primary_lowest=5.0, enabled=10, checked=10),
            rows=self.healthy_user_key_rows(),
        )

        first = snapshot_module.gpt_pool_5h_low_capacity_alert(low_snapshot, self.capacity_rate(hourly=15_000_000))
        second = snapshot_module.gpt_pool_5h_low_capacity_alert(slightly_lower_snapshot, self.capacity_rate(hourly=15_000_000))
        critical = snapshot_module.gpt_pool_5h_low_capacity_alert(critical_snapshot, self.capacity_rate(hourly=15_000_000))

        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.fingerprint, "low-0.5-to-0.8:10")
        self.assertEqual(critical.fingerprint, "critical-under-0.5:10")

    def test_capacity_incomplete_coverage_or_unavailable_demand_creates_no_low_5h_alert(self):
        incomplete = self.capacity_snapshot(
            pool=self.capacity_pool(primary_avg=20.0, primary_lowest=10.0, enabled=10, checked=7),
            rows=self.healthy_user_key_rows(),
        )
        unavailable_demand = self.capacity_snapshot(
            pool=self.capacity_pool(primary_avg=20.0, primary_lowest=10.0, enabled=10, checked=10),
            rows=self.healthy_user_key_rows(),
        )

        self.assertIsNone(snapshot_module.gpt_pool_5h_low_capacity_alert(incomplete, self.capacity_rate(hourly=15_000_000)))
        self.assertIsNone(snapshot_module.gpt_pool_5h_low_capacity_alert(unavailable_demand, self.capacity_rate(hourly=15_000_000, error="usage unavailable")))

    def test_capacity_5h_margin_at_alert_threshold_creates_no_low_5h_alert(self):
        snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(primary_avg=30.0, primary_lowest=20.0, enabled=10, checked=10),
            rows=self.healthy_user_key_rows(),
        )

        alert = snapshot_module.gpt_pool_5h_low_capacity_alert(snapshot, self.capacity_rate(hourly=15_000_000))

        self.assertIsNone(alert)

    def test_build_snapshot_includes_low_5h_capacity_alert_in_system_alerts(self):
        pool = self.capacity_pool(primary_avg=20.0, primary_lowest=10.0, enabled=10, checked=10)
        with mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({}, auth_observation(healthy=["acct-ok"]))), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value={}), \
             mock.patch("telegram_alerts.snapshot.quota_alerts_from_context", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.quota_rows_from_context", return_value=self.healthy_user_key_rows()), \
             mock.patch("telegram_alerts.snapshot.gpt_pool_capacity_snapshot", return_value=pool), \
             mock.patch("telegram_alerts.snapshot.usage_rate_estimate", return_value=self.capacity_rate(hourly=15_000_000)):
            built = snapshot_module.build_snapshot(interactive=True)

        self.assertIn("capacity:gpt-pool-5h-low", built["system_alerts"])
        self.assertEqual(built["system_alerts"]["capacity:gpt-pool-5h-low"]["severity"], "warning")

    def test_top_users_reply_uses_standard_header_and_data_line(self):
        snapshot = {
            "created_at": 100,
            "quota_error": "",
            "quota_rows": [
                {
                    "alias": "alice",
                    "status": "active",
                    "daily_used": 1_000_000,
                    "daily_limit": 10_000_000,
                }
            ],
        }

        with mock.patch.object(snapshot_module, "now_ts", return_value=100):
            text = snapshot_module.build_top_reply(snapshot)

        lines = text.splitlines()
        self.assertEqual(lines[0], "Top Users")
        self.assertIn("Data: updated 0s ago", lines[1])
        self.assertNotIn("Data: snapshot", lines[1])
        self.assertNotIn("personal-cliproxy top token users today", text)

    def test_top_users_callback_uses_simple_refresh_keyboard_layout(self):
        state = {"snapshot": {"created_at": 1, "quota_error": "", "quota_rows": []}}
        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]):
            result = handle_callback("menu:top", state, chat_id="chat", user_id="user", message_id=1)

        self.assertTrue(result["edit_message"])
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Menu", "Usage"], ["Refresh"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["menu:back", "menu:usage"], ["menu:top_refresh"]])

    def test_top_users_refresh_uses_narrow_quota_rows_snapshot(self):
        snapshot = {
            "created_at": 100,
            "quota_error": "",
            "quota_rows": [{
                "alias": "alice",
                "status": "active",
                "daily_used": 10,
                "daily_limit": 100,
            }],
        }
        with mock.patch("telegram_alerts.handlers.get_snapshot", side_effect=AssertionError("full snapshot should not refresh top users")), \
             mock.patch("telegram_alerts.handlers.build_quota_rows_snapshot", return_value=snapshot, create=True) as narrow:
            result = handle_callback("menu:top_refresh", {}, chat_id="chat", user_id="user", message_id=1)

        narrow.assert_called_once()
        self.assertEqual(result["text"], snapshot_module.build_top_reply(snapshot))
        self.assertEqual(result["reply_markup"], top_users_keyboard())
        self.assertTrue(result["edit_message"])

    def test_key_status_refresh_uses_narrow_quota_rows_snapshot(self):
        snapshot = {
            "created_at": 100,
            "quota_error": "",
            "quota_rows": [
                {"alias": "alice", "name": "alice", "status": "active", "daily_used": 0, "daily_limit": 100, "weekly_used": 0, "weekly_limit": 400},
                {"alias": "bob", "name": "bob", "status": "disabled", "daily_used": 100, "daily_limit": 100, "weekly_used": 400, "weekly_limit": 400},
            ],
        }
        with mock.patch("telegram_alerts.handlers.get_snapshot", side_effect=AssertionError("full snapshot should not refresh key status")), \
             mock.patch("telegram_alerts.handlers.build_quota_rows_snapshot", return_value=snapshot, create=True) as narrow:
            result = handle_callback("menu:key_status_refresh", {}, chat_id="chat", user_id="user", message_id=1)

        narrow.assert_called_once()
        self.assertEqual(result["text"], snapshot_module.build_key_status_reply(snapshot))
        self.assertTrue(result["edit_message"])

    def test_incidents_refresh_uses_narrow_health_alerts_snapshot(self):
        snapshot = {"created_at": 100, "system_alerts": {}}
        with mock.patch("telegram_alerts.handlers.get_snapshot", side_effect=AssertionError("full snapshot should not refresh incidents")), \
             mock.patch("telegram_alerts.handlers.build_health_alerts_snapshot", return_value=snapshot, create=True) as narrow:
            result = handle_callback("menu:incidents_refresh", {}, chat_id="chat", user_id="user", message_id=1)

        narrow.assert_called_once_with(interactive=True, auth_inspection_state=None)
        self.assertEqual(result["text"], build_alerts_reply(snapshot))
        self.assertTrue(result["edit_message"])

    def test_usage_route_still_works_from_top_users_button(self):
        state = {}
        with mock.patch("telegram_alerts.handlers.prompt_usage_picker", return_value={"text": "Usage picker"}) as picker:
            result = handle_callback("menu:usage", state, chat_id="chat", user_id="user", message_id=1)

        self.assertTrue(result["edit_message"])
        self.assertEqual(result["text"], "Usage picker")
        picker.assert_called_once()

    def test_errors_normal_tap_reuses_fresh_cache_and_refresh_rebuilds(self):
        state = {
            "errors_reply_cache": {
                "all": {"created_at": 1_000, "text": "Errors Today\ncached"},
            }
        }

        with mock.patch("telegram_alerts.handlers.now_ts", return_value=1_030), \
             mock.patch("telegram_alerts.handlers.build_errors_reply", return_value="Errors Today\nlive") as build:
            cached = handle_callback("menu:errors", state, chat_id="chat", user_id="user", message_id=1)
            refreshed = handle_callback("menu:errors_refresh", state, chat_id="chat", user_id="user", message_id=1)

        self.assertEqual(cached["text"], "Errors Today\ncached")
        self.assertEqual(refreshed["text"], "Errors Today\nlive")
        build.assert_called_once_with("all")
        self.assertEqual(state["errors_reply_cache"]["all"]["text"], "Errors Today\nlive")

    def test_menu_prewarms_capacity_snapshot_from_overview_snapshot_without_parsing_errors(self):
        overview_snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(checked=10, enabled=10),
            rows=self.healthy_user_key_rows(),
            created_at=1_000,
        )
        state = {}

        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=overview_snapshot), \
             mock.patch("telegram_alerts.handlers.build_errors_reply", side_effect=AssertionError("menu should not parse errors synchronously")):
            result = build_menu_reply(state)

        self.assertEqual(result["text"].splitlines()[0], "System Overview")
        self.assertEqual(state["capacity_check_snapshot"]["created_at"], overview_snapshot["created_at"])
        self.assertEqual(state["capacity_check_snapshot"]["quota_rows"], overview_snapshot["quota_rows"])
        self.assertEqual(state["capacity_check_snapshot"]["gpt_pool_capacity"], overview_snapshot["gpt_pool_capacity"])
        self.assertNotIn("errors_reply_cache", state)

    def test_background_prewarm_can_fill_errors_reply_cache(self):
        snapshot = self.capacity_snapshot(
            pool=self.capacity_pool(checked=10, enabled=10),
            rows=self.healthy_user_key_rows(),
            created_at=1_000,
        )
        state = {}

        with mock.patch("telegram_alerts.handlers.now_ts", return_value=1_005), \
             mock.patch("telegram_alerts.handlers.build_errors_reply", return_value="Errors Today\ncached") as build_errors:
            handlers_module.prewarm_menu_fast_caches(state, snapshot, include_errors=True)

        build_errors.assert_called_once_with("all")
        self.assertEqual(state["errors_reply_cache"]["all"], {"created_at": 1_005, "text": "Errors Today\ncached"})
        self.assertEqual(state["errors_reply_cache"]["all"]["text"], "Errors Today\ncached")

    def test_menu_keeps_fresh_capacity_snapshot_when_overview_opens(self):
        cached_capacity = self.capacity_snapshot(
            pool=self.capacity_pool(checked=10, enabled=10),
            rows=self.healthy_user_key_rows(),
            created_at=1_050,
        )
        older_overview = self.capacity_snapshot(
            pool=self.capacity_pool(checked=9, enabled=10),
            rows=self.healthy_user_key_rows(),
            created_at=1_000,
        )
        state = {"capacity_check_snapshot": cached_capacity}

        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=older_overview), \
             mock.patch("telegram_alerts.handlers.now_ts", return_value=1_060), \
             mock.patch("telegram_alerts.handlers.build_errors_reply", return_value="Errors Today\ncached"):
            build_menu_reply(state)

        self.assertIs(state["capacity_check_snapshot"], cached_capacity)

    def test_quota_refresh_uses_narrow_quota_rows_snapshot(self):
        snapshot = {
            "created_at": 100,
            "quota_error": "",
            "quota_rows": [{
                "alias": "alice",
                "status": "disabled",
                "daily_used": 100,
                "daily_limit": 100,
                "weekly_used": 400,
                "weekly_limit": 400,
                "effective_percent": 100.0,
            }],
        }
        with mock.patch("telegram_alerts.handlers.get_snapshot", side_effect=AssertionError("full snapshot should not refresh quota")), \
             mock.patch("telegram_alerts.handlers.build_quota_rows_snapshot", return_value=snapshot, create=True) as narrow:
            result = handle_callback("menu:quota_refresh", {}, chat_id="chat", user_id="user", message_id=1)

        narrow.assert_called_once()
        self.assertEqual(result["text"], build_quota_reply(snapshot))
        self.assertTrue(result["edit_message"])

    def test_quota_management_callback_uses_refresh_menu_keyboard(self):
        state = {"snapshot": {"created_at": 1}}
        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]), \
             mock.patch("telegram_alerts.handlers.get_quota_management_snapshot", return_value=state["snapshot"], create=True), \
             mock.patch("telegram_alerts.handlers.build_quota_management_reply", return_value="Quota Management"):
            result = handle_callback("menu:quota_management", state, chat_id="chat", user_id="user", message_id=1)

        self.assertTrue(result["edit_message"])
        self.assertEqual(result["text"], "Quota Management")
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Menu", "Refresh"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["menu:back", "menu:quota_management_refresh"]])

    def test_quota_management_callbacks_use_cached_and_live_cache_paths(self):
        state = {"snapshot": {"created_at": 1}}
        cached_snapshot = {"created_at": 100, "quota_management_rows": [], "quota_management_quota_by_ref": {}}
        live_snapshot = {"created_at": 101, "quota_management_rows": [], "quota_management_quota_by_ref": {}}
        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]) as general_snapshot, \
             mock.patch("telegram_alerts.handlers.get_quota_management_snapshot", side_effect=[cached_snapshot, live_snapshot], create=True) as quota_snapshot, \
             mock.patch("telegram_alerts.handlers.build_quota_management_reply", side_effect=["cached", "live"]) as render:
            cached_result = handle_callback("menu:quota_management", state, chat_id="chat", user_id="user", message_id=1)
            live_result = handle_callback("menu:quota_management_refresh", state, chat_id="chat", user_id="user", message_id=1)

        self.assertEqual(cached_result["text"], "cached")
        self.assertEqual(live_result["text"], "live")
        quota_snapshot.assert_has_calls([mock.call(state, live=False), mock.call(state, live=True)])
        render.assert_has_calls([mock.call(cached_snapshot), mock.call(live_snapshot)])
        general_snapshot.assert_not_called()

    def test_quota_management_snapshot_reuses_fresh_cache(self):
        cached_snapshot = {
            "created_at": 100,
            "quota_management_rows": [],
            "quota_management_quota_by_ref": {},
        }
        state = {"quota_management_snapshot": cached_snapshot}

        with mock.patch.object(snapshot_module, "now_ts", return_value=159), \
             mock.patch.object(snapshot_module, "build_quota_management_snapshot", return_value={"created_at": 159}, create=True) as build:
            snapshot = snapshot_module.get_quota_management_snapshot(state, live=False)

        self.assertIs(snapshot, cached_snapshot)
        build.assert_not_called()

    def test_quota_management_snapshot_refreshes_stale_cache(self):
        old_snapshot = {
            "created_at": 100,
            "quota_management_rows": [],
            "quota_management_quota_by_ref": {},
        }
        new_snapshot = {
            "created_at": 161,
            "quota_management_rows": [],
            "quota_management_quota_by_ref": {},
        }
        state = {"quota_management_snapshot": old_snapshot}

        with mock.patch.object(snapshot_module, "now_ts", return_value=161), \
             mock.patch.object(snapshot_module, "build_quota_management_snapshot", return_value=new_snapshot, create=True) as build:
            snapshot = snapshot_module.get_quota_management_snapshot(state, live=False)

        self.assertIs(snapshot, new_snapshot)
        self.assertIs(state["quota_management_snapshot"], new_snapshot)
        build.assert_called_once()

    def test_quota_management_reply_uses_cached_rows_without_live_lookup(self):
        snapshot = {
            "created_at": 100,
            "quota_management_rows": [
                {
                    "ref": "acct-1",
                    "label": "acct-1",
                    "status": "enabled",
                    "primary": 100.0,
                    "secondary": 88.0,
                },
                {
                    "ref": "acct-2",
                    "label": "acct-2",
                    "status": "disabled",
                },
            ],
            "quota_management_quota_by_ref": {},
        }

        with mock.patch.object(snapshot_module, "now_ts", return_value=100), \
             mock.patch.object(snapshot_module, "auth_management_quota_left_by_ref") as live_lookup:
            text = build_quota_management_reply(snapshot)

        live_lookup.assert_not_called()
        self.assertIn("Quota Management", text)
        self.assertIn("Data: updated 0s ago", text)
        self.assertIn("1. acct-1", text)
        self.assertIn("(5h avail: 100%, weekly avail: 88%)", text)
        self.assertIn("Disabled Auth Accounts", text)

    def test_quota_management_live_lookup_only_uses_management_for_missing_rows(self):
        rows = [
            {"ref": "acct-1", "status": "enabled", "auth_index": "idx-1"},
            {"ref": "acct-2", "status": "enabled", "auth_index": "idx-2"},
            {"ref": "acct-3", "status": "disabled", "auth_index": "idx-3"},
        ]

        def fake_quota_for_index(auth_index):
            self.assertEqual(auth_index, "idx-2")
            return {"primary": 44.0, "secondary": 55.0}

        with mock.patch.object(snapshot_module, "usage_keeper_auth_quota_left_by_ref", return_value={"acct-1": {"primary": 99.0}}), \
             mock.patch.object(snapshot_module, "auth_quota_left_for_index", side_effect=fake_quota_for_index) as fallback, \
             mock.patch.object(snapshot_module, "management_request", side_effect=AssertionError("auth-files fallback should not run")):
            values = snapshot_module.auth_management_quota_left_by_ref(rows)

        self.assertEqual(values["acct-1"], {"primary": 99.0})
        self.assertEqual(values["acct-2"], {"primary": 44.0, "secondary": 55.0})
        self.assertNotIn("acct-3", values)
        fallback.assert_called_once_with("idx-2")

    def test_quota_management_lists_all_enabled_and_disabled_auth_accounts_with_quota(self):
        def fake_usage_keeper_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "identities": [
                        {"identity": "codex-account-a@example.com-plus.json", "type": "codex", "disabled": False, "auth_type": 1},
                        {"identity": "codex-quota-primary@example.com-plus.json", "type": "codex", "disabled": False, "auth_type": 1},
                        *[
                            {"identity": f"codex-quota-a{idx}@example.com-plus.json", "type": "codex", "disabled": False, "auth_type": 1}
                            for idx in range(9)
                        ],
                    ]
                }, ""
            if path == "quota/cache":
                return 200, {
                    "items": [
                        {
                            "auth_index": auth_index,
                            "quota": {
                                "quota": [
                                    {"key": "rate_limit.primary_window", "usedPercent": 0},
                                    {"key": "rate_limit.secondary_window", "usedPercent": 0},
                                ]
                            },
                        }
                        for auth_index in payload["auth_indexes"]
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            enabled = [
                "codex-account-a@example.com",
                *[f"codex-quota-a{idx}@example.com" for idx in range(9)],
                "codex-quota-primary@example.com",
            ]
            disabled = [
                *[f"codex-quota-b{idx}@example.com" for idx in range(9)],
                "codex-quota-secondary@example.com",
                "codex-quota-tertiary@example.com",
            ]
            for label in enabled:
                path = auth_dir / f"{label}-plus.json"
                path.write_text(json.dumps({"type": "codex", "disabled": False}), encoding="utf-8")
            for label in disabled:
                path = auth_dir / f"{label}-plus.json"
                path.write_text(json.dumps({"type": "codex", "disabled": True}), encoding="utf-8")
            state_path = auth_dir / "state.json"
            state_path.write_text('{"auth_weekly_auto_disabled": {}}\n', encoding="utf-8")
            with mock.patch.object(snapshot_module, "now_ts", return_value=100), \
                 mock.patch.object(snapshot_module, "AUTH_DIR", auth_dir, create=True), \
                 mock.patch.object(snapshot_module, "QUOTA_STATE", state_path), \
                 mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
                 mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_usage_keeper_request):
                text = build_quota_management_reply({"created_at": 100})

        lines = text.splitlines()
        self.assertEqual(lines[0], "Quota Management")
        self.assertEqual(lines[1], "Data: updated 0s ago")
        self.assertNotIn("Cliproxy:", text)
        self.assertIn("Enabled Auth Accounts", text)
        self.assertIn("Disabled Auth Accounts", text)
        self.assertNotIn("more enabled", text)
        self.assertNotIn("more disabled", text)
        for index, label in enumerate(enabled, start=1):
            self.assertIn(f"{index}. {label}\n(5h avail: 100%, weekly avail: 100%)", text)
            self.assertNotIn(f"- {label}", text)
            self.assertNotIn(f"{index}. {label}: 5h", text)
        for index, label in enumerate(disabled, start=1):
            self.assertIn(f"{index}. {label}", text)
            self.assertNotIn(f"{index}. {label}: disabled", text)
            self.assertNotIn(f"{index}. {label}: 5h", text)
            self.assertNotIn(f"{index}. {label}\n(5h", text)
        self.assertNotIn("5h avail: unavailable", text)
        self.assertNotIn("codex ...", text)

    def test_quota_management_handles_unavailable_quota_without_crashing_or_leaking_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            (auth_dir / "codex-secret@example.com.json").write_text(json.dumps({"type": "codex", "disabled": False, "token": "sk-secret-value"}), encoding="utf-8")
            with mock.patch.object(snapshot_module, "AUTH_DIR", auth_dir, create=True), \
                 mock.patch.object(snapshot_module, "auth_management_quota_left_by_ref", return_value={}):
                text = build_quota_management_reply({"created_at": 100})

        self.assertIn("(5h avail: unavailable, weekly avail: unavailable)", text)
        self.assertNotIn("codex-secret@example.com", text)
        self.assertNotIn("sk-secret", text)
        self.assertNotIn("auth_index", text)

    def test_key_status_reply_shows_summary_disabled_keys_and_action(self):
        snapshot = {
            "created_at": snapshot_module.now_ts(),
            "quota_error": "",
            "quota_rows": [
                {
                    "alias": "active-ok",
                    "status": "active",
                    "daily_used": 1_000_000,
                    "daily_limit": 10_000_000,
                    "weekly_used": 2_000_000,
                    "weekly_limit": 40_000_000,
                    "effective_percent": 10.0,
                },
                {
                    "alias": "near-daily",
                    "status": "active",
                    "daily_used": 9_000_000,
                    "daily_limit": 10_000_000,
                    "weekly_used": 3_000_000,
                    "weekly_limit": 40_000_000,
                    "effective_percent": 90.0,
                },
                {
                    "alias": "weekly-off",
                    "status": "active",
                    "daily_used": 1_000_000,
                    "daily_limit": 10_000_000,
                    "weekly_used": 2_000_000,
                    "weekly_limit": None,
                    "effective_percent": 10.0,
                },
                {
                    "alias": "quota-hit",
                    "status": "disabled",
                    "daily_used": 11_690_000,
                    "daily_limit": 10_000_000,
                    "weekly_used": 5_000_000,
                    "weekly_limit": None,
                    "effective_percent": 116.9,
                },
                {
                    "alias": "weekly-hit",
                    "status": "disabled",
                    "daily_used": 30_700_000,
                    "daily_limit": 30_000_000,
                    "weekly_used": 33_500_000,
                    "weekly_limit": 120_000_000,
                    "effective_percent": 102.3,
                },
                {
                    "alias": "missing-one",
                    "status": "missing",
                    "daily_used": 0,
                    "daily_limit": 10_000_000,
                    "weekly_used": 0,
                    "weekly_limit": 40_000_000,
                    "effective_percent": 0.0,
                },
            ],
        }

        text = snapshot_module.build_key_status_reply(snapshot)

        self.assertEqual(text.splitlines()[0], "Key Status")
        self.assertEqual(text.splitlines()[1], "Data: updated 0s ago")
        self.assertNotIn("Data: cached, snapshot", text)
        self.assertIn("Summary", text)
        self.assertIn("Active keys: 3", text)
        self.assertIn("Disabled keys: 2", text)
        self.assertIn("Missing from config: 1", text)
        self.assertNotIn("quota-exhausted keys", text)
        self.assertNotIn("missing from proxy config", text)
        self.assertNotIn("near quota", text)
        self.assertIn("Uncapped weekly: 1 active, 1 disabled", text)
        self.assertNotIn("No weekly cap", text)
        self.assertNotIn("weekly cap disabled keys", text)
        self.assertNotIn("quota-exhausted", text)
        self.assertIn("Disabled Keys", text)
        self.assertNotIn("Cliproxy: key status", text)
        self.assertNotIn("Quota warnings", text)
        self.assertIn("- quota-hit (quota exceeded)", text)
        self.assertIn("- weekly-hit (quota exceeded)", text)
        self.assertNotIn("+ Daily quota:", text)
        self.assertNotIn("+ Weekly quota:", text)
        self.assertNotIn("near-daily", text)
        self.assertNotIn("missing-one", text)
        self.assertNotIn("[disabled]", text)
        self.assertNotIn("[active]", text)
        self.assertNotIn("[missing]", text)
        self.assertNotIn("(116.9%)", text)
        self.assertNotIn("(102.3%)", text)
        self.assertNotIn("Action", text)
        self.assertNotIn("Disabled keys usually restore automatically after daily or weekly reset.", text)
        self.assertNotIn("backend GPT auth", text)

    def test_key_status_reply_includes_manually_disabled_keys_without_missing_label(self):
        snapshot = {
            "created_at": 0,
            "quota_error": "",
            "quota_rows": [
                {
                    "alias": "manual-off",
                    "status": "manually_disabled",
                    "daily_used": 1_000_000,
                    "daily_limit": 10_000_000,
                    "weekly_used": 2_000_000,
                    "weekly_limit": 40_000_000,
                    "effective_percent": 10.0,
                },
            ],
        }

        text = snapshot_module.build_key_status_reply(snapshot)

        self.assertIn("Disabled keys: 1", text)
        self.assertIn("Missing from config: 0", text)
        self.assertIn("Disabled Keys", text)
        self.assertIn("- manual-off (manually disabled)", text)
        self.assertNotIn("+ Daily quota:", text)
        self.assertNotIn("+ Weekly quota:", text)
        self.assertNotIn("[missing]", text)
        self.assertNotIn("quota-disabled", text.lower())

    def test_manually_disabled_keys_suppress_not_in_proxy_alert(self):
        context = {
            "items": [
                {
                    "name": "manual-off",
                    "key": "manual-secret-key",
                    "daily_token_limit": 10_000_000,
                    "weekly_token_limit": 40_000_000,
                    "manually_disabled": True,
                }
            ],
            "disabled": set(),
            "config_keys": {"some-other-key"},
            "alias_by_key": {"manual-secret-key": "manual-off"},
            "usage": {},
        }

        rows = snapshot_module.quota_rows_from_context(context)
        alerts = snapshot_module.quota_alerts_from_context(context)

        self.assertEqual(rows[0]["status"], "manually_disabled")
        self.assertFalse(any(alert.alert_id.startswith("quota:not-in-proxy:") for alert in alerts))

    def test_key_status_manually_disabled_row_uses_full_quota_alias_over_short_cpa_alias(self):
        context = {
            "items": [
                {
                    "name": "hominhquang",
                    "key": "hominhquang-secret-key",
                    "daily_token_limit": 75_000_000,
                    "weekly_token_limit": 300_000_000,
                    "manually_disabled": True,
                }
            ],
            "disabled": set(),
            "config_keys": {"some-other-key"},
            "alias_by_key": {"hominhquang-secret-key": "quang"},
            "usage": {
                "hominhquang-secret-key": {
                    "daily_tokens": 0,
                    "weekly_tokens": 54_000_000,
                }
            },
        }

        rows = snapshot_module.quota_rows_from_context(context)
        text = snapshot_module.build_key_status_reply({
            "created_at": 0,
            "quota_error": "",
            "quota_rows": [snapshot_module.sanitize_quota_row(rows[0])],
        })

        self.assertEqual(rows[0]["alias"], "hominhquang")
        self.assertIn("- hominhquang (manually disabled)", text)
        self.assertNotIn("- quang: manually disabled", text)

    def test_key_status_reply_shows_no_disabled_keys_when_empty(self):
        snapshot = {
            "created_at": 0,
            "quota_error": "",
            "quota_rows": [
                {
                    "alias": "active-ok",
                    "status": "active",
                    "daily_used": 1_000_000,
                    "daily_limit": 10_000_000,
                    "weekly_used": 2_000_000,
                    "weekly_limit": 40_000_000,
                    "effective_percent": 10.0,
                },
            ],
        }

        text = snapshot_module.build_key_status_reply(snapshot)

        self.assertNotIn("Disabled Keys", text)
        self.assertNotIn("- None", text)
        self.assertNotIn("Quota warnings", text)
        self.assertNotIn("[disabled]", text)
        self.assertNotIn("%", text)
        self.assertNotIn("near quota", text)
        self.assertNotIn("quota-exhausted", text)

    def test_key_status_reply_does_not_render_secret_like_labels(self):
        snapshot = {
            "created_at": 0,
            "quota_error": "",
            "quota_rows": [
                {
                    "alias": "secret-auth@example.com",
                    "name": "auth-file.json",
                    "masked": "sk-secret***abcd",
                    "status": "disabled",
                    "daily_used": 12_000_000,
                    "daily_limit": 10_000_000,
                    "weekly_used": 1_000_000,
                    "weekly_limit": None,
                    "effective_percent": 120.0,
                },
            ],
        }

        text = snapshot_module.build_key_status_reply(snapshot)

        self.assertIn("- key (quota exceeded)", text)
        self.assertNotIn("+ Daily quota:", text)
        self.assertNotIn("+ Weekly quota:", text)
        self.assertNotIn("[disabled]", text)
        self.assertNotIn("(120.0%)", text)
        self.assertNotIn("secret-auth", text)
        self.assertNotIn("@example.com", text)
        self.assertNotIn("auth-file.json", text)
        self.assertNotIn("sk-secret", text)
        self.assertNotIn("auth JSON", text)

    def test_alert_message_has_impact_evidence_and_action(self):
        alert = Alert(
            alert_id="service:usage-keeper",
            severity="critical",
            title="usage-keeper is not reachable",
            body="http://usage-keeper:8080/usage/healthz failed: timed out",
            fingerprint="unreachable",
        )

        text = build_alert_message(alert)

        self.assertIn("[CRITICAL]", text)
        self.assertIn("Impact:", text)
        self.assertIn("Evidence:", text)
        self.assertIn("Action:", text)
        self.assertIn("Usage dashboard and Telegram usage summaries", text)
        self.assertIn("docker compose", text)

    def test_alert_message_standardizes_selected_title_lines_only(self):
        cases = [
            (
                Alert("capacity:gpt-pool-5h-low", "warning", "GPT pool 5h capacity low", "5h margin: 0.7x", "margin:0.7"),
                "[WARN] GPT pool 5h capacity low",
            ),
            (
                Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload", "unavailable:malformed"),
                "[WARN] Proxy Auth Inspection Unavailable",
            ),
            (
                Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice"),
                "[CRITICAL] Proxy accounts need reauth",
            ),
        ]
        for alert, title in cases:
            with self.subTest(alert_id=alert.alert_id):
                text = build_alert_message(alert)
                self.assertEqual(text.splitlines()[0], title)
                if alert.alert_id in {"auth:quota-inspection-failed", "capacity:gpt-pool-5h-low"}:
                    self.assertNotIn("Impact:", text)
                else:
                    self.assertIn("Impact:", text)
                self.assertIn("Evidence:", text)
                self.assertIn("Action:", text)
                self.assertNotIn("---", text)

    def test_reauth_alert_uses_actionable_email_and_compact_secret_safe_evidence(self):
        payload = {
            "results": [
                {
                    "file_name": "codex-account-b@example.com.json",
                    "name": "codex-account-b@example.com.json",
                    "type": "codex",
                    "status": "unauthorized_401",
                    "error": "HTTP 401 {\"error\": {\"code\": \"token_revoked\", \"message\": \"Encountered invalidated oauth token for user, failing request bearer ghp_errorbearersecret sk-errorsecret123 cookie=session-cookie-secret api_key=ck-error-api-key management_token=mgmt-error-secret\"}}",
                    "token": "sk-secret-token-value",
                    "cookie": "session-cookie-secret",
                    "api_key": "ck-secret-api-key",
                    "management_token": "management-secret-value",
                }
            ]
        }

        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts = check_auth_quota_status(refresh_before_check=False, wait_for_refresh=False)

        self.assertEqual(len(alerts), 1)
        text = build_alert_message(alerts[0])

        self.assertEqual(text, "\n".join([
            "[CRITICAL] Proxy accounts need reauth",
            "",
            "Evidence: 401 Encountered invalidated oauth token for user, failing request",
            "- codex-account-b@example.com",
            "",
            "Action:",
            "Reauth the listed account(s), then check Health alerts.",
        ]))
        self.assertNotIn("- Account ", text)
        self.assertNotIn("---", text)
        self.assertNotIn("Account ending", text)
        self.assertNotIn("ghp_errorbearersecret", text)
        self.assertNotIn("sk-errorsecret123", text)
        self.assertNotIn("cookie=session-cookie-secret", text)
        self.assertNotIn("api_key=ck-error-api-key", text)
        self.assertNotIn("management_token=mgmt-error-secret", text)
        self.assertNotIn("codex-account-b@example.com.json", text)
        self.assertNotIn("token_revoked", text)
        self.assertNotIn("sk-secret-token-value", text)
        self.assertNotIn("session-cookie-secret", text)
        self.assertNotIn("ck-secret-api-key", text)
        self.assertNotIn("management-secret-value", text)
        self.assertNotIn("raw auth", text.lower())

    def test_reauth_alert_masks_secret_like_label_when_email_is_unavailable(self):
        payload = {
            "results": [
                {
                    "file_name": "sk-secret-label-1234567890abcdef.json",
                    "name": "sk-secret-label-1234567890abcdef.json",
                    "type": "codex",
                    "status": "unauthorized_401",
                    "error": "HTTP 401 failed",
                }
            ]
        }

        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts = check_auth_quota_status(refresh_before_check=False, wait_for_refresh=False)

        text = build_alert_message(alerts[0])

        self.assertIn("[CRITICAL] Proxy accounts need reauth", text)
        self.assertIn("Evidence: 401 failed", text)
        self.assertRegex(text, r"(?m)^- hash [0-9a-f]{16}$")
        self.assertNotIn("- Account ", text)
        self.assertNotIn("sk-secret-label-1234567890abcdef", text)
        self.assertNotIn("sk-secret-label-1234567890abcdef.json", text)
        self.assertNotIn("---", text)

    def test_key_create_summary_is_concise_and_hides_backend_targets(self):
        text = build_key_create_summary("exampleuser", "hung", 100_000_000, "default", "hung-12345678901234567")

        self.assertIn("Pending API key creation", text)
        self.assertIn("User: exampleuser", text)
        self.assertNotIn("Alias shown in dashboards", text)
        self.assertIn("Key prefix: hung", text)
        self.assertIn("Daily quota: 100.0M", text)
        self.assertIn("Weekly quota: default = 400.0M", text)
        self.assertIn("Key preview:", text)
        self.assertNotIn("This creates a shared API key.", text)
        self.assertNotIn("Will add to:", text)
        self.assertNotIn("proxy config", text)
        self.assertNotIn("web management", text)
        self.assertNotIn("quota config", text)
        self.assertNotIn("CPA Usage Keeper registry", text)
        self.assertNotIn("hung-12345678901234567", text)

    def test_quota_update_summary_shows_current_new_and_effective_weekly_default(self):
        account = {"alias": "alice", "daily": 4_000_000, "weekly": 16_000_000}

        text = quota_update_summary(account, 20_000_000, "default")

        self.assertEqual(
            text,
            "Pending quota update\n\n"
            "User: alice\n"
            "Daily quota: 4M -> 20M\n"
            "Weekly quota: 16M -> 80M",
        )
        self.assertNotIn("default =", text)
        self.assertNotIn("Confirm Quota Update", text)
        self.assertNotIn("This changes the shared quota for this account.", text)
        self.assertNotIn("shared quota config", text)

    def test_create_key_prompt_uses_standard_header(self):
        prompt = settings_module.MESSAGES["key_create_prompt"]

        self.assertTrue(prompt.startswith("Create Key"))
        self.assertNotIn("Cliproxy:", prompt.splitlines()[0])
        self.assertIn("Examples:", prompt)
        self.assertNotIn("Create API key", prompt)

    def test_key_create_input_still_creates_pending_confirm_action(self):
        state = {"pending_inputs": {"chat:user": {"type": "key_create", "expires_at": 99_999_999_999, "cleanup_message_ids": [55]}}}
        with mock.patch("telegram_alerts.actions.parse_api_keys_block", return_value=[]), \
             mock.patch("telegram_alerts.actions.CLIPROXY_CONFIG", mock.Mock(read_text=mock.Mock(return_value=""))), \
             mock.patch("telegram_alerts.actions.load_quotas_json", return_value={"keys": []}), \
             mock.patch("telegram_alerts.actions.generate_api_key", return_value="alice-secret-key"):
            result = handle_pending_input("alice, alice, 20M", state, chat_id="chat", user_id="user", message_id=66)

        self.assertIn("Pending API key creation", result["text"])
        self.assertIn("User: alice", result["text"])
        self.assertIn("Tap Confirm to apply or Cancel to discard. This expires in 5 minutes.", result["text"])
        self.assertIn("Confirm", str(result.get("reply_markup", "")))
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Cancel", "Confirm"]])
        callbacks = [[button["callback_data"] for button in row] for row in keyboard]
        self.assertTrue(callbacks[0][0].startswith("cancel:"))
        self.assertTrue(callbacks[0][1].startswith("confirm:"))
        self.assertEqual(callbacks[0][0].split(":", 1)[1], callbacks[0][1].split(":", 1)[1])
        self.assertNotIn("alice-secret-key", str(callbacks))
        self.assertIn("pending_actions", state)
        self.assertEqual(state["pending_actions"]["chat:user"].get("cleanup_message_ids"), [55, 66])
        self.assertIn("Key preview:", result["text"])
        self.assertNotIn("This creates a shared API key.", result["text"])
        self.assertNotIn("alice-secret-key", result["text"])

    def test_key_create_acquires_runtime_lock_around_shared_writes(self):
        events = []

        @contextmanager
        def fake_lock():
            events.append("lock_enter")
            try:
                yield
            finally:
                events.append("lock_exit")

        def record_write(name):
            def _record(*args, **kwargs):
                self.assertIn("lock_enter", events)
                self.assertNotIn("lock_exit", events)
                events.append(name)
            return _record

        with mock.patch("telegram_alerts.actions.parse_api_keys_block", return_value=[]), \
             mock.patch("telegram_alerts.actions.CLIPROXY_CONFIG", mock.Mock(read_text=mock.Mock(return_value=""))), \
             mock.patch("telegram_alerts.actions.load_quotas_json", return_value={"keys": []}), \
             mock.patch("telegram_alerts.actions.quota_runtime_lock", fake_lock, create=True), \
             mock.patch("telegram_alerts.actions.backup_action_files", side_effect=record_write("backup")), \
             mock.patch("telegram_alerts.actions.write_config_api_keys", side_effect=record_write("config")), \
             mock.patch("telegram_alerts.actions.save_quotas_json", side_effect=record_write("quotas")), \
             mock.patch("telegram_alerts.actions.upsert_cpa_api_key_alias", side_effect=record_write("cpa")):
            execute_key_create({"alias": "alice", "name": "alice", "daily": 20_000_000, "weekly": "default", "key": "alice-secret-key"})

        self.assertEqual(events[0], "lock_enter")
        self.assertEqual(events[-1], "lock_exit")
        self.assertIn("config", events)
        self.assertIn("quotas", events)

    def test_quota_set_acquires_runtime_lock_around_quota_write(self):
        events = []
        quotas = {"keys": [{"name": "alice", "key": "alice-key", "daily_token_limit": 4_000_000, "weekly_token_limit": 16_000_000}]}

        @contextmanager
        def fake_lock():
            events.append("lock_enter")
            try:
                yield
            finally:
                events.append("lock_exit")

        def save_quotas(data):
            self.assertIn("lock_enter", events)
            self.assertNotIn("lock_exit", events)
            events.append("save_quotas")

        with mock.patch("telegram_alerts.actions.load_quotas_json", return_value=quotas), \
             mock.patch("telegram_alerts.actions.load_cpa_alias_map", return_value={"alice-key": "alice"}), \
             mock.patch("telegram_alerts.actions.quota_runtime_lock", fake_lock, create=True), \
             mock.patch("telegram_alerts.actions.backup_action_files", return_value="backup"), \
             mock.patch("telegram_alerts.actions.save_quotas_json", side_effect=save_quotas):
            execute_quota_set({"query": "alice", "daily": 20_000_000, "weekly": "default"})

        self.assertEqual(events, ["lock_enter", "save_quotas", "lock_exit"])

    def test_key_management_actions_acquire_runtime_lock_around_shared_writes(self):
        for action_type, state_data in (
            ("key_disable", {}),
            ("key_enable", {"manually_disabled_keys": ["alice-key"]}),
            ("key_delete", {"manually_disabled_keys": ["alice-key"]}),
        ):
            with self.subTest(action_type=action_type):
                events = []
                quotas = {"keys": [{"name": "alice", "key": "alice-key", "daily_token_limit": 1}]}

                @contextmanager
                def fake_lock():
                    events.append("lock_enter")
                    try:
                        yield
                    finally:
                        events.append("lock_exit")

                def record_write(name):
                    def _record(*args, **kwargs):
                        self.assertIn("lock_enter", events)
                        self.assertNotIn("lock_exit", events)
                        events.append(name)
                    return _record

                with mock.patch("telegram_alerts.actions.load_quotas_json", return_value=quotas), \
                     mock.patch("telegram_alerts.actions.quota_state_data", return_value=dict(state_data)), \
                     mock.patch("telegram_alerts.actions.config_api_keys", return_value=["alice-key"] if action_type != "key_enable" else []), \
                     mock.patch("telegram_alerts.actions.quota_runtime_lock", fake_lock, create=True), \
                     mock.patch("telegram_alerts.actions.backup_action_files", side_effect=record_write("backup")), \
                     mock.patch("telegram_alerts.actions.write_config_api_keys", side_effect=record_write("config")), \
                     mock.patch("telegram_alerts.actions.save_quotas_json", side_effect=record_write("quotas")), \
                     mock.patch("telegram_alerts.actions.save_quota_state_json", side_effect=record_write("state")), \
                     mock.patch("telegram_alerts.actions.soft_delete_cpa_api_key", side_effect=record_write("cpa_delete")):
                    execute_key_management(action_type, {"key": "alice-key", "alias": "alice"})

                self.assertEqual(events[0], "lock_enter")
                self.assertEqual(events[-1], "lock_exit")
                self.assertTrue(any(name in events for name in ("config", "quotas", "state")))

    def test_key_create_success_reminds_operator_to_keep_key_private(self):
        with mock.patch("telegram_alerts.actions.parse_api_keys_block", return_value=[]), \
             mock.patch("telegram_alerts.actions.CLIPROXY_CONFIG", mock.Mock(read_text=mock.Mock(return_value=""))), \
             mock.patch("telegram_alerts.actions.load_quotas_json", return_value={"keys": []}), \
             mock.patch("telegram_alerts.actions.backup_action_files"), \
             mock.patch("telegram_alerts.actions.write_config_api_keys"), \
             mock.patch("telegram_alerts.actions.save_quotas_json"), \
             mock.patch("telegram_alerts.actions.upsert_cpa_api_key_alias"):
            text = execute_key_create({"alias": "alice", "name": "alice", "daily": 20_000_000, "weekly": "default", "key": "alice-secret-key"})

        self.assertIn("API key created.", text)
        self.assertIn("User: alice", text)
        self.assertNotIn("Alias: alice", text)
        self.assertIn("API key: alice-secret-key", text)
        self.assertIn("Keep this key private.", text)

    def test_quota_set_success_uses_operator_result_heading(self):
        quotas = {"keys": [{"name": "alice", "key": "alice-key", "daily_token_limit": 4_000_000, "weekly_token_limit": 16_000_000}]}
        with mock.patch("telegram_alerts.actions.load_quotas_json", return_value=quotas), \
             mock.patch("telegram_alerts.actions.load_cpa_alias_map", return_value={"alice-key": "alice"}), \
             mock.patch("telegram_alerts.actions.backup_action_files", return_value="backup"), \
             mock.patch("telegram_alerts.actions.save_quotas_json"):
            text = execute_quota_set({"query": "alice", "daily": 20_000_000, "weekly": "default"})

        self.assertTrue(text.startswith("Quota update applied."))
        self.assertIn("User: alice", text)
        self.assertIn("Daily: 20M", text)

    def test_quota_set_success_renders_unlimited_weekly_wording(self):
        quotas = {"keys": [{"name": "alice", "key": "alice-key", "daily_token_limit": 100_000_000, "weekly_token_limit": 400_000_000}]}
        with mock.patch("telegram_alerts.actions.load_quotas_json", return_value=quotas), \
             mock.patch("telegram_alerts.actions.load_cpa_alias_map", return_value={"alice-key": "alice"}), \
             mock.patch("telegram_alerts.actions.backup_action_files", return_value="backup"), \
             mock.patch("telegram_alerts.actions.save_quotas_json"):
            text = execute_quota_set({"query": "alice", "daily": 100_000_000, "weekly": None})

        self.assertIn("Weekly: unlimited", text)
        self.assertNotIn("weekly cap disabled", text)
        self.assertNotIn("no weekly cap", text)

    def test_save_quotas_json_preserves_existing_runtime_file_inode_and_avoids_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            quota_path = Path(tmp) / "quotas.json"
            quota_path.write_text('{"keys": []}\n', encoding="utf-8")
            before = quota_path.stat()

            with mock.patch.object(quota_config_module, "QUOTA_CONFIG", quota_path), \
                 mock.patch("telegram_alerts.storage.os.replace", side_effect=AssertionError("os.replace called")):
                quota_config_module.save_quotas_json({
                    "timezone": "Asia/Ho_Chi_Minh",
                    "keys": [{"name": "alice", "key": "alice-secret-key", "daily_token_limit": 1}],
                })

            after = quota_path.stat()
            saved = quota_path.read_text(encoding="utf-8")

            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
            self.assertEqual(json.loads(saved)["keys"][0]["name"], "alice")
            self.assertTrue(saved.endswith("\n"))

    def test_write_config_api_keys_preserves_existing_runtime_file_inode_and_avoids_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text('server: true\napi-keys:\n  - "old-key"\nother: value\n', encoding="utf-8")
            before = config_path.stat()

            with mock.patch.object(quota_config_module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch("telegram_alerts.storage.os.replace", side_effect=AssertionError("os.replace called")):
                quota_config_module.write_config_api_keys(["new-key"])

            after = config_path.stat()
            saved = config_path.read_text(encoding="utf-8")

            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
            self.assertIn('  - "new-key"', saved)
            self.assertNotIn("old-key", saved)
            self.assertTrue(saved.endswith("\n"))

    def test_quota_runtime_lock_uses_shared_quota_enforcer_lock_file(self):
        self.assertTrue(hasattr(quota_config_module, "quota_runtime_lock"))
        self.assertTrue(hasattr(quota_config_module, "fcntl"))
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "quota-enforcer" / "quota_enforcer.lock"
            calls = []

            def record_flock(file_obj, operation):
                calls.append((Path(file_obj.name), operation))

            with mock.patch.object(quota_config_module, "QUOTA_RUNTIME_LOCK", lock_path, create=True), \
                 mock.patch.object(quota_config_module.fcntl, "flock", side_effect=record_flock):
                with quota_config_module.quota_runtime_lock():
                    self.assertTrue(lock_path.exists())

            self.assertEqual(calls[0], (lock_path, quota_config_module.fcntl.LOCK_EX))
            self.assertEqual(calls[-1], (lock_path, quota_config_module.fcntl.LOCK_UN))

    def test_manual_disable_and_enable_quota_state_writes_preserve_inode_and_avoid_replace(self):
        key = "alice-secret-key"
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            quota_path = base / "quotas.json"
            state_path = base / "state.json"
            config_path = base / "config.yaml"
            quota_path.write_text(
                json.dumps({"keys": [{"name": "alice", "key": key, "daily_token_limit": 1}]}) + "\n",
                encoding="utf-8",
            )
            state_path.write_text("{}\n", encoding="utf-8")
            config_path.write_text(f'api-keys:\n  - "{key}"\n', encoding="utf-8")
            before = state_path.stat()

            with mock.patch.object(actions_module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(actions_module, "QUOTA_STATE", state_path), \
                 mock.patch.object(quota_config_module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(quota_config_module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(quota_config_module, "QUOTA_STATE", state_path), \
                 mock.patch("telegram_alerts.actions.backup_action_files"), \
                 mock.patch("telegram_alerts.storage.os.replace", side_effect=AssertionError("os.replace called")):
                execute_key_management("key_disable", {"key": key, "alias": "alice"})
                after_disable = state_path.stat()
                disabled_state = json.loads(state_path.read_text(encoding="utf-8"))
                execute_key_management("key_enable", {"key": key, "alias": "alice"})
                after_enable = state_path.stat()
                enabled_state = json.loads(state_path.read_text(encoding="utf-8"))
                saved_state_text = state_path.read_text(encoding="utf-8")

            self.assertEqual((after_disable.st_dev, after_disable.st_ino), (before.st_dev, before.st_ino))
            self.assertEqual((after_enable.st_dev, after_enable.st_ino), (before.st_dev, before.st_ino))
            self.assertEqual(disabled_state.get("manually_disabled_keys"), [key])
            self.assertEqual(enabled_state.get("manually_disabled_keys"), [])
            self.assertTrue(saved_state_text.endswith("\n"))

    def test_execute_key_reveal_result_contains_secret_only_in_final_reply(self):
        result = execute_key_reveal({"alias": "alice", "key": "alice-secret-key"})

        self.assertIn("API key", result)
        self.assertIn("User: alice", result)
        self.assertNotIn("Alias: alice", result)
        self.assertIn("alice-secret-key", result)
        self.assertIn("Keep this key private", result)

    def test_key_picker_reveal_is_immediate_without_pending_confirmation(self):
        state = {
            "key_pickers": {
                "chat:user": {
                    "id": "picker1",
                    "keys": ["alice-secret-key"],
                    "aliases": ["alice"],
                    "expires_at": 99_999_999_999,
                }
            }
        }

        result = build_key_reveal_from_picker(state, "picker1", "0", chat_id="chat", user_id="user")

        self.assertIn("alice-secret-key", result["text"])
        self.assertIn("Keep this key private", result["text"])
        self.assertNotIn("Confirm", str(result.get("reply_markup", "")))
        self.assertNotIn("pending_actions", state)
        self.assertIn("reply_markup", result)
        labels = [button["text"] for row in result.get("reply_markup", {}).get("inline_keyboard", []) for button in row]
        self.assertEqual(labels, ["Menu", "Show another key"])

    def test_show_key_picker_uses_standard_header(self):
        state = {}
        with mock.patch("telegram_alerts.pickers.key_accounts_for_picker", return_value=[{"alias": "alice", "key": "alice-secret-key"}]), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
            result = prompt_key_reveal_picker(state, chat_id="chat", user_id="user")

        self.assertTrue(result["text"].startswith("Show Key\n\nChoose a user to show the full API key."))
        self.assertNotIn("an alias", result["text"])
        self.assertNotIn("Cliproxy:", result["text"].splitlines()[0])

    def test_show_key_picker_pagination_uses_cancel_next_and_menu_layout(self):
        page_size = max(4, pickers_module.QUOTA_PICKER_PAGE_SIZE)
        accounts = [
            {"alias": f"user{index:02d}", "key": f"key-{index}"}
            for index in range(page_size + 1)
        ]

        with mock.patch("telegram_alerts.pickers.key_accounts_for_picker", return_value=accounts), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
            result = prompt_key_reveal_picker({}, chat_id="chat", user_id="user")

        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard[-2:]], [["Cancel", "Next"], ["Menu"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard[-2:]], [["menu:key_status", "kpage:picker1:1"], ["menu:back"]])

    def test_show_key_lookup_prompt_uses_user_wording(self):
        result = prompt_key_lookup({}, chat_id="chat", user_id="user")

        self.assertEqual(result["text"], "Enter the exact user to show the full API key.")
        self.assertNotIn("alias", result["text"].lower())

    def test_edit_quota_picker_uses_standard_header(self):
        state = {}
        with mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=[{"alias": "alice", "key": "alice-key"}]), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
            result = prompt_quota_picker(state, chat_id="chat", user_id="user")

        self.assertTrue(result["text"].startswith("Edit Quota\n\nChoose a user:"))
        self.assertNotIn("account alias", result["text"])
        self.assertNotIn("Cliproxy:", result["text"].splitlines()[0])

    def test_edit_quota_picker_pagination_uses_cancel_next_without_menu_tail(self):
        page_size = max(4, pickers_module.QUOTA_PICKER_PAGE_SIZE)
        accounts = [
            {"alias": f"user{index:02d}", "key": f"key-{index}"}
            for index in range(page_size + 1)
        ]

        with mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=accounts), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
            result = prompt_quota_picker({}, chat_id="chat", user_id="user")

        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard[-1:]], [["Cancel", "Next"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard[-1:]], [["menu:back", "qpage:picker1:1"]])
        self.assertNotIn(["Menu"], [[button["text"] for button in row] for row in keyboard])

    def test_edit_quota_account_selection_opens_quota_type_choice(self):
        state = {
            "quota_pickers": {
                "chat:user": {
                    "id": "picker1",
                    "keys": ["hominhquang-secret-key"],
                    "aliases": ["hominhquang"],
                    "expires_at": 99_999_999_999,
                }
            }
        }
        account = {"alias": "hominhquang", "key": "hominhquang-secret-key", "daily": 30_000_000, "weekly": 120_000_000}

        with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account):
            result = handle_callback("qacct:picker1:0", state, chat_id="chat", user_id="user", message_id=1)

        self.assertEqual(
            result["text"],
            "Edit Quota\n\n"
            "User: hominhquang\n"
            "Daily quota: 30M\n"
            "Weekly quota: 120M\n\n"
            "Choose quota to edit:",
        )
        self.assertNotIn("quang\n", result["text"].replace("hominhquang", ""))
        self.assertNotIn("hominhquang-secret-key", result["text"])
        labels = [[button["text"] for button in row] for row in result["reply_markup"]["inline_keyboard"]]
        self.assertEqual(labels, [["Daily quota", "Weekly quota"], ["Cancel", "Menu"]])
        self.assertEqual(
            [[button["callback_data"] for button in row] for row in result["reply_markup"]["inline_keyboard"]],
            [["qdaily:picker1:0", "qweekly:picker1:0"], ["qpage:picker1:0", "menu:back"]],
        )
        callbacks = [button["callback_data"] for row in result["reply_markup"]["inline_keyboard"] for button in row]
        self.assertFalse(any("hominhquang-secret-key" in callback for callback in callbacks))

    def test_daily_quota_preset_buttons_use_current_layout_only(self):
        state = {
            "quota_pickers": {
                "chat:user": {
                    "id": "picker1",
                    "keys": ["alice-key"],
                    "aliases": ["alice"],
                    "expires_at": 99_999_999_999,
                }
            }
        }
        account = {"alias": "alice", "key": "alice-key", "daily": 100_000_000, "weekly": "default"}

        with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account):
            result = handle_callback("qdaily:picker1:0", state, chat_id="chat", user_id="user", message_id=1)

        labels = [[button["text"] for button in row] for row in result["reply_markup"]["inline_keyboard"]]
        self.assertEqual(labels, [["20M", "40M"], ["60M", "80M"], ["100M", "200M"], ["Menu", "Custom"]])
        flattened = [label for row in labels for label in row]
        for removed in ("4M", "50M", "75M", "125M", "Unlimited"):
            with self.subTest(removed=removed):
                self.assertNotIn(removed, flattened)

    def test_removed_daily_quota_preset_callbacks_are_invalid(self):
        removed_callbacks = ["0", "2", "3", "5", "none"]
        for limit_code in removed_callbacks:
            with self.subTest(limit_code=limit_code):
                state = {
                    "quota_pickers": {
                        "chat:user": {
                            "id": "picker1",
                            "selected_key": "alice-key",
                            "expires_at": 99_999_999_999,
                        }
                    }
                }
                account = {"alias": "alice", "key": "alice-key", "daily": 100_000_000, "weekly": "default"}

                with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account):
                    result = handle_callback(f"qlimit:picker1:{limit_code}", state, chat_id="chat", user_id="user", message_id=1)

                self.assertIn("Invalid quota option. Open Edit quota again.", result["text"])
                self.assertNotIn("pending_actions", state)

    def test_daily_quota_preset_preserves_current_weekly_behavior(self):
        cases = [
            ("default weekly", "default", "default"),
            ("explicit weekly", 500_000_000, 500_000_000),
            ("unlimited", None, None),
        ]
        for _label, current_weekly, expected_weekly in cases:
            with self.subTest(current_weekly=current_weekly):
                state = {
                    "quota_pickers": {
                        "chat:user": {
                            "id": "picker1",
                            "selected_key": "alice-key",
                            "expires_at": 99_999_999_999,
                        }
                    }
                }
                account = {"alias": "alice", "key": "alice-key", "daily": 100_000_000, "weekly": current_weekly}

                with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account):
                    result = handle_callback("qlimit:picker1:200m", state, chat_id="chat", user_id="user", message_id=1)

                self.assertIn("Pending quota update", result["text"])
                params = state["pending_actions"]["chat:user"]["params"]
                self.assertEqual(params["daily"], 200_000_000)
                self.assertEqual(params["weekly"], expected_weekly)
                self.assertEqual(params["quota_kind"], "daily")

    def test_weekly_quota_preset_buttons_use_current_layout_only(self):
        state = {
            "quota_pickers": {
                "chat:user": {
                    "id": "picker1",
                    "keys": ["alice-key"],
                    "aliases": ["alice"],
                    "expires_at": 99_999_999_999,
                }
            }
        }
        account = {"alias": "alice", "key": "alice-key", "daily": 100_000_000, "weekly": 400_000_000}

        with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account):
            result = handle_callback("qweekly:picker1:0", state, chat_id="chat", user_id="user", message_id=1)

        labels = [[button["text"] for button in row] for row in result["reply_markup"]["inline_keyboard"]]
        self.assertEqual(labels, [["Default", "Unlimited"], ["Menu", "Custom"]])

    def test_weekly_quota_default_and_unlimited_buttons_create_expected_pending_actions(self):
        cases = [
            ("qweek:picker1:default", "default"),
            ("qweek:picker1:none", None),
        ]
        for callback, expected_weekly in cases:
            with self.subTest(callback=callback):
                state = {
                    "quota_pickers": {
                        "chat:user": {
                            "id": "picker1",
                            "selected_key": "alice-key",
                            "expires_at": 99_999_999_999,
                        }
                    }
                }
                account = {"alias": "alice", "key": "alice-key", "daily": 100_000_000, "weekly": 400_000_000}

                with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account):
                    result = handle_callback(callback, state, chat_id="chat", user_id="user", message_id=1)

                self.assertIn("Pending quota update", result["text"])
                params = state["pending_actions"]["chat:user"]["params"]
                self.assertEqual(params["daily"], 100_000_000)
                self.assertEqual(params["weekly"], expected_weekly)
                self.assertEqual(params["quota_kind"], "weekly")

    def test_removed_weekly_quota_preset_callbacks_are_invalid(self):
        for limit_code in ("0", "1", "2", "3", "4", "5"):
            with self.subTest(limit_code=limit_code):
                state = {
                    "quota_pickers": {
                        "chat:user": {
                            "id": "picker1",
                            "selected_key": "alice-key",
                            "expires_at": 99_999_999_999,
                        }
                    }
                }
                account = {"alias": "alice", "key": "alice-key", "daily": 100_000_000, "weekly": 400_000_000}

                with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account):
                    result = handle_callback(f"qweek:picker1:{limit_code}", state, chat_id="chat", user_id="user", message_id=1)

                self.assertIn("Invalid quota option. Open Edit quota again.", result["text"])
                self.assertNotIn("pending_actions", state)

    def test_weekly_custom_input_accepts_default_none_and_numeric_values(self):
        cases = [
            ("default", "default"),
            ("none", None),
            ("unlimited", None),
            ("800M", 800_000_000),
        ]
        for typed, expected_weekly in cases:
            with self.subTest(typed=typed):
                state = {
                    "quota_pickers": {
                        "chat:user": {
                            "id": "picker1",
                            "selected_key": "alice-key",
                            "expires_at": 99_999_999_999,
                        }
                    }
                }
                account = {"alias": "alice", "key": "alice-key", "daily": 100_000_000, "weekly": 400_000_000}

                with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account):
                    prompt = handle_callback("qweek:picker1:custom", state, chat_id="chat", user_id="user", message_id=1)
                with mock.patch("telegram_alerts.actions.quota_account_by_key", return_value=account):
                    result = handle_pending_input(typed, state, chat_id="chat", user_id="user")

                self.assertIn("Custom weekly quota", prompt["text"])
                self.assertIn("unlimited", prompt["text"])
                self.assertNotIn("no weekly cap", prompt["text"])
                self.assertIn("Pending quota update", result["text"])
                params = state["pending_actions"]["chat:user"]["params"]
                self.assertEqual(params["daily"], 100_000_000)
                self.assertEqual(params["weekly"], expected_weekly)
                self.assertEqual(params["quota_kind"], "weekly")

    def test_confirm_quota_summary_renders_effective_weekly_values_without_default_label(self):
        account = {"alias": "alice", "daily": 100_000_000, "weekly": "default"}

        text = quota_update_summary(account, 125_000_000, "default")

        self.assertIn("Pending quota update", text)
        self.assertIn("Daily quota: 100M -> 125M", text)
        self.assertIn("Weekly quota: 400M -> 500M", text)
        self.assertNotIn("default =", text)
        self.assertNotIn("Weekly behavior", text)
        for old in ("100.0M", "125.0M", "400.0M", "500.0M"):
            with self.subTest(old=old):
                self.assertNotIn(old, text)

    def test_quota_edit_summary_preserves_disabled_and_unlimited_wording(self):
        disabled = quota_update_summary({"alias": "alice", "daily": 100_000_000, "weekly": None}, 125_000_000, None)
        unlimited = quota_update_summary({"alias": "bob", "daily": None, "weekly": "default"}, None, "default")

        self.assertIn("Weekly quota: unlimited -> unlimited", disabled)
        self.assertIn("Daily quota: unlimited -> unlimited", unlimited)
        self.assertIn("Weekly quota: unlimited -> unlimited", unlimited)
        self.assertNotIn("default =", disabled + unlimited)
        for removed in ("weekly cap disabled", "no weekly cap", "No weekly cap"):
            with self.subTest(removed=removed):
                self.assertNotIn(removed, disabled + unlimited)

    def test_daily_quota_custom_input_still_creates_pending_confirm_action(self):
        state = {
            "quota_pickers": {
                "chat:user": {
                    "id": "picker1",
                    "selected_key": "alice-key",
                    "expires_at": 99_999_999_999,
                }
            }
        }
        account = {"alias": "alice", "key": "alice-key", "daily": 100_000_000, "weekly": "default"}

        with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account):
            prompt = handle_callback("qlimit:picker1:custom", state, chat_id="chat", user_id="user", message_id=1)
        with mock.patch("telegram_alerts.actions.quota_account_by_key", return_value=account):
            result = handle_pending_input("150M", state, chat_id="chat", user_id="user")

        self.assertIn("Custom quota", prompt["text"])
        self.assertIn("Pending quota update", result["text"])
        params = state["pending_actions"]["chat:user"]["params"]
        self.assertEqual(params["daily"], 150_000_000)
        self.assertEqual(params["weekly"], "default")
        self.assertEqual(params["quota_kind"], "daily")

    def test_weekly_quota_invalid_picker_paths_remain_user_friendly(self):
        state = {"quota_pickers": {"chat:user": {"id": "picker1", "selected_key": "alice-key", "expires_at": 1}}}

        result = handle_callback("qweekly:missing:0", state, chat_id="chat", user_id="user", message_id=1)

        self.assertIn("This quota picker expired. Open Edit quota again.", result["text"])
        labels = [button["text"] for row in result["reply_markup"]["inline_keyboard"] for button in row]
        self.assertEqual(labels, ["Edit quota", "Menu"])

    def test_usage_picker_uses_standard_header(self):
        state = {}
        with mock.patch("telegram_alerts.pickers.usage_accounts_for_picker", return_value=("Asia/Ho_Chi_Minh", [{"alias": "alice", "key": "alice-key"}])), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
            result = prompt_usage_picker(state, chat_id="chat", user_id="user")

        self.assertTrue(result["text"].startswith("Usage\n\nChoose a user:"))
        self.assertNotIn("Choose an alias", result["text"])
        self.assertNotIn("Cliproxy:", result["text"].splitlines()[0])
        self.assertNotIn("Usage report", result["text"])

    def test_usage_picker_pagination_cancel_returns_to_top_users(self):
        page_size = max(4, pickers_module.QUOTA_PICKER_PAGE_SIZE)
        accounts = [
            {"alias": f"user{index:02d}", "key": f"key-{index}"}
            for index in range(page_size + 1)
        ]

        with mock.patch("telegram_alerts.pickers.usage_accounts_for_picker", return_value=("Asia/Ho_Chi_Minh", accounts)), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
            result = prompt_usage_picker({}, chat_id="chat", user_id="user")

        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard[-2:]], [["Cancel", "Next"], ["Menu"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard[-2:]], [["menu:top", "upage:picker1:1"], ["menu:back"]])

    def test_usage_report_uses_standard_keyboard_layout(self):
        state = {
            "usage_pickers": {
                "chat:user": {
                    "id": "picker1",
                    "keys": ["alice-key"],
                    "aliases": ["alice"],
                    "daily_limits": [125_000_000],
                    "weekly_limits": [500_000_000],
                    "statuses": ["active"],
                    "masked": ["sk-..."],
                    "tz_name": "Asia/Ho_Chi_Minh",
                    "expires_at": 99_999_999_999,
                }
            }
        }
        usage = {"daily": empty_usage_bucket(), "weekly": empty_usage_bucket()}

        with mock.patch("telegram_alerts.pickers.get_usage_breakdown_for_key", return_value=usage):
            result = build_usage_report_from_picker(state, "picker1", "0", chat_id="chat", user_id="user")

        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Menu", "Another user"], ["Refresh"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["menu:back", "menu:usage"], ["uacct:picker1:0"]])
        self.assertNotIn("Another account", str(keyboard))
        self.assertNotEqual([[button["text"] for button in row] for row in keyboard], [["Refresh", "Another user"], ["Menu"]])

    def test_show_another_key_callback_routes_to_key_picker(self):
        state = {}
        with mock.patch("telegram_alerts.handlers.prompt_key_reveal_picker") as picker:
            picker.return_value = {"text": "Show key", "reply_markup": {"inline_keyboard": []}}
            result = handle_callback("menu:key_lookup", state, chat_id="chat", user_id="user", message_id=1)

        picker.assert_called_once_with(state, chat_id="chat", user_id="user")
        self.assertTrue(result["edit_message"])

    def test_confirmed_quota_update_includes_edit_another_key_actions(self):
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "quota_set",
                    "params": {"query": "alice", "daily": 20_000_000, "weekly": "default", "quota_kind": "daily"},
                    "summary": "Pending quota update\n\nUser: alice",
                    "expires_at": 99_999_999_999,
                }
            }
        }
        with mock.patch("telegram_alerts.actions.execute_quota_set", return_value=("Quota updated.", "alice-key")):
            result = handle_callback("confirm:abc123", state, chat_id="chat", user_id="user", message_id=1)

        self.assertEqual(result["text"], "Quota updated.")
        self.assertTrue(result["edit_message"])
        keyboard = result.get("reply_markup", {}).get("inline_keyboard", [])
        labels = [[button["text"] for button in row] for row in keyboard]
        callbacks = [[button["callback_data"] for button in row] for row in keyboard]
        self.assertEqual(labels, [["Edit weekly quota", "Edit another key"], ["Menu"]])
        self.assertEqual(callbacks[0][1], "after:menu:quota_set")
        self.assertEqual(callbacks[1][0], "after:menu:back")
        self.assertTrue(callbacks[0][0].startswith("after:qsame:"))
        self.assertTrue(callbacks[0][0].endswith(":weekly"))
        self.assertNotIn("alice-key", callbacks[0][0])

    def test_confirmed_weekly_quota_update_includes_edit_daily_action(self):
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "quota_set",
                    "params": {"query": "alice", "daily": 20_000_000, "weekly": None, "quota_kind": "weekly"},
                    "summary": "Pending quota update\n\nUser: alice",
                    "expires_at": 99_999_999_999,
                }
            }
        }
        with mock.patch("telegram_alerts.actions.execute_quota_set", return_value=("Quota updated.", "alice-key")):
            result = handle_callback("confirm:abc123", state, chat_id="chat", user_id="user", message_id=1)

        keyboard = result.get("reply_markup", {}).get("inline_keyboard", [])
        labels = [[button["text"] for button in row] for row in keyboard]
        callback = keyboard[0][0]["callback_data"]
        self.assertEqual(labels, [["Edit daily quota", "Edit another key"], ["Menu"]])
        self.assertTrue(callback.startswith("after:qsame:"))
        self.assertTrue(callback.endswith(":daily"))
        self.assertNotIn("alice-key", callback)

    def test_quota_update_confirm_cancel_returns_to_previous_quota_picker(self):
        cases = (
            ("daily", "Edit Quota\n\nUser: alice", "Choose new daily quota:"),
            ("weekly", "Edit Weekly Quota\n\nUser: alice", "Choose new weekly quota:"),
        )
        for quota_kind, prefix, prompt in cases:
            with self.subTest(quota_kind=quota_kind):
                state = {
                    "quota_pickers": {
                        "chat:user": {
                            "id": "picker1",
                            "selected_key": "alice-key",
                            "expires_at": 99_999_999_999,
                        }
                    },
                    "pending_actions": {
                        "chat:user": {
                            "code": "abc123",
                            "type": "quota_set",
                            "params": {
                                "query": "alice-key",
                                "daily": 200_000_000,
                                "weekly": "default",
                                "quota_kind": quota_kind,
                            },
                            "summary": "Pending quota update\n\nUser: alice",
                            "expires_at": 99_999_999_999,
                        }
                    },
                }
                account = {"alias": "alice", "key": "alice-key", "daily": 300_000_000, "weekly": None}

                with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account):
                    result = handle_callback("cancel:abc123", state, chat_id="chat", user_id="user", message_id=1)

                self.assertTrue(result["edit_message"])
                self.assertTrue(result["text"].startswith(prefix))
                self.assertIn(prompt, result["text"])
                self.assertNotIn("chat:user", state.get("pending_actions", {}))

    def test_key_create_confirm_cancel_returns_to_create_key_prompt(self):
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "key_create",
                    "params": {
                        "alias": "alice",
                        "name": "alice",
                        "daily": 20_000_000,
                        "weekly": "default",
                        "key": "alice-secret-key",
                    },
                    "summary": "Pending API key creation\n\nUser: alice",
                    "expires_at": 99_999_999_999,
                }
            }
        }

        result = handle_callback("cancel:abc123", state, chat_id="chat", user_id="user", message_id=1)

        self.assertTrue(result["edit_message"])
        self.assertEqual(result["text"], settings_module.MESSAGES["key_create_prompt"])
        self.assertEqual(state["pending_inputs"]["chat:user"]["type"], "key_create")
        self.assertNotIn("chat:user", state.get("pending_actions", {}))
        self.assertNotIn("alice-secret-key", str(result))

    def test_key_create_confirm_cancel_deletes_old_prompt_and_user_input(self):
        state = {
            "telegram_offset": 1,
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "key_create",
                    "params": {
                        "alias": "alice",
                        "name": "alice",
                        "daily": 20_000_000,
                        "weekly": "default",
                        "key": "alice-secret-key",
                    },
                    "summary": "Pending API key creation\n\nUser: alice",
                    "cleanup_message_ids": [55, 66],
                    "expires_at": 99_999_999_999,
                }
            },
        }
        update = {
            "update_id": 7,
            "callback_query": {
                "id": "cb1",
                "data": "cancel:abc123",
                "from": {"id": "user"},
                "message": {
                    "message_id": 77,
                    "chat": {"id": "chat"},
                },
            },
        }

        with mock.patch("telegram_alerts.handlers.TELEGRAM_BOT_TOKEN", "token"), \
             mock.patch("telegram_alerts.handlers.allowed_chat_ids", return_value={"chat"}), \
             mock.patch("telegram_alerts.handlers.allowed_user_ids", return_value={"user"}), \
             mock.patch("telegram_alerts.handlers.is_authorized", return_value=True), \
             mock.patch("telegram_alerts.handlers.telegram_get_updates", return_value=[update]), \
             mock.patch("telegram_alerts.handlers.answer_callback_query_async"), \
             mock.patch("telegram_alerts.handlers.delete_telegram_message_async") as delete_message, \
             mock.patch("telegram_alerts.handlers.edit_telegram_message_result", return_value={"ok": True, "reason": "ok"}) as edit_message:
            handled = process_commands(state)

        self.assertEqual(handled, 1)
        edit_message.assert_called_once()
        self.assertEqual(delete_message.call_args_list, [mock.call("chat", 55), mock.call("chat", 66)])
        self.assertEqual(state["pending_inputs"]["chat:user"]["type"], "key_create")
        self.assertNotIn("chat:user", state.get("pending_actions", {}))

    def test_same_key_edit_weekly_callback_opens_weekly_picker_for_applied_key(self):
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "quota_set",
                    "params": {"query": "alice", "daily": 300_000_000, "weekly": None, "quota_kind": "daily"},
                    "summary": "Pending quota update\n\nUser: alice",
                    "expires_at": 99_999_999_999,
                }
            }
        }
        account = {"alias": "alice", "key": "alice-key", "daily": 300_000_000, "weekly": None}
        with mock.patch("telegram_alerts.actions.execute_quota_set", return_value=("Quota updated.", "alice-key")):
            confirmed = handle_callback("confirm:abc123", state, chat_id="chat", user_id="user", message_id=1)
        callback = confirmed["reply_markup"]["inline_keyboard"][0][0]["callback_data"]

        with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account) as by_key:
            result = handle_callback(callback, state, chat_id="chat", user_id="user", message_id=1)

        by_key.assert_called_once_with("alice-key")
        self.assertTrue(result["delete_message"])
        self.assertFalse(result.get("edit_message", False))
        self.assertTrue(result["text"].startswith("Edit Weekly Quota\n\nUser: alice"))
        self.assertIn("Current daily: 300M", result["text"])
        self.assertIn("Current weekly: unlimited", result["text"])
        labels = [[button["text"] for button in row] for row in result["reply_markup"]["inline_keyboard"]]
        self.assertEqual(labels, [["Default", "Unlimited"], ["Menu", "Custom"]])
        self.assertNotIn("alice-key", result["text"])

    def test_same_key_edit_daily_callback_opens_daily_picker_for_applied_key(self):
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "quota_set",
                    "params": {"query": "alice", "daily": 300_000_000, "weekly": 1_200_000_000, "quota_kind": "weekly"},
                    "summary": "Pending quota update\n\nUser: alice",
                    "expires_at": 99_999_999_999,
                }
            }
        }
        account = {"alias": "alice", "key": "alice-key", "daily": 300_000_000, "weekly": 1_200_000_000}
        with mock.patch("telegram_alerts.actions.execute_quota_set", return_value=("Quota updated.", "alice-key")):
            confirmed = handle_callback("confirm:abc123", state, chat_id="chat", user_id="user", message_id=1)
        callback = confirmed["reply_markup"]["inline_keyboard"][0][0]["callback_data"]

        with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account) as by_key:
            result = handle_callback(callback, state, chat_id="chat", user_id="user", message_id=1)

        by_key.assert_called_once_with("alice-key")
        self.assertTrue(result["delete_message"])
        self.assertFalse(result.get("edit_message", False))
        self.assertTrue(result["text"].startswith("Edit Quota\n\nUser: alice"))
        self.assertIn("Current daily: 300M", result["text"])
        self.assertIn("Current weekly: 1.2B", result["text"])
        labels = [[button["text"] for button in row] for row in result["reply_markup"]["inline_keyboard"]]
        self.assertEqual(labels, [["20M", "40M"], ["60M", "80M"], ["100M", "200M"], ["Menu", "Custom"]])
        self.assertNotIn("alice-key", result["text"])

    def test_same_key_edit_callback_is_scoped_to_confirming_operator(self):
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "quota_set",
                    "params": {"query": "alice", "daily": 300_000_000, "weekly": None, "quota_kind": "daily"},
                    "summary": "Pending quota update\n\nUser: alice",
                    "expires_at": 99_999_999_999,
                }
            }
        }
        with mock.patch("telegram_alerts.actions.execute_quota_set", return_value=("Quota updated.", "alice-key")):
            confirmed = handle_callback("confirm:abc123", state, chat_id="chat", user_id="user", message_id=1)
        callback = confirmed["reply_markup"]["inline_keyboard"][0][0]["callback_data"]

        with mock.patch("telegram_alerts.pickers.quota_account_by_key") as by_key:
            result = handle_callback(callback, state, chat_id="other-chat", user_id="user", message_id=1)

        by_key.assert_not_called()
        self.assertIn("This quota picker expired. Open Edit quota again.", result["text"])
        self.assertNotIn("alice-key", result["text"])

    def test_edit_another_key_from_quota_success_opens_account_picker(self):
        state = {}
        with mock.patch("telegram_alerts.handlers.prompt_quota_picker", return_value={"text": "Edit Quota\n\nChoose a user:", "reply_markup": {"inline_keyboard": []}}) as picker:
            result = handle_callback("after:menu:quota_set", state, chat_id="chat", user_id="user", message_id=1)

        picker.assert_called_once_with(state, chat_id="chat", user_id="user")
        self.assertTrue(result["delete_message"])
        self.assertFalse(result.get("edit_message", False))

    def test_quota_preset_limits_setting_is_removed(self):
        self.assertFalse(hasattr(settings_module, "QUOTA_" + "PRESET_LIMITS"))

    def test_confirmed_key_create_includes_create_another_key_actions(self):
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "key_create",
                    "params": {"alias": "alice", "name": "alice", "daily": 20_000_000, "weekly": "default", "key": "alice-secret-key"},
                    "summary": "Pending API key creation\n\nUser: alice\nKey preview: masked",
                    "expires_at": 99_999_999_999,
                }
            }
        }
        with mock.patch("telegram_alerts.actions.execute_key_create", return_value="API key created.\n\nUser: alice\nAPI key: alice-secret-key"):
            result = handle_callback("confirm:abc123", state, chat_id="chat", user_id="user", message_id=1)

        self.assertIn("alice-secret-key", result["text"])
        self.assertTrue(result["edit_message"])
        labels = [button["text"] for row in result.get("reply_markup", {}).get("inline_keyboard", []) for button in row]
        callbacks = [button["callback_data"] for row in result.get("reply_markup", {}).get("inline_keyboard", []) for button in row]
        self.assertEqual(labels, ["Menu", "Create another key"])
        self.assertEqual(callbacks, ["after:menu:back", "after:menu:key_create"])

    def test_key_create_confirm_deletes_create_prompt_after_successful_mutation(self):
        state = {
            "telegram_offset": 1,
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "key_create",
                    "params": {"alias": "alice", "name": "alice", "daily": 20_000_000, "weekly": "default", "key": "alice-secret-key"},
                    "summary": "Pending API key creation\n\nUser: alice",
                    "cleanup_message_ids": [55, 66],
                    "expires_at": 99_999_999_999,
                }
            },
        }
        update = {
            "update_id": 7,
            "callback_query": {
                "id": "cb1",
                "data": "confirm:abc123",
                "from": {"id": "user"},
                "message": {
                    "message_id": 77,
                    "chat": {"id": "chat"},
                },
            },
        }

        with mock.patch("telegram_alerts.handlers.TELEGRAM_BOT_TOKEN", "token"), \
             mock.patch("telegram_alerts.handlers.allowed_chat_ids", return_value={"chat"}), \
             mock.patch("telegram_alerts.handlers.allowed_user_ids", return_value={"user"}), \
             mock.patch("telegram_alerts.handlers.is_authorized", return_value=True), \
             mock.patch("telegram_alerts.handlers.telegram_get_updates", return_value=[update]), \
             mock.patch("telegram_alerts.handlers.answer_callback_query_async"), \
             mock.patch("telegram_alerts.actions.execute_key_create", return_value="API key created.\n\nUser: alice\nAPI key: alice-secret-key"), \
             mock.patch("telegram_alerts.handlers.delete_telegram_message_async") as delete_message, \
             mock.patch("telegram_alerts.handlers.edit_telegram_message_result", return_value={"ok": True, "reason": "ok"}) as edit_message:
            handled = process_commands(state)

        self.assertEqual(handled, 1)
        self.assertEqual(delete_message.call_args_list, [mock.call("chat", 55), mock.call("chat", 66)])
        edit_message.assert_called_once()
        self.assertNotIn("chat:user", state.get("pending_actions", {}))

    def test_inline_quota_set_still_requires_confirm_before_execution(self):
        state = {"quota_pickers": {"chat:user": {"id": "picker1", "selected_key": "alice-key", "expires_at": 99_999_999_999}}}
        account = {"alias": "alice", "key": "alice-key", "daily": 4_000_000, "weekly": "default"}
        with mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account), \
             mock.patch("telegram_alerts.actions.execute_quota_set") as execute_quota_set:
            result = handle_callback("qlimit:picker1:20m", state, chat_id="chat", user_id="user", message_id=1)

        self.assertIn("Pending quota update", result["text"])
        self.assertIn("Tap Confirm to apply or Cancel to discard. This expires in 5 minutes.", result["text"])
        self.assertNotIn("This changes the shared quota for this account.", result["text"])
        self.assertIn("Confirm", str(result.get("reply_markup", "")))
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Cancel", "Confirm"]])
        callbacks = [[button["callback_data"] for button in row] for row in keyboard]
        self.assertTrue(callbacks[0][0].startswith("cancel:"))
        self.assertTrue(callbacks[0][1].startswith("confirm:"))
        self.assertEqual(callbacks[0][0].split(":", 1)[1], callbacks[0][1].split(":", 1)[1])
        self.assertNotIn("alice-key", str(callbacks))
        self.assertIn("pending_actions", state)
        execute_quota_set.assert_not_called()

    def test_key_create_pending_summary_does_not_expose_new_key_before_confirmation(self):
        new_key = "alice-secret-key"
        summary = build_key_create_summary("alice", "alice", 20_000_000, "default", new_key)

        self.assertIn("Pending API key creation", summary)
        self.assertIn("Key preview:", summary)
        self.assertNotIn(new_key, summary)

    def test_no_key_secret_appears_in_summary_or_log_style_text(self):
        secret = "alice-secret-key"

        create_summary = build_key_create_summary("alice", "alice", 1_000_000, "default", secret)

        self.assertNotIn(secret, create_summary)

    def test_key_status_callback_uses_exact_keyboard_layout(self):
        state = {"snapshot": {"created_at": 1, "quota_error": "", "quota_rows": []}}
        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]) as get_snapshot:
            result = handle_callback("menu:key_status", state, chat_id="chat", user_id="user", message_id=1)

        get_snapshot.assert_called_once_with(state, live=False, interactive=True)
        self.assertTrue(result["edit_message"])
        self.assertEqual(result["text"].splitlines()[0], "Key Status")
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Disable key", "Enable key"], ["Delete key", "Show key"], ["Menu", "Refresh"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["menu:key_disable", "menu:key_enable"], ["menu:key_delete", "menu:key_lookup"], ["menu:back", "menu:key_status_refresh"]])

    def test_key_status_refresh_reloads_key_status(self):
        state = {"snapshot": {"created_at": 1, "quota_error": "", "quota_rows": []}}
        with mock.patch("telegram_alerts.handlers.build_quota_rows_snapshot", return_value=state["snapshot"]) as get_snapshot:
            result = handle_callback("menu:key_status_refresh", state, chat_id="chat", user_id="user", message_id=1)

        get_snapshot.assert_called_once_with()
        self.assertEqual(result["text"].splitlines()[0], "Key Status")
        self.assertTrue(result["edit_message"])

    def test_key_status_show_key_button_opens_existing_key_picker(self):
        state = {}
        with mock.patch("telegram_alerts.handlers.prompt_key_reveal_picker") as picker:
            picker.return_value = {"text": "Show key picker", "reply_markup": {"inline_keyboard": []}}
            result = handle_callback("menu:key_lookup", state, chat_id="chat", user_id="user", message_id=1)

        picker.assert_called_once_with(state, chat_id="chat", user_id="user")
        self.assertTrue(result["edit_message"])
        self.assertEqual(result["text"], "Show key picker")

    def test_key_status_management_buttons_open_scoped_pickers_without_raw_key_callbacks(self):
        state = {}
        accounts = [
            {"key": "alice-secret-key", "alias": "alice"},
            {"key": "bob-secret-key", "alias": "bob"},
        ]
        for callback, title, manual_keys in (
            ("menu:key_disable", "Disable Key", set()),
            ("menu:key_enable", "Enable Key", {"alice-secret-key", "bob-secret-key"}),
            ("menu:key_delete", "Delete Key", {"alice-secret-key", "bob-secret-key"}),
        ):
            with self.subTest(callback=callback):
                with mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=accounts), \
                     mock.patch("telegram_alerts.pickers.manually_disabled_keys", return_value=manual_keys):
                    result = handle_callback(callback, state, chat_id="chat", user_id="user", message_id=1)

                self.assertTrue(result["edit_message"])
                self.assertTrue(result["text"].startswith(title))
                self.assertIn(f"Choose a user to {title.split()[0].lower()}.", result["text"])
                self.assertNotIn("an alias", result["text"])
                callbacks = [
                    button["callback_data"]
                    for row in result["reply_markup"]["inline_keyboard"]
                    for button in row
                ]
                self.assertFalse(any("alice-secret-key" in item or "bob-secret-key" in item for item in callbacks))

    def test_enable_key_picker_only_lists_manually_disabled_keys(self):
        state = {}
        accounts = [
            {"key": "active-secret-key", "alias": "active"},
            {"key": "manual-secret-key", "alias": "manual"},
            {"key": "quota-secret-key", "alias": "quota-disabled-manual"},
        ]

        with mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=accounts), \
             mock.patch("telegram_alerts.pickers.manually_disabled_keys", return_value={"manual-secret-key", "quota-secret-key"}), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
            result = prompt_key_management_picker(state, "enable", chat_id="chat", user_id="user")

        labels = [
            button["text"]
            for row in result["reply_markup"]["inline_keyboard"]
            for button in row
        ]
        callbacks = [
            button["callback_data"]
            for row in result["reply_markup"]["inline_keyboard"]
            for button in row
        ]
        self.assertIn("manual", labels)
        self.assertIn("quota-disabled-manual", labels)
        self.assertNotIn("active", labels)
        self.assertEqual(state["key_pickers"]["chat:user"]["keys"], ["manual-secret-key", "quota-secret-key"])
        self.assertFalse(any("manual-secret-key" in item or "quota-secret-key" in item for item in callbacks))
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard[-1:]], [["Cancel", "Menu"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard[-1:]], [["menu:key_status", "menu:back"]])

    def test_enable_key_picker_excludes_stale_manual_marker_for_active_proxy_key(self):
        state = {}
        accounts = [
            {"key": "active-secret-key", "alias": "active"},
            {"key": "manual-secret-key", "alias": "manual"},
        ]

        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text("api-keys:\n  - \"active-secret-key\"\n", encoding="utf-8")
            with mock.patch.object(quota_config_module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=accounts), \
                 mock.patch("telegram_alerts.pickers.manually_disabled_keys", return_value={"active-secret-key", "manual-secret-key"}), \
                 mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
                result = prompt_key_management_picker(state, "enable", chat_id="chat", user_id="user")

        labels = [
            button["text"]
            for row in result["reply_markup"]["inline_keyboard"]
            for button in row
        ]
        self.assertIn("manual", labels)
        self.assertNotIn("active", labels)
        self.assertEqual(state["key_pickers"]["chat:user"]["keys"], ["manual-secret-key"])

    def test_disable_key_picker_excludes_manually_disabled_keys(self):
        state = {}
        accounts = [
            {"key": "active-secret-key", "alias": "active"},
            {"key": "manual-secret-key", "alias": "manual"},
        ]
        with mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=accounts), \
             mock.patch("telegram_alerts.pickers.manually_disabled_keys", return_value={"manual-secret-key"}), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
            result = prompt_key_management_picker(state, "disable", chat_id="chat", user_id="user")

        labels = [
            button["text"]
            for row in result["reply_markup"]["inline_keyboard"]
            for button in row
        ]
        callbacks = [
            button["callback_data"]
            for row in result["reply_markup"]["inline_keyboard"]
            for button in row
        ]
        self.assertIn("active", labels)
        self.assertNotIn("manual", labels)
        self.assertEqual(state["key_pickers"]["chat:user"]["keys"], ["active-secret-key"])
        self.assertFalse(any("active-secret-key" in item or "manual-secret-key" in item for item in callbacks))

    def test_disable_and_delete_key_picker_pagination_uses_cancel_next_and_menu_layout(self):
        page_size = max(4, pickers_module.QUOTA_PICKER_PAGE_SIZE)
        accounts = [
            {"key": f"key-{index}", "alias": f"user{index:02d}"}
            for index in range(page_size + 1)
        ]
        for action, manual_keys in (
            ("disable", set()),
            ("delete", set()),
        ):
            with self.subTest(action=action):
                state = {}
                with mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=accounts), \
                     mock.patch("telegram_alerts.pickers.manually_disabled_keys", return_value=manual_keys), \
                     mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
                    result = prompt_key_management_picker(state, action, chat_id="chat", user_id="user")

                keyboard = result["reply_markup"]["inline_keyboard"]
                self.assertEqual([[button["text"] for button in row] for row in keyboard[-2:]], [["Cancel", "Next"], ["Menu"]])
                self.assertEqual([[button["callback_data"] for button in row] for row in keyboard[-2:]], [["menu:key_status", "kmpage:picker1:1"], ["menu:back"]])

    def test_enable_key_picker_pagination_keeps_next_then_cancel_menu_layout(self):
        page_size = max(4, pickers_module.QUOTA_PICKER_PAGE_SIZE)
        accounts = [
            {"key": f"key-{index}", "alias": f"user{index:02d}"}
            for index in range(page_size + 1)
        ]
        with mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=accounts), \
             mock.patch("telegram_alerts.pickers.manually_disabled_keys", return_value={account["key"] for account in accounts}), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
            result = prompt_key_management_picker({}, "enable", chat_id="chat", user_id="user")

        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard[-2:]], [["Next"], ["Cancel", "Menu"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard[-2:]], [["kmpage:picker1:1"], ["menu:key_status", "menu:back"]])

    def test_key_management_pickers_prefer_full_quota_name_over_short_cpa_alias(self):
        key = "hominhquang-secret-key"
        quota_data = {
            "keys": [
                {
                    "key": key,
                    "name": "hominhquang",
                    "daily_token_limit": 75_000_000,
                    "weekly_token_limit": 300_000_000,
                }
            ]
        }

        for action in ("disable", "enable", "delete"):
            with self.subTest(action=action):
                state = {}
                manual_keys = {key} if action == "enable" else set()
                with mock.patch("telegram_alerts.quota_config.load_quotas_json", return_value=quota_data), \
                     mock.patch("telegram_alerts.quota_config.load_cpa_alias_map", return_value={key: "quang"}), \
                     mock.patch("telegram_alerts.pickers.manually_disabled_keys", return_value=manual_keys), \
                     mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
                    result = prompt_key_management_picker(state, action, chat_id="chat", user_id="user")

                combined = result["text"] + str(result["reply_markup"])
                self.assertIn("hominhquang", combined)
                self.assertNotIn("quang", combined.replace("hominhquang", ""))
                self.assertNotIn(key, str(result["reply_markup"]))

    def test_enable_key_picker_empty_state_when_no_manual_keys(self):
        with mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=[{"key": "active-secret-key", "alias": "active"}]), \
             mock.patch("telegram_alerts.pickers.manually_disabled_keys", return_value=set()):
            result = prompt_key_management_picker({}, "enable", chat_id="chat", user_id="user")

        self.assertEqual(result["text"], "No manually disabled keys found.")
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Cancel", "Menu"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["menu:key_status", "menu:back"]])

    def test_enable_key_picker_reports_stale_manual_state_when_quota_row_is_missing(self):
        with mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=[]), \
             mock.patch("telegram_alerts.pickers.manually_disabled_keys", return_value={"stale-secret-key"}):
            result = prompt_key_management_picker({}, "enable", chat_id="chat", user_id="user")

        self.assertEqual(result["text"], "Manual disabled key state is stale. Open Key Status or restore the key from backup.")
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Cancel", "Menu"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["menu:key_status", "menu:back"]])
        self.assertNotIn("stale-secret-key", str(result))

    def test_manual_disable_keeps_quota_and_cpa_rows_enable_picker_lists_key(self):
        key = "hominhquang-secret-key"
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            quota_path = base / "quotas.json"
            config_path = base / "config.yaml"
            state_path = base / "state.json"
            db_path = base / "app.db"
            quota_path.write_text(
                json.dumps({
                    "timezone": "Asia/Ho_Chi_Minh",
                    "keys": [{"name": "hominhquang", "key": key, "daily_token_limit": 75_000_000, "weekly_token_limit": 300_000_000}],
                }) + "\n",
                encoding="utf-8",
            )
            config_path.write_text(f'api-keys:\n  - "{key}"\n', encoding="utf-8")
            state_path.write_text("{}\n", encoding="utf-8")
            con = sqlite3.connect(db_path)
            try:
                con.execute(
                    """
                    CREATE TABLE cpa_api_keys (
                        api_key TEXT PRIMARY KEY,
                        display_key TEXT,
                        key_alias TEXT,
                        is_deleted INTEGER DEFAULT 0
                    )
                    """
                )
                con.execute(
                    "INSERT INTO cpa_api_keys (api_key, display_key, key_alias, is_deleted) VALUES (?, ?, ?, 0)",
                    (key, "display", "hominhquang"),
                )
                con.commit()
            finally:
                con.close()

            with mock.patch("telegram_alerts.actions.CLIPROXY_CONFIG", config_path), \
                 mock.patch("telegram_alerts.actions.QUOTA_STATE", state_path), \
                 mock.patch("telegram_alerts.actions.backup_action_files"), \
                 mock.patch("telegram_alerts.quota_config.CLIPROXY_CONFIG", config_path), \
                 mock.patch("telegram_alerts.quota_config.QUOTA_CONFIG", quota_path), \
                 mock.patch("telegram_alerts.quota_config.QUOTA_STATE", state_path), \
                 mock.patch("telegram_alerts.quota_config.USAGE_DB", db_path), \
                 mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
                disable_result = execute_key_management("key_disable", {"key": key, "alias": "hominhquang"})
                saved_quota = json.loads(quota_path.read_text(encoding="utf-8"))
                saved_state = json.loads(state_path.read_text(encoding="utf-8"))
                con = sqlite3.connect(db_path)
                try:
                    cpa_row = con.execute(
                        "SELECT key_alias, is_deleted FROM cpa_api_keys WHERE api_key = ?",
                        (key,),
                    ).fetchone()
                finally:
                    con.close()
                picker = prompt_key_management_picker({}, "enable", chat_id="chat", user_id="user")

        self.assertIsNone(disable_result)
        self.assertEqual([item["key"] for item in saved_quota["keys"]], [key])
        self.assertEqual(saved_state.get("manually_disabled_keys"), [key])
        self.assertEqual(cpa_row, ("hominhquang", 0))
        self.assertIn("hominhquang", picker["text"] + str(picker["reply_markup"]))
        self.assertNotIn(key, str(picker["reply_markup"]))

    def test_delete_key_picker_keeps_active_and_disabled_quota_managed_keys(self):
        state = {}
        accounts = [
            {"key": "active-secret-key", "alias": "active"},
            {"key": "disabled-secret-key", "alias": "disabled"},
        ]

        with mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=accounts), \
             mock.patch("telegram_alerts.pickers.manually_disabled_keys", return_value={"disabled-secret-key"}), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
            result = prompt_key_management_picker(state, "delete", chat_id="chat", user_id="user")

        labels = [
            button["text"]
            for row in result["reply_markup"]["inline_keyboard"]
            for button in row
        ]
        self.assertIn("active", labels)
        self.assertIn("disabled", labels)
        self.assertEqual(state["key_pickers"]["chat:user"]["keys"], ["active-secret-key", "disabled-secret-key"])

    def test_disable_key_flow_requires_confirmation_and_does_not_delete_key(self):
        state = {
            "key_pickers": {
                "chat:user": {
                    "id": "picker1",
                    "keys": ["hung33-secret-7BfCD"],
                    "aliases": ["tuanhung33"],
                    "expires_at": 99_999_999_999,
                    "action": "disable",
                }
            }
        }

        with mock.patch("telegram_alerts.actions.execute_key_management") as execute:
            result = handle_callback("kmanage:picker1:0", state, chat_id="chat", user_id="user", message_id=1)

        self.assertEqual(
            result["text"],
            "Pending key disable\n\n"
            "User: tuanhung33\n"
            "Key preview: hung3***7BfCD\n"
            "Current status: Active\n"
            "New status: Disabled\n\n"
            "Tap Confirm to apply or Cancel to discard. This expires in 5 minutes.",
        )
        self.assertNotIn("This removes the key from active proxy keys without deleting quota management.", result["text"])
        self.assertNotIn("hung33-secret-7BfCD", result["text"])
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Cancel", "Confirm"]])
        callbacks = [[button["callback_data"] for button in row] for row in keyboard]
        self.assertTrue(callbacks[0][0].startswith("cancel:"))
        self.assertTrue(callbacks[0][1].startswith("confirm:"))
        self.assertEqual(callbacks[0][0].split(":", 1)[1], callbacks[0][1].split(":", 1)[1])
        self.assertNotIn("hung33-secret-7BfCD", str(callbacks))
        self.assertIn("pending_actions", state)
        self.assertEqual(state["pending_actions"]["chat:user"]["type"], "key_disable")
        self.assertEqual(state["pending_actions"]["chat:user"]["params"]["key"], "hung33-secret-7BfCD")
        execute.assert_not_called()

    def test_enable_key_flow_uses_exact_confirmation_template(self):
        state = {
            "key_pickers": {
                "chat:user": {
                    "id": "picker1",
                    "keys": ["hung33-secret-7BfCD"],
                    "aliases": ["tuanhung33"],
                    "expires_at": 99_999_999_999,
                    "action": "enable",
                }
            }
        }

        with mock.patch("telegram_alerts.actions.execute_key_management") as execute:
            result = handle_callback("kmanage:picker1:0", state, chat_id="chat", user_id="user", message_id=1)

        self.assertEqual(
            result["text"],
            "Pending key enable\n\n"
            "User: tuanhung33\n"
            "Key preview: hung3***7BfCD\n"
            "Current status: Disabled\n"
            "New status: Active\n\n"
            "Tap Confirm to apply or Cancel to discard. This expires in 5 minutes.",
        )
        self.assertNotIn("Only keys manually disabled by an operator can be enabled here.", result["text"])
        self.assertNotIn("hung33-secret-7BfCD", result["text"])
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Cancel", "Confirm"]])
        callbacks = [[button["callback_data"] for button in row] for row in keyboard]
        self.assertTrue(callbacks[0][0].startswith("cancel:"))
        self.assertTrue(callbacks[0][1].startswith("confirm:"))
        self.assertEqual(callbacks[0][0].split(":", 1)[1], callbacks[0][1].split(":", 1)[1])
        self.assertNotIn("hung33-secret-7BfCD", str(callbacks))
        self.assertIn("pending_actions", state)
        self.assertEqual(state["pending_actions"]["chat:user"]["type"], "key_enable")
        self.assertEqual(state["pending_actions"]["chat:user"]["params"]["key"], "hung33-secret-7BfCD")
        execute.assert_not_called()

    def test_delete_key_confirmation_uses_cancel_then_confirm_order(self):
        state = {
            "key_pickers": {
                "chat:user": {
                    "id": "picker1",
                    "keys": ["hung33-secret-7BfCD"],
                    "aliases": ["tuanhung33"],
                    "expires_at": 99_999_999_999,
                    "action": "delete",
                }
            }
        }

        with mock.patch("telegram_alerts.actions.execute_key_management") as execute:
            result = handle_callback("kmanage:picker1:0", state, chat_id="chat", user_id="user", message_id=1)

        self.assertEqual(
            result["text"],
            "Pending key deletion\n\n"
            "User: tuanhung33\n"
            "Key preview: hung3***7BfCD\n\n"
            "Tap Confirm to apply or Cancel to discard. This expires in 5 minutes.",
        )
        self.assertNotIn("This removes the key from proxy config, quota management, and the CPA registry.", result["text"])
        self.assertNotIn("Current status:", result["text"])
        self.assertNotIn("New status:", result["text"])
        self.assertNotIn("hung33-secret-7BfCD", result["text"])
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Cancel", "Confirm"]])
        callbacks = [[button["callback_data"] for button in row] for row in keyboard]
        self.assertTrue(callbacks[0][0].startswith("cancel:"))
        self.assertTrue(callbacks[0][1].startswith("confirm:"))
        self.assertEqual(callbacks[0][0].split(":", 1)[1], callbacks[0][1].split(":", 1)[1])
        self.assertNotIn("hung33-secret-7BfCD", str(callbacks))
        self.assertEqual(state["pending_actions"]["chat:user"]["type"], "key_delete")
        self.assertEqual(state["pending_actions"]["chat:user"]["params"]["key"], "hung33-secret-7BfCD")
        execute.assert_not_called()

    def test_key_management_confirm_cancel_returns_to_previous_picker(self):
        cases = (
            ("key_disable", "disable", "Disable Key"),
            ("key_enable", "enable", "Enable Key"),
            ("key_delete", "delete", "Delete Key"),
        )
        for action_type, action, title in cases:
            with self.subTest(action_type=action_type):
                state = {
                    "key_pickers": {
                        "chat:user": {
                            "id": "picker1",
                            "action": action,
                            "keys": ["alice-secret-key"],
                            "aliases": ["alice"],
                            "expires_at": 99_999_999_999,
                        }
                    },
                    "pending_actions": {
                        "chat:user": {
                            "code": "abc123",
                            "type": action_type,
                            "params": {"key": "alice-secret-key", "alias": "alice"},
                            "summary": "Confirm Key Action\n\nUser: alice",
                            "expires_at": 99_999_999_999,
                        }
                    }
                }

                result = handle_callback("cancel:abc123", state, chat_id="chat", user_id="user", message_id=1)

                self.assertTrue(result["edit_message"])
                self.assertTrue(result["text"].startswith(f"{title}\n\nChoose a user to {action}."))
                callbacks = [
                    button["callback_data"]
                    for row in result["reply_markup"]["inline_keyboard"]
                    for button in row
                ]
                self.assertIn("kmanage:picker1:0", callbacks)
                self.assertNotIn("chat:user", state.get("pending_actions", {}))

    def test_key_management_success_actions_return_no_operator_message(self):
        key = "alice-secret-key"
        quota_item = {"key": key, "name": "alice", "daily_token_limit": 1}
        cases = [
            ("key_disable", {}, [key]),
            ("key_enable", {"manually_disabled_keys": [key]}, []),
            ("key_delete", {"manually_disabled_keys": [key]}, [key]),
        ]

        for action_type, quota_state, config_keys in cases:
            with self.subTest(action_type=action_type), \
                 mock.patch("telegram_alerts.actions.parse_api_keys_block", return_value=config_keys), \
                 mock.patch("telegram_alerts.actions.write_config_api_keys"), \
                 mock.patch("telegram_alerts.actions.load_quotas_json", return_value={"keys": [dict(quota_item)]}), \
                 mock.patch("telegram_alerts.actions.save_quotas_json"), \
                 mock.patch("telegram_alerts.actions.load_json", return_value=quota_state), \
                 mock.patch("telegram_alerts.actions.save_quota_state_json"), \
                 mock.patch("telegram_alerts.actions.backup_action_files"), \
                 mock.patch("telegram_alerts.actions.soft_delete_cpa_api_key"), \
                 mock.patch("telegram_alerts.actions.CLIPROXY_CONFIG", mock.Mock(read_text=mock.Mock(return_value="api-keys: []"))):
                result = execute_key_management(action_type, {"key": key, "alias": "alice"})

            self.assertIsNone(result)

    def test_key_disable_confirm_returns_operator_success_after_mutation(self):
        key = "hung31-secret-7BfCD"
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "key_disable",
                    "params": {"key": key, "alias": "tuanhung31"},
                    "summary": "Pending key disable\n\nUser: tuanhung31",
                    "expires_at": 99_999_999_999,
                }
            }
        }

        with mock.patch("telegram_alerts.actions.parse_api_keys_block", return_value=[key]), \
             mock.patch("telegram_alerts.actions.write_config_api_keys"), \
             mock.patch("telegram_alerts.actions.load_quotas_json", return_value={"keys": [{"key": key, "name": "hominhquang", "daily_token_limit": 1}]}), \
             mock.patch("telegram_alerts.actions.load_json", return_value={}), \
             mock.patch("telegram_alerts.actions.save_quota_state_json"), \
             mock.patch("telegram_alerts.actions.backup_action_files"), \
             mock.patch("telegram_alerts.actions.CLIPROXY_CONFIG", mock.Mock(read_text=mock.Mock(return_value="api-keys: []"))):
            result = handle_callback("confirm:abc123", state, chat_id="chat", user_id="user", message_id=1)

        self.assertEqual(
            result["text"],
            "API key disabled.\n\n"
            "User: tuanhung31\n"
            "API key: hung3***7BfCD\n"
            "Status: Disabled\n\n"
            "This key can no longer be used for API requests.",
        )
        self.assertTrue(result["edit_message"])
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Key Status", "Disable another key"], ["Menu"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["after:menu:key_status", "after:menu:key_disable"], ["after:menu:back"]])
        self.assertNotIn(key, result["text"])
        self.assertNotIn("chat:user", state.get("pending_actions", {}))
        self.assertEqual(state["action_audit"][-1]["type"], "key_disable")
        self.assertEqual(state["action_audit"][-1]["key"], key)

    def test_key_enable_confirm_returns_operator_success_after_mutation(self):
        key = "hung31-secret-7BfCD"
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "key_enable",
                    "params": {"key": key, "alias": "tuanhung31"},
                    "summary": "Pending key enable\n\nUser: tuanhung31",
                    "expires_at": 99_999_999_999,
                }
            }
        }

        with mock.patch("telegram_alerts.actions.parse_api_keys_block", return_value=[]), \
             mock.patch("telegram_alerts.actions.write_config_api_keys"), \
             mock.patch("telegram_alerts.actions.load_quotas_json", return_value={"keys": [{"key": key, "name": "hominhquang", "daily_token_limit": 1}]}), \
             mock.patch("telegram_alerts.actions.load_json", return_value={"manually_disabled_keys": [key]}), \
             mock.patch("telegram_alerts.actions.save_quota_state_json"), \
             mock.patch("telegram_alerts.actions.backup_action_files"), \
             mock.patch("telegram_alerts.actions.CLIPROXY_CONFIG", mock.Mock(read_text=mock.Mock(return_value="api-keys: []"))):
            result = handle_callback("confirm:abc123", state, chat_id="chat", user_id="user", message_id=1)

        self.assertEqual(
            result["text"],
            "API key enabled.\n\n"
            "User: tuanhung31\n"
            "API key: hung3***7BfCD\n"
            "Status: Active\n\n"
            "This key is now active and ready for use.",
        )
        self.assertTrue(result["edit_message"])
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Key Status", "Enable another key"], ["Menu"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["after:menu:key_status", "after:menu:key_enable"], ["after:menu:back"]])
        self.assertNotIn(key, result["text"])
        self.assertNotIn("chat:user", state.get("pending_actions", {}))
        self.assertEqual(state["action_audit"][-1]["type"], "key_enable")
        self.assertEqual(state["action_audit"][-1]["key"], key)

    def test_stale_key_enable_confirm_cleans_marker_without_success_audit(self):
        key = "phat-Z7tJiOiax1TRyPbKk"
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "key_enable",
                    "params": {"key": key, "alias": "letanphat"},
                    "summary": "Pending key enable\n\nUser: letanphat",
                    "expires_at": 99_999_999_999,
                }
            }
        }

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            quota_path = base / "quotas.json"
            state_path = base / "state.json"
            config_path = base / "config.yaml"
            quota_path.write_text(
                json.dumps({"keys": [{"name": "letanphat", "key": key, "daily_token_limit": 20_000_000}]}) + "\n",
                encoding="utf-8",
            )
            state_path.write_text(json.dumps({"manually_disabled_keys": [key]}) + "\n", encoding="utf-8")
            config_path.write_text(f'api-keys:\n  - "{key}"\n', encoding="utf-8")

            with mock.patch.object(actions_module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(actions_module, "QUOTA_STATE", state_path), \
                 mock.patch.object(quota_config_module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(quota_config_module, "QUOTA_STATE", state_path), \
                 mock.patch("telegram_alerts.actions.backup_action_files") as backup:
                result = handle_callback("confirm:abc123", state, chat_id="chat", user_id="user", message_id=1)

            saved_state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(result["text"], "This key is already active.")
        self.assertEqual(saved_state.get("manually_disabled_keys"), [])
        self.assertNotIn("chat:user", state.get("pending_actions", {}))
        self.assertNotIn("action_audit", state)
        backup.assert_not_called()

    def test_enable_key_flow_only_enables_manually_disabled_keys_not_quota_disabled_keys(self):
        manual_state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "key_enable",
                    "params": {"key": "alice-secret-key", "alias": "alice"},
                    "summary": "Confirm Enable Key\n\nUser: alice",
                    "expires_at": 99_999_999_999,
                }
            }
        }
        quota_state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "key_enable",
                    "params": {"key": "quota-secret-key", "alias": "quota"},
                    "summary": "Confirm Enable Key\n\nUser: quota",
                    "expires_at": 99_999_999_999,
                }
            }
        }

        with mock.patch("telegram_alerts.actions.execute_key_management", return_value=None) as execute:
            manual = handle_callback("confirm:abc123", manual_state, chat_id="chat", user_id="user", message_id=1)
        with mock.patch("telegram_alerts.actions.execute_key_management", side_effect=ValueError("quota-disabled keys cannot be manually enabled from this action")):
            quota = handle_callback("confirm:abc123", quota_state, chat_id="chat", user_id="user", message_id=1)

        execute.assert_called_once()
        self.assertEqual(manual["text"].splitlines()[0], "API key enabled.")
        self.assertIn("cannot be manually enabled", quota["text"])

    def test_execute_key_enable_refuses_quota_disabled_key_even_if_manual_marker_exists(self):
        with mock.patch("telegram_alerts.actions.load_quotas_json", return_value={"keys": [{"key": "quota-secret-key", "name": "quota", "daily_token_limit": 1}]}), \
             mock.patch("telegram_alerts.actions.load_json", return_value={"disabled_by_quota": ["quota-secret-key"], "manually_disabled_keys": ["quota-secret-key"]}), \
             mock.patch("telegram_alerts.actions.write_config_api_keys") as write_config, \
             mock.patch("telegram_alerts.actions.save_quota_state_json") as save_state, \
             mock.patch("telegram_alerts.actions.backup_action_files"):
            with self.assertRaisesRegex(ValueError, "disabled by quota exhaustion"):
                execute_key_management("key_enable", {"key": "quota-secret-key", "alias": "quota"})

        write_config.assert_not_called()
        save_state.assert_not_called()

    def test_delete_key_flow_can_delete_active_and_disabled_keys(self):
        for key, disabled in (("active-secret-key", False), ("disabled-secret-key", True)):
            with self.subTest(key=key):
                state = {}
                with mock.patch("telegram_alerts.actions.parse_api_keys_block", return_value=[key]), \
                     mock.patch("telegram_alerts.actions.write_config_api_keys") as write_config, \
                     mock.patch("telegram_alerts.actions.load_quotas_json", return_value={"keys": [{"key": key, "name": "alice", "daily_token_limit": 1}]}), \
                     mock.patch("telegram_alerts.actions.save_quotas_json") as save_quotas, \
                     mock.patch("telegram_alerts.actions.load_json", return_value={"disabled_by_quota": [key] if disabled else [], "manually_disabled_keys": [key], "cpa_deleted_while_quota_disabled": [key]}), \
                     mock.patch("telegram_alerts.actions.save_quota_state_json") as save_state, \
                     mock.patch("telegram_alerts.actions.backup_action_files"), \
                     mock.patch("telegram_alerts.actions.soft_delete_cpa_api_key") as soft_delete, \
                     mock.patch("telegram_alerts.actions.CLIPROXY_CONFIG", mock.Mock(read_text=mock.Mock(return_value="api-keys: []"))):
                    result = create_pending_action(
                        state,
                        "key_delete",
                        {"key": key, "alias": "alice"},
                        "Confirm Delete Key\n\nUser: alice",
                        chat_id="chat",
                        user_id="user",
                    )
                    keyboard = result["reply_markup"]["inline_keyboard"]
                    self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Cancel", "Confirm"]])
                    callbacks = [button["callback_data"] for row in keyboard for button in row]
                    self.assertFalse(any(key in item for item in callbacks))
                    code = keyboard[0][1]["callback_data"].split(":", 1)[1]
                    confirmed = handle_callback(f"confirm:{code}", state, chat_id="chat", user_id="user", message_id=1)

                self.assertEqual(
                    confirmed["text"],
                    "API key deleted.\n\n"
                    "User: alice\n"
                    f"API key: {key[:5]}***{key[-5:]}\n\n"
                    "This key has been permanently removed from the system.",
                )
                self.assertTrue(confirmed["edit_message"])
                keyboard = confirmed["reply_markup"]["inline_keyboard"]
                self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Key Status", "Delete another key"], ["Menu"]])
                self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["after:menu:key_status", "after:menu:key_delete"], ["after:menu:back"]])
                self.assertNotIn(key, confirmed["text"])
                write_config.assert_called_once_with([])
                self.assertEqual(save_quotas.call_args.args[0]["keys"], [])
                soft_delete.assert_called_once_with(key)
                saved_state = save_state.call_args.args[0]
                self.assertEqual(saved_state["disabled_by_quota"], [])
                self.assertEqual(saved_state["manually_disabled_keys"], [])
                self.assertEqual(saved_state["cpa_deleted_while_quota_disabled"], [])

    def test_simple_quota_button_uses_cached_snapshot_not_live_refresh(self):
        state = {"snapshot": {"created_at": 1, "quota_error": "", "quota_rows": []}}
        with mock.patch("telegram_alerts.handlers.get_snapshot") as get_snapshot:
            get_snapshot.return_value = state["snapshot"]
            result = handle_callback("menu:quota", state, chat_id="chat", user_id="user", message_id=1)

        get_snapshot.assert_called_once_with(state, live=False, interactive=True)
        self.assertTrue(result["edit_message"])

    def test_errors_today_reply_excludes_management_noise_when_no_proxy_errors(self):
        latest_mtime = int(datetime(2026, 6, 10, 11, 49, 50, tzinfo=timezone.utc).timestamp())
        events = [
            {
                "file": "main.log",
                "raw": "main.log: 401 management call",
                "mtime": latest_mtime,
                "status": 401,
                "method": "GET",
                "endpoint": "/v0/management/api-call",
                "ip": "127.0.0.1",
            },
            {
                "file": "main.log",
                "raw": "main.log: 401 management auth files",
                "mtime": latest_mtime,
                "status": 401,
                "method": "GET",
                "endpoint": "/v0/management/auth-files",
                "ip": "127.0.0.1",
            },
        ]

        with mock.patch.object(logs_module, "recent_error_events", return_value=events), \
             mock.patch.object(logs_module, "local_tz_name", return_value="Asia/Ho_Chi_Minh"), \
             mock.patch.object(logs_module, "usage_request_summary_today", return_value={"total": 4430, "failed": 275, "failed_rate": 6.21}):
            text = logs_module.build_errors_reply("all")

        self.assertIn("- CPA failed: 275 / 4,430 (6.21%)", text)
        self.assertIn("- Proxy HTTP failures: 0", text)
        self.assertIn("- Latest error: 18:49:50", text)
        self.assertNotIn("- latest: 18:49:50", text)
        self.assertIn("- No proxy traffic errors in recent logs", text)
        self.assertIn("- If failures keep rising, check provider/upstream or docker logs.", text)
        self.assertNotIn("/v0/management/api-call", text)
        self.assertNotIn("/v0/management/auth-files", text)
        self.assertNotIn("401 Unauthorized", text)
        self.assertNotIn("401/403 means", text)

    def test_errors_today_reply_includes_proxy_traffic_and_uses_proxy_latest_time(self):
        proxy_mtime = int(datetime(2026, 6, 10, 11, 49, 50, tzinfo=timezone.utc).timestamp())
        management_mtime = int(datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc).timestamp())
        events = []
        for _ in range(44):
            events.append({
                "file": "main.log",
                "raw": "main.log: 502 upstream failed",
                "mtime": proxy_mtime,
                "status": 502,
                "method": "POST",
                "endpoint": "/v1/messages",
                "ip": "116.111.184.70",
            })
        events.extend([
            {
                "file": "main.log",
                "raw": "main.log: 401 management call",
                "mtime": management_mtime,
                "status": 401,
                "method": "GET",
                "endpoint": "/v0/management/api-call",
                "ip": "127.0.0.1",
            },
            {
                "file": "main.log",
                "raw": "main.log: warning line",
                "mtime": management_mtime,
                "status": None,
                "method": "",
                "endpoint": "",
                "ip": "",
            },
        ])

        with mock.patch.object(logs_module, "recent_error_events", return_value=events), \
             mock.patch.object(logs_module, "local_tz_name", return_value="Asia/Ho_Chi_Minh"), \
             mock.patch.object(logs_module, "usage_request_summary_today", return_value={"total": 4430, "failed": 275, "failed_rate": 6.21}):
            text = logs_module.build_errors_reply("all")

        lines = text.splitlines()
        self.assertEqual(lines[0], "Errors Today")
        self.assertIn("Summary", text)
        self.assertIn("Breakdown", text)
        self.assertIn("Action", text)
        self.assertIn("- CPA failed: 275 / 4,430 (6.21%)", text)
        self.assertIn("- Proxy HTTP failures: 44", text)
        self.assertIn("- Latest error: 18:49:50", text)
        self.assertNotIn("- latest: 18:49:50", text)
        self.assertIn("- Status: 502 Bad Gateway x44", text)
        self.assertIn("- Endpoint: POST /v1/messages x44", text)
        self.assertIn("- 502 means upstream call failed after reaching cliproxy.", text)
        self.assertIn("- If failures keep rising, check provider/upstream or docker logs.", text)
        latest_line = next(line for line in lines if line.startswith("- Latest error:"))
        self.assertNotIn("2026-", latest_line)
        self.assertNotIn("+07", latest_line)
        for old in (
            "log signals",
            "source IP",
            "log file",
            "Latest log update:",
            "HTTP Status:",
            "Top Endpoints:",
            "Top Source IPs:",
            "Log Files:",
            "Meaning:",
            "Note:",
            "Suggested Action:",
            "if CPA failed keeps rising",
            "/v0/management/api-call",
            "401 Unauthorized",
        ):
            with self.subTest(old=old):
                self.assertNotIn(old, text)
        self.assertNotIn("Cliproxy: errors today", text)
        self.assertNotIn("personal-cliproxy errors: all", text)

    def test_errors_today_cliproxy_429_renders_backend_upstream_attribution(self):
        events = [{
            "file": "main.log",
            "raw": "main.log: 429 | sk-secret123 | 127.0.0.1 | POST \"/v1/chat/completions\" Bearer secret-token cookie=session-secret",
            "mtime": int(datetime(2026, 6, 13, 5, 2, 4, tzinfo=timezone.utc).timestamp()),
            "status": 429,
            "method": "POST",
            "endpoint": "/v1/chat/completions",
            "ip": "127.0.0.1",
        }]

        with mock.patch.object(logs_module, "recent_error_events", return_value=events), \
             mock.patch.object(logs_module, "local_tz_name", return_value="Asia/Ho_Chi_Minh"), \
             mock.patch.object(logs_module, "usage_request_summary_today", return_value={"total": 1, "failed": 1, "failed_rate": 100.0}):
            text = logs_module.build_errors_reply("all")

        self.assertIn("- Status: 429 Backend/Upstream Rate Limited x1", text)
        self.assertNotIn("- Status: 429 Rate Limited x1", text)
        self.assertIn("- 429 came from backend/upstream; check provider/account throttling, model concurrency, or account rotation.", text)
        self.assertNotIn("sk-secret123", text)
        self.assertNotIn("secret-token", text)
        self.assertNotIn("session-secret", text)

    def test_errors_today_nginx_429_with_empty_upstream_status_renders_frontdoor_attribution(self):
        events = [{
            "file": "cliproxy_v1_timing.log",
            "raw": "cliproxy_v1_timing.log: status=429 us=\"-\" path=\"/v1/chat/completions\"",
            "mtime": int(datetime(2026, 6, 13, 5, 2, 4, tzinfo=timezone.utc).timestamp()),
            "status": 429,
            "method": "POST",
            "endpoint": "/v1/chat/completions",
            "ip": "127.0.0.1",
            "us": "-",
        }]

        with mock.patch.object(logs_module, "recent_error_events", return_value=events), \
             mock.patch.object(logs_module, "local_tz_name", return_value="Asia/Ho_Chi_Minh"), \
             mock.patch.object(logs_module, "usage_request_summary_today", return_value={"total": 1, "failed": 1, "failed_rate": 100.0}):
            text = logs_module.build_errors_reply("all")

        self.assertIn("- Status: 429 Nginx/Frontdoor Rate Limited x1", text)
        self.assertNotIn("- Status: 429 Rate Limited x1", text)
        self.assertIn("- 429 came from nginx/frontdoor; check rate/connection limits and client burstiness.", text)

    def test_errors_today_nginx_429_with_upstream_429_renders_backend_upstream_attribution(self):
        events = [{
            "file": "cliproxy_v1_timing.log",
            "raw": "cliproxy_v1_timing.log: status=429 us=\"429\" path=\"/v1/chat/completions\"",
            "mtime": int(datetime(2026, 6, 13, 5, 2, 4, tzinfo=timezone.utc).timestamp()),
            "status": 429,
            "method": "POST",
            "endpoint": "/v1/chat/completions",
            "ip": "127.0.0.1",
            "upstream_status": "429",
        }]

        with mock.patch.object(logs_module, "recent_error_events", return_value=events), \
             mock.patch.object(logs_module, "local_tz_name", return_value="Asia/Ho_Chi_Minh"), \
             mock.patch.object(logs_module, "usage_request_summary_today", return_value={"total": 1, "failed": 1, "failed_rate": 100.0}):
            text = logs_module.build_errors_reply("all")

        self.assertIn("- Status: 429 Backend/Upstream Rate Limited x1", text)
        self.assertNotIn("- Status: 429 Rate Limited x1", text)
        self.assertIn("- 429 came from backend/upstream; check provider/account throttling, model concurrency, or account rotation.", text)

    def test_errors_today_502_behavior_remains_unchanged(self):
        events = [{
            "file": "main.log",
            "raw": "main.log: 502 upstream failed",
            "mtime": int(datetime(2026, 6, 13, 5, 2, 4, tzinfo=timezone.utc).timestamp()),
            "status": 502,
            "method": "POST",
            "endpoint": "/v1/messages",
            "ip": "127.0.0.1",
        }]

        with mock.patch.object(logs_module, "recent_error_events", return_value=events), \
             mock.patch.object(logs_module, "local_tz_name", return_value="Asia/Ho_Chi_Minh"), \
             mock.patch.object(logs_module, "usage_request_summary_today", return_value={"total": 1, "failed": 1, "failed_rate": 100.0}):
            text = logs_module.build_errors_reply("all")

        self.assertIn("- Status: 502 Bad Gateway x1", text)
        self.assertIn("- 502 means upstream call failed after reaching cliproxy.", text)
        self.assertIn("- If failures keep rising, check provider/upstream or docker logs.", text)

    def test_errors_today_callback_uses_exact_keyboard_layout(self):
        with mock.patch("telegram_alerts.handlers.build_errors_reply", return_value="Errors Today\nbody"):
            result = handle_callback("menu:errors", {}, chat_id="chat", user_id="user", message_id=1)

        self.assertTrue(result["edit_message"])
        self.assertEqual(result["text"].splitlines()[0], "Errors Today")
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Menu", "Refresh"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["menu:back", "menu:errors_refresh"]])
        self.assertNotIn("Raw logs", str(result["reply_markup"]))

    def test_errors_today_refresh_reloads_errors_today(self):
        with mock.patch("telegram_alerts.handlers.build_errors_reply", return_value="Errors Today\nbody") as build_errors_reply:
            result = handle_callback("menu:errors_refresh", {}, chat_id="chat", user_id="user", message_id=1)

        build_errors_reply.assert_called_once_with("all")
        self.assertTrue(result["edit_message"])
        self.assertEqual(result["text"].splitlines()[0], "Errors Today")
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Menu", "Refresh"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["menu:back", "menu:errors_refresh"]])

    def test_cleared_legacy_callback_aliases_return_unknown_button_action(self):
        for callback in ("menu:accounts", "menu:accounts_refresh", "menu:raw_logs", "menu:raw_logs_refresh"):
            with self.subTest(callback=callback), \
                 mock.patch("telegram_alerts.handlers.build_errors_reply", return_value="Errors Today\nbody") as build_errors_reply:
                result = handle_callback(callback, {}, chat_id="chat", user_id="user", message_id=1)

            build_errors_reply.assert_not_called()
            self.assertEqual(result, "Unknown button action.")

    def test_stale_headers_are_absent_from_representative_messages(self):
        with mock.patch.object(snapshot_module, "hours_until_week_end", return_value=100.0):
            capacity_text = snapshot_module.build_capacity_reply(self.capacity_snapshot(), self.capacity_rate())
        top_text = snapshot_module.build_top_reply({
            "created_at": 0,
            "quota_error": "",
            "quota_rows": [{"alias": "alice", "status": "active", "daily_used": 1, "daily_limit": 10}],
        })
        key_status_text = snapshot_module.build_key_status_reply({"created_at": 0, "quota_error": "", "quota_rows": []})
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(snapshot_module, "AUTH_DIR", Path(tmp), create=True), \
             mock.patch.object(snapshot_module, "auth_management_quota_left_by_ref", return_value={}):
            overview_text = build_overview_reply({
                "created_at": 0,
                "service_lines": [],
                "system_alerts": {},
                "quota_signals": {},
                "quota_rows": [],
                "enforcer_age": "0s",
            })
            quota_management_text = build_quota_management_reply({"created_at": 0})
        health_text = build_alerts_reply({
            "created_at": 0,
            "system_alerts": {
                "service:cliproxy": {
                    "alert_id": "service:cliproxy",
                    "severity": "critical",
                    "title": "cliproxy is not reachable",
                    "body": "connect failed",
                    "fingerprint": "unreachable",
                }
            },
        })
        with mock.patch.object(logs_module, "recent_error_events", return_value=[]), \
             mock.patch.object(logs_module, "usage_request_summary_today", return_value={"total": 0, "failed": 0, "failed_rate": 0.0}):
            errors_text = logs_module.build_errors_reply("all")
        with mock.patch("telegram_alerts.pickers.key_accounts_for_picker", return_value=[{"alias": "alice", "key": "alice-secret-key"}]), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker1"):
            show_key_text = prompt_key_reveal_picker({}, chat_id="chat", user_id="user")["text"]
        with mock.patch("telegram_alerts.pickers.usage_accounts_for_picker", return_value=("Asia/Ho_Chi_Minh", [{"alias": "alice", "key": "alice-key"}])), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker2"):
            usage_picker_text = prompt_usage_picker({}, chat_id="chat", user_id="user")["text"]
        with mock.patch("telegram_alerts.pickers.quota_accounts_for_picker", return_value=[{"alias": "alice", "key": "alice-key"}]), \
             mock.patch("telegram_alerts.pickers.short_code", return_value="picker3"):
            edit_quota_text = prompt_quota_picker({}, chat_id="chat", user_id="user")["text"]

        combined_text = "\n".join([
            capacity_text,
            top_text,
            key_status_text,
            overview_text,
            quota_management_text,
            health_text,
            errors_text,
            show_key_text,
            usage_picker_text,
            edit_quota_text,
            settings_module.MESSAGES["key_create_prompt"],
        ])

        stale = [
            "Capacity check: personal-cliproxy",
            "personal-cliproxy top token users today",
            "Cliproxy: Overview",
            "Cliproxy: Capacity Check",
            "Cliproxy: Key Status",
            "Cliproxy: key status",
            "Cliproxy: Top Users",
            "Cliproxy: Usage",
            "Cliproxy: Quota Management",
            "Cliproxy: Health Alerts",
            "Cliproxy: Errors Today",
            "personal-cliproxy: 1 active health alert",
            "Cliproxy: errors today",
            "Cliproxy: Show Key",
            "Cliproxy: Edit Quota",
            "Cliproxy: Create Key",
            "Create API key",
            "personal-cliproxy raw warning/error logs",
            "Usage report",
            "Open Errors today for recent failed requests and raw log signals.",
            "Cliproxy: Raw Logs",
            "Data: warning/error logs, all",
            "snapshot: snapshot",
        ]
        for old in stale:
            with self.subTest(old=old):
                self.assertNotIn(old, combined_text)
        representative_headers = {
            "Overview": overview_text.splitlines()[0],
            "Capacity Check": capacity_text.splitlines()[0],
            "Key Status": key_status_text.splitlines()[0],
            "Top Users": top_text.splitlines()[0],
            "Usage": usage_picker_text.splitlines()[0],
            "Quota Management": quota_management_text.splitlines()[0],
            "Health Alerts": health_text.splitlines()[0],
            "Errors Today": errors_text.splitlines()[0],
            "Show Key": show_key_text.splitlines()[0],
            "Edit Quota": edit_quota_text.splitlines()[0],
            "Create Key": settings_module.MESSAGES["key_create_prompt"].splitlines()[0],
        }
        self.assertEqual(representative_headers["Overview"], "System Overview")
        for screen, header in representative_headers.items():
            with self.subTest(screen=screen):
                self.assertFalse(header.startswith("Cliproxy:"), header)
        for new in ("Usage", "Quota Management", "Capacity Check", "System Overview"):
            with self.subTest(new=new):
                self.assertIn(new, combined_text)

    def test_capacity_screen_uses_dedicated_refresh_callback(self):
        state = {"capacity_check_snapshot": {"created_at": 1, "quota_error": "", "quota_rows": []}}
        with mock.patch("telegram_alerts.handlers.get_capacity_check_snapshot", return_value=state["capacity_check_snapshot"]) as get_snapshot:
            result = handle_callback("menu:capacity", state, chat_id="chat", user_id="user", message_id=1)

        get_snapshot.assert_called_once_with(state, live=False)
        keyboard = result["reply_markup"]["inline_keyboard"]
        self.assertEqual([[button["text"] for button in row] for row in keyboard], [["Menu", "Refresh"]])
        self.assertEqual([[button["callback_data"] for button in row] for row in keyboard], [["menu:back", "menu:capacity_refresh"]])
        callbacks = [button["callback_data"] for row in keyboard for button in row]
        self.assertIn("menu:capacity_refresh", callbacks)
        self.assertNotIn("menu:refresh", callbacks)
        self.assertTrue(result["edit_message"])

    def test_capacity_normal_tap_uses_cached_demand_rate_without_live_realtime_call(self):
        cached = self.capacity_snapshot(pool=self.capacity_pool(checked=10, enabled=10), rows=self.healthy_user_key_rows(), created_at=1_000)
        cached["capacity_check_demand_rate"] = self.capacity_rate(hourly=1_000_000)
        state = {"capacity_check_snapshot": cached}

        with mock.patch("telegram_alerts.handlers.get_capacity_check_snapshot", return_value=cached) as get_snapshot, \
             mock.patch("telegram_alerts.handlers.capacity_demand_rate_estimate", side_effect=AssertionError("live demand should not run")):
            result = handle_callback("menu:capacity", state, chat_id="chat", user_id="user", message_id=1)

        get_snapshot.assert_called_once_with(state, live=False)
        self.assertIn("Demand rate: 1.0M/h", result["text"])

    def test_capacity_refresh_updates_cached_demand_rate_from_live_realtime_call(self):
        fresh = self.capacity_snapshot(pool=self.capacity_pool(checked=10, enabled=10), rows=self.healthy_user_key_rows(), created_at=1_061)
        state = {}

        with mock.patch("telegram_alerts.handlers.get_capacity_check_snapshot", return_value=fresh), \
             mock.patch("telegram_alerts.handlers.capacity_demand_rate_estimate", return_value=self.capacity_rate(hourly=3_000_000)) as demand:
            result = handle_callback("menu:capacity_refresh", state, chat_id="chat", user_id="user", message_id=1)

        demand.assert_called_once()
        self.assertIs(fresh["capacity_check_demand_rate"], demand.return_value)
        self.assertIn("Demand rate: 3.0M/h", result["text"])

    def test_capacity_check_uses_recent_cached_snapshot_when_fresh(self):
        cached = self.capacity_snapshot(pool=self.capacity_pool(checked=10, enabled=10), rows=self.healthy_user_key_rows(), created_at=1_000)
        state = {"capacity_check_snapshot": cached}

        with mock.patch.object(snapshot_module, "now_ts", return_value=1_030), \
             mock.patch.object(snapshot_module, "build_snapshot") as build_snapshot:
            snapshot = snapshot_module.get_capacity_check_snapshot(state, live=False)

        build_snapshot.assert_not_called()
        self.assertIs(snapshot, cached)

    def test_interactive_build_snapshot_skips_disabled_auth_cache_health_probe(self):
        with mock.patch.object(snapshot_module, "check_http_services_detailed", return_value=[]), \
             mock.patch.object(snapshot_module, "collect_alerts_with_auth_observation", return_value=({}, auth_observation())) as collect_alerts, \
             mock.patch.object(snapshot_module, "load_quota_context", return_value={}), \
             mock.patch.object(snapshot_module, "quota_alerts_from_context", return_value=[]), \
             mock.patch.object(snapshot_module, "quota_rows_from_context", return_value=[]), \
             mock.patch.object(snapshot_module, "gpt_pool_capacity_snapshot", return_value=self.capacity_pool(checked=10, enabled=10)), \
             mock.patch.object(snapshot_module, "usage_rate_estimate", return_value={"tokens_per_hour": 1, "error": ""}):
            snapshot_module.build_snapshot(interactive=True)

        self.assertEqual(collect_alerts.call_args.kwargs.get("include_cached_disabled_auth"), False)

    def test_capacity_check_rebuilds_when_cached_snapshot_is_stale(self):
        fresh = self.capacity_snapshot(pool=self.capacity_pool(checked=10, enabled=10), rows=self.healthy_user_key_rows(), created_at=1_061)
        state = {"capacity_check_snapshot": self.capacity_snapshot(pool=self.capacity_pool(checked=9, enabled=10), rows=self.healthy_user_key_rows(), created_at=1_000)}

        with mock.patch.object(snapshot_module, "now_ts", return_value=1_061), \
             mock.patch.object(snapshot_module, "build_snapshot", return_value=fresh) as build_snapshot:
            snapshot = snapshot_module.get_capacity_check_snapshot(state, live=False)

        build_snapshot.assert_called_once()
        self.assertIs(snapshot, fresh)
        self.assertIs(state["capacity_check_snapshot"], fresh)

    def test_capacity_check_rebuild_uses_cached_auth_state_without_refresh_retry_or_fallback(self):
        fresh = self.capacity_snapshot(pool=self.capacity_pool(checked=9, enabled=9), rows=self.healthy_user_key_rows(), created_at=1_061)
        auth_state = {
            "raw_current_complete": True,
            "last_complete_at": 1_050,
            "failed_auth_index_keys": ["abcdef1234567890"],
        }
        state = {
            "auth_quota_inspection": auth_state,
            "capacity_check_recent_gpt_pool": {"created_at": 1_000, "identities": {}},
        }

        with mock.patch.object(snapshot_module, "now_ts", return_value=1_061), \
             mock.patch.object(snapshot_module, "build_snapshot", return_value=fresh) as build_snapshot, \
             mock.patch.object(snapshot_module.time, "sleep") as sleep:
            snapshot = snapshot_module.get_capacity_check_snapshot(state, live=True)

        build_snapshot.assert_called_once_with(
            interactive=True,
            auth_refresh_before_check=False,
            auth_wait_for_refresh=False,
            auth_inspection_state=auth_state,
            gpt_pool_management_fallback=False,
            gpt_pool_recent_cache=state["capacity_check_recent_gpt_pool"],
            gpt_pool_recent_cache_max_age_seconds=snapshot_module.CAPACITY_CHECK_FAST_CACHE_SECONDS,
        )
        sleep.assert_not_called()
        self.assertIs(snapshot, fresh)

    def test_interactive_capacity_retry_returns_complete_gpt_coverage_before_rendering(self):
        incomplete = self.capacity_snapshot(pool=self.capacity_pool(checked=7, enabled=10), rows=self.healthy_user_key_rows())
        complete = self.capacity_snapshot(pool=self.capacity_pool(checked=10, enabled=10), rows=self.healthy_user_key_rows())
        state = {"snapshot": incomplete}

        with mock.patch.object(snapshot_module, "get_snapshot", side_effect=[incomplete, complete]) as get_snapshot, \
             mock.patch.object(snapshot_module.time, "monotonic", side_effect=[0.0, 0.0, 1.0]), \
             mock.patch.object(snapshot_module.time, "sleep") as sleep:
            snapshot = snapshot_module.snapshot_with_complete_gpt_pool(
                state,
                live=True,
                interactive=True,
                auth_refresh_before_check=False,
                auth_wait_for_refresh=False,
                timeout_seconds=6.0,
                interval_seconds=1.0,
            )

        self.assertIs(snapshot, complete)
        self.assertEqual(get_snapshot.call_count, 2)
        sleep.assert_called_once_with(1.0)
        text = snapshot_module.build_capacity_reply(snapshot, self.capacity_rate(hourly=1_000_000))
        self.assertIn("5h avail: 145.4M\n(avg: 72.7%, lowest: 60%)", text)
        self.assertNotIn("Quota data updating", text)
        self.assertNotIn("10/10", text)

    def test_interactive_capacity_retry_falls_back_to_updating_after_timeout(self):
        incomplete = self.capacity_snapshot(pool=self.capacity_pool(checked=7, enabled=10), rows=self.healthy_user_key_rows())
        state = {"snapshot": incomplete}

        with mock.patch.object(snapshot_module, "get_snapshot", return_value=incomplete) as get_snapshot, \
             mock.patch.object(snapshot_module.time, "monotonic", side_effect=[0.0, 7.0]), \
             mock.patch.object(snapshot_module.time, "sleep") as sleep:
            snapshot = snapshot_module.snapshot_with_complete_gpt_pool(
                state,
                live=True,
                interactive=True,
                auth_refresh_before_check=False,
                auth_wait_for_refresh=False,
                timeout_seconds=6.0,
                interval_seconds=1.0,
            )

        self.assertIs(snapshot, incomplete)
        self.assertEqual(get_snapshot.call_count, 1)
        sleep.assert_not_called()
        text = snapshot_module.build_capacity_reply(snapshot, self.capacity_rate(hourly=1_000_000))
        self.assertIn("Quota data updating: 7/10 with 5h data, 7/10 with weekly data", text)

    def test_interactive_capacity_does_not_wait_for_partial_weekly_cache(self):
        pool = self.capacity_pool(checked=10, enabled=10)
        pool["secondary"]["checked_count"] = 9
        pool["secondary"]["left_tokens"] = round(pool["secondary"]["avg_left_percent"] / 100.0 * 140_000_000 * 9, 1)
        pool["usage_keeper_checked_count"] = 9
        pool["missing_rows_count"] = 1
        incomplete = self.capacity_snapshot(pool=pool, rows=self.healthy_user_key_rows())
        state = {"snapshot": incomplete}

        with mock.patch.object(snapshot_module, "get_snapshot", side_effect=[incomplete, incomplete]) as get_snapshot, \
             mock.patch.object(snapshot_module.time, "monotonic", side_effect=[0.0, 0.0, 7.0]), \
             mock.patch.object(snapshot_module.time, "sleep") as sleep:
            snapshot = snapshot_module.snapshot_with_complete_gpt_pool(
                state,
                live=True,
                interactive=True,
                auth_refresh_before_check=False,
                auth_wait_for_refresh=False,
                timeout_seconds=0.0,
                interval_seconds=1.0,
            )

        self.assertIs(snapshot, incomplete)
        self.assertEqual(get_snapshot.call_count, 1)
        sleep.assert_not_called()
        text = snapshot_module.build_capacity_reply(snapshot, self.capacity_rate(hourly=1_000_000))
        self.assertIn("Quota data updating: 10/10 with 5h data, 9/10 with weekly data", text)

    def test_background_snapshot_does_not_retry_gpt_pool_coverage(self):
        incomplete = self.capacity_pool(checked=7, enabled=10)
        with mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({}, auth_observation(healthy=["acct-ok"]))), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value={}), \
             mock.patch("telegram_alerts.snapshot.quota_alerts_from_context", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.quota_rows_from_context", return_value=self.healthy_user_key_rows()), \
             mock.patch("telegram_alerts.snapshot.gpt_pool_capacity_snapshot", return_value=incomplete) as gpt_pool, \
             mock.patch.object(snapshot_module.time, "sleep") as sleep:
            built = snapshot_module.build_snapshot(interactive=False)

        self.assertEqual(gpt_pool.call_count, 1)
        sleep.assert_not_called()
        self.assertEqual(built["gpt_pool_capacity"], incomplete)

    def test_capacity_refresh_renders_without_retry_or_management_fallback(self):
        state = {"capacity_check_snapshot": {"created_at": 1, "quota_error": "", "quota_rows": []}}
        with mock.patch("telegram_alerts.handlers.get_capacity_check_snapshot", return_value=state["capacity_check_snapshot"]) as get_snapshot:
            result = handle_callback("menu:capacity_refresh", state, chat_id="chat", user_id="user", message_id=1)

        get_snapshot.assert_called_once_with(state, live=True)
        self.assertIn("Capacity Check", result["text"])
        self.assertNotIn("Cliproxy:", result["text"])
        self.assertTrue(result["edit_message"])

    def test_first_start_opens_inline_control_panel_and_marks_initialized(self):
        state = {"snapshot": {"created_at": 1, "quota_error": "", "service_lines": [], "system_alerts": {}, "quota_signals": {}, "quota_rows": []}}
        with mock.patch("telegram_alerts.handlers.delete_telegram_message_async") as delete_message, \
             mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]) as get_snapshot:
            result = handle_command("/start", state, chat_id="chat", user_id="user", message_id=1)

        delete_message.assert_called_once_with("chat", 1)
        get_snapshot.assert_called_once_with(state, live=False, interactive=True)
        self.assertNotIn("remove_keyboard", result)
        self.assertTrue(state["start_initialized"]["chat:user"])
        labels = [button["text"] for row in result["reply_markup"]["inline_keyboard"] for button in row]
        self.assertIn("Capacity Check", labels)
        self.assertIn("Key Status", labels)
        self.assertNotIn("Show key", labels)
        self.assertNotIn("Accounts", labels)
        self.assertNotIn("Quota warnings", labels)

    def test_second_start_is_silent_and_does_not_open_menu(self):
        state = {"start_initialized": {"chat:user": True}}
        with mock.patch("telegram_alerts.handlers.delete_telegram_message_async") as delete_message, \
             mock.patch("telegram_alerts.handlers.get_snapshot") as get_snapshot:
            result = handle_command("/start", state, chat_id="chat", user_id="user", message_id=2)

        delete_message.assert_called_once_with("chat", 2)
        get_snapshot.assert_not_called()
        self.assertEqual(result, {"skip_send": True})
        self.assertTrue(state["start_initialized"]["chat:user"])

    def test_start_after_clear_opens_menu_once_and_consumes_flag(self):
        state = {
            "snapshot": {"created_at": 1, "quota_error": "", "service_lines": [], "system_alerts": {}, "quota_signals": {}, "quota_rows": []},
            "start_initialized": {"chat:user": True},
            "start_menu_once_after_clear": {"chat:user": True},
        }
        with mock.patch("telegram_alerts.handlers.delete_telegram_message_async") as delete_message, \
             mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]) as get_snapshot:
            result = handle_command("/start", state, chat_id="chat", user_id="user", message_id=3)

        delete_message.assert_called_once_with("chat", 3)
        get_snapshot.assert_called_once_with(state, live=False, interactive=True)
        self.assertNotIn("remove_keyboard", result)
        self.assertEqual(state.get("start_menu_once_after_clear"), {})
        self.assertTrue(state["start_initialized"]["chat:user"])
        labels = [button["text"] for row in result["reply_markup"]["inline_keyboard"] for button in row]
        self.assertIn("Capacity Check", labels)

        with mock.patch("telegram_alerts.handlers.delete_telegram_message_async") as second_delete, \
             mock.patch("telegram_alerts.handlers.get_snapshot") as second_get_snapshot:
            second = handle_command("/start", state, chat_id="chat", user_id="user", message_id=4)

        second_delete.assert_called_once_with("chat", 4)
        second_get_snapshot.assert_not_called()
        self.assertEqual(second, {"skip_send": True})

    def test_start_during_pending_flow_stays_silent_and_preserves_start_flags(self):
        state = {
            "pending_inputs": {"chat:user": {"expires_at": 99_999_999_999}},
            "start_initialized": {"chat:user": True},
            "start_menu_once_after_clear": {"chat:user": True},
        }
        with mock.patch("telegram_alerts.handlers.delete_telegram_message_async") as delete_message, \
             mock.patch("telegram_alerts.handlers.get_snapshot") as get_snapshot:
            result = handle_command("/start", state, chat_id="chat", user_id="user", message_id=1)

        delete_message.assert_called_once_with("chat", 1)
        get_snapshot.assert_not_called()
        self.assertEqual(result, {"skip_send": True})
        self.assertEqual(state["start_menu_once_after_clear"], {"chat:user": True})
        self.assertIn("chat:user", state["pending_inputs"])

    def test_menu_command_opens_inline_control_panel_without_keyboard_cleanup(self):
        state = {"snapshot": {"created_at": 1, "quota_error": "", "service_lines": [], "system_alerts": {}, "quota_signals": {}, "quota_rows": []}}
        with mock.patch("telegram_alerts.handlers.delete_telegram_message_async") as delete_message, \
             mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]) as get_snapshot:
            result = handle_command("/menu", state, chat_id="chat", user_id="user", message_id=5)

        delete_message.assert_called_once_with("chat", 5)
        get_snapshot.assert_called_once_with(state, live=False, interactive=True)
        self.assertNotIn("remove_keyboard", result)
        labels = [button["text"] for row in result["reply_markup"]["inline_keyboard"] for button in row]
        self.assertIn("Capacity Check", labels)
        self.assertIn("Key Status", labels)
        self.assertNotIn("Show key", labels)
        self.assertNotIn("Accounts", labels)
        self.assertNotIn("Quota warnings", labels)

    def test_menu_command_replaces_previous_menu_messages_only(self):
        state = {
            "telegram_offset": 1,
            "menu_messages": {"chat": [10, 11]},
            "known_messages": {"chat": [10, 11, 99]},
            "snapshot": {"created_at": 1, "quota_error": "", "service_lines": [], "system_alerts": {}, "quota_signals": {}, "quota_rows": []},
        }
        update = {
            "update_id": 7,
            "message": {
                "message_id": 50,
                "text": "/menu",
                "chat": {"id": "chat"},
                "from": {"id": "user"},
            },
        }

        with mock.patch("telegram_alerts.handlers.TELEGRAM_BOT_TOKEN", "token"), \
             mock.patch("telegram_alerts.handlers.allowed_chat_ids", return_value={"chat"}), \
             mock.patch("telegram_alerts.handlers.allowed_user_ids", return_value={"user"}), \
             mock.patch("telegram_alerts.handlers.is_authorized", return_value=True), \
             mock.patch("telegram_alerts.handlers.telegram_get_updates", return_value=[update]), \
             mock.patch("telegram_alerts.handlers.delete_telegram_message_async") as delete_message, \
             mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]), \
             mock.patch("telegram_alerts.handlers.send_reply", return_value=[{"chat_id": "chat", "message_id": 100}]):
            handled = process_commands(state)

        self.assertEqual(handled, 1)
        self.assertEqual(state["menu_messages"]["chat"], [100])
        self.assertIn(99, state["known_messages"]["chat"])
        delete_calls = [call.args for call in delete_message.call_args_list]
        self.assertIn(("chat", 50), delete_calls)
        self.assertIn(("chat", 10), delete_calls)
        self.assertIn(("chat", 11), delete_calls)
        self.assertNotIn(("chat", 99), delete_calls)

    def test_menu_button_replaces_previous_menu_messages_and_tracks_edited_menu(self):
        state = {
            "telegram_offset": 1,
            "menu_messages": {"chat": [10, 11, 20]},
            "known_messages": {"chat": [10, 11, 20, 99]},
            "snapshot": {"created_at": 1, "quota_error": "", "service_lines": [], "system_alerts": {}, "quota_signals": {}, "quota_rows": []},
        }
        update = {
            "update_id": 7,
            "callback_query": {
                "id": "cb1",
                "data": "menu:back",
                "from": {"id": "user"},
                "message": {
                    "message_id": 20,
                    "chat": {"id": "chat"},
                },
            },
        }

        with mock.patch("telegram_alerts.handlers.TELEGRAM_BOT_TOKEN", "token"), \
             mock.patch("telegram_alerts.handlers.allowed_chat_ids", return_value={"chat"}), \
             mock.patch("telegram_alerts.handlers.allowed_user_ids", return_value={"user"}), \
             mock.patch("telegram_alerts.handlers.is_authorized", return_value=True), \
             mock.patch("telegram_alerts.handlers.telegram_get_updates", return_value=[update]), \
             mock.patch("telegram_alerts.handlers.answer_callback_query_async"), \
             mock.patch("telegram_alerts.handlers.delete_telegram_message_async") as delete_message, \
             mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]), \
             mock.patch("telegram_alerts.handlers.edit_telegram_message_result", return_value={"ok": True, "reason": "ok"}):
            handled = process_commands(state)

        self.assertEqual(handled, 1)
        self.assertEqual(state["menu_messages"]["chat"], [20])
        self.assertIn(99, state["known_messages"]["chat"])
        delete_calls = [call.args for call in delete_message.call_args_list]
        self.assertIn(("chat", 10), delete_calls)
        self.assertIn(("chat", 11), delete_calls)
        self.assertNotIn(("chat", 20), delete_calls)
        self.assertNotIn(("chat", 99), delete_calls)

    def test_after_confirm_button_deletes_success_message_and_sends_next_screen(self):
        state = {"telegram_offset": 1}
        update = {
            "update_id": 7,
            "callback_query": {
                "id": "cb1",
                "data": "after:menu:key_create",
                "from": {"id": "user"},
                "message": {
                    "message_id": 77,
                    "chat": {"id": "chat"},
                },
            },
        }

        with mock.patch("telegram_alerts.handlers.TELEGRAM_BOT_TOKEN", "token"), \
             mock.patch("telegram_alerts.handlers.allowed_chat_ids", return_value={"chat"}), \
             mock.patch("telegram_alerts.handlers.allowed_user_ids", return_value={"user"}), \
             mock.patch("telegram_alerts.handlers.is_authorized", return_value=True), \
             mock.patch("telegram_alerts.handlers.telegram_get_updates", return_value=[update]), \
             mock.patch("telegram_alerts.handlers.answer_callback_query_async"), \
             mock.patch("telegram_alerts.handlers.delete_telegram_message_async") as delete_message, \
             mock.patch("telegram_alerts.handlers.edit_telegram_message_result") as edit_message, \
             mock.patch("telegram_alerts.handlers.send_reply", return_value=[{"chat_id": "chat", "message_id": 100}]) as send:
            handled = process_commands(state)

        self.assertEqual(handled, 1)
        delete_message.assert_called_once_with("chat", 77)
        edit_message.assert_not_called()
        self.assertEqual(send.call_args.args[0]["text"], settings_module.MESSAGES["key_create_prompt"])

    def test_clear_command_still_runs_background_cleanup_and_sets_start_once_flag(self):
        state = {"known_messages": {"chat": [1, 2, 3]}, "start_initialized": {"chat:user": True}}
        with mock.patch("telegram_alerts.handlers.start_clear_chat_messages") as clear:
            result = handle_command("/clear 20", state, chat_id="chat", user_id="user", message_id=9)

        clear.assert_called_once_with("chat", 9, 20, ready_message=None, known_message_ids=[1, 2, 3])
        self.assertTrue(result.get("skip_send"))
        self.assertTrue(result.get("remove_keyboard"))
        self.assertEqual(state["known_messages"]["chat"], [])
        self.assertTrue(state["start_menu_once_after_clear"]["chat:user"])

    def test_clear_command_without_count_and_all_still_run_background_cleanup(self):
        for command in ("/clear", "/clear all"):
            state = {"known_messages": {"chat": [1, 2, 3]}}
            with self.subTest(command=command), \
                 mock.patch("telegram_alerts.handlers.start_clear_chat_messages") as clear:
                result = handle_command(command, state, chat_id="chat", user_id="user", message_id=9)

            clear.assert_called_once_with("chat", 9, None, ready_message=None, known_message_ids=[1, 2, 3])
            self.assertTrue(result.get("skip_send"))
            self.assertTrue(result.get("remove_keyboard"))
            self.assertEqual(state["known_messages"]["chat"], [])
            self.assertTrue(state["start_menu_once_after_clear"]["chat:user"])

    def test_clear_command_invalid_count_returns_invalid_message(self):
        state = {"known_messages": {"chat": [1, 2, 3]}}
        with mock.patch("telegram_alerts.handlers.start_clear_chat_messages") as clear:
            result = handle_command("/clear nope", state, chat_id="chat", user_id="user", message_id=9)

        clear.assert_not_called()
        self.assertEqual(result, "Usage: /clear or /clear 200")
        self.assertEqual(state["known_messages"]["chat"], [1, 2, 3])

    def test_removed_help_and_status_commands_return_unknown_command(self):
        unknown = handle_command("/unknown-command", {}, chat_id="chat", user_id="user")
        for command in ("/help", "/status", "/status live"):
            with self.subTest(command=command):
                self.assertEqual(handle_command(command, {}, chat_id="chat", user_id="user"), unknown)
        self.assertEqual(unknown, "Unknown command. Use /menu to choose an action.")

    def test_removed_slash_commands_return_unknown_command(self):
        state = {}
        unknown = handle_command("/unknown-command", state, chat_id="chat", user_id="user")
        removed_commands = [
            "/ack all",
            "/help",
            "/status",
            "/status live",
            "/home",
            "/summary",
            "/incidents",
            "/alerts",
            "/quota",
            "/top",
            "/errors",
            "/logs",
            "/accounts",
            "/key alice",
            "/key_lookup",
            "/key-lookup",
            "/key_create",
            "/key-create",
            "/quota_set alice 20m",
            "/quota-set alice 20m",
            "/silence 30m",
            "/unsilence",
        ]

        for command in removed_commands:
            with self.subTest(command=command):
                self.assertEqual(handle_command(command, state, chat_id="chat", user_id="user"), unknown)
        self.assertNotIn("acked", state)
        self.assertNotIn("silenced_until_by_chat", state)

    def test_removed_stale_callbacks_return_unknown_button_action(self):
        state = {}
        for callback in ("menu:refresh", "menu:silence", "menu:clear", "menu:logs", "menu:overview", "menu:summary", "menu:status", "menu:overview_refresh"):
            with self.subTest(callback=callback):
                self.assertEqual(handle_callback(callback, state, chat_id="chat", user_id="user", message_id=1), "Unknown button action.")

    def test_current_top_level_inline_callbacks_still_route(self):
        state = {"snapshot": {"created_at": 1, "quota_error": "", "service_lines": [], "system_alerts": {}, "quota_signals": {}, "quota_rows": []}}
        callbacks = [
            "menu:capacity",
            "menu:capacity_refresh",
            "menu:quota_management",
            "menu:quota_management_refresh",
            "menu:top",
            "menu:top_refresh",
            "menu:usage",
            "menu:key_status",
            "menu:key_status_refresh",
            "menu:incidents",
            "menu:incidents_refresh",
            "menu:errors",
            "menu:errors_refresh",
            "menu:quota_set",
            "menu:key_create",
        ]
        current_menu_callbacks = [button["callback_data"] for row in menu_keyboard()["inline_keyboard"] for button in row]
        for callback in current_menu_callbacks:
            self.assertIn(callback, callbacks)
        with mock.patch("telegram_alerts.handlers.get_snapshot", return_value=state["snapshot"]), \
             mock.patch("telegram_alerts.handlers.get_capacity_check_snapshot", return_value=state["snapshot"]), \
             mock.patch("telegram_alerts.handlers.prompt_usage_picker", return_value={"text": "Usage picker"}), \
             mock.patch("telegram_alerts.handlers.prompt_key_reveal_picker", return_value={"text": "Show key picker"}), \
             mock.patch("telegram_alerts.handlers.prompt_key_create", return_value={"text": "Create key"}), \
             mock.patch("telegram_alerts.handlers.prompt_quota_picker", return_value={"text": "Quota picker"}), \
             mock.patch("telegram_alerts.handlers.build_errors_reply", return_value="Errors Today\nbody"):
            for callback in callbacks:
                with self.subTest(callback=callback):
                    result = handle_callback(callback, state, chat_id="chat", user_id="user", message_id=1)
                    self.assertIsInstance(result, dict)
                    self.assertTrue(result.get("edit_message"))
                    self.assertNotEqual(result.get("text"), "Unknown button action.")

    def test_current_picker_and_action_callbacks_still_route(self):
        state = {
            "key_pickers": {"chat:user": {"id": "picker1", "keys": ["alice-secret-key"], "aliases": ["alice"], "expires_at": 99_999_999_999}},
            "usage_pickers": {"chat:user": {"id": "picker2", "keys": ["alice-key"], "aliases": ["alice"], "daily_limits": [4_000_000], "weekly_limits": [16_000_000], "statuses": ["active"], "masked": ["alice***key"], "tz_name": "Asia/Ho_Chi_Minh", "expires_at": 99_999_999_999}},
            "quota_pickers": {"chat:user": {"id": "picker3", "keys": ["alice-key"], "aliases": ["alice"], "selected_key": "alice-key", "expires_at": 99_999_999_999}},
            "pending_actions": {"chat:user": {"code": "abc123", "type": "quota_set", "params": {"query": "alice", "daily": 20_000_000, "weekly": "default"}, "summary": "Pending quota update\n\nUser: alice", "expires_at": 99_999_999_999}},
        }
        callbacks = [
            "kpage:picker1:0",
            "kreveal:picker1:0",
            "upage:picker2:0",
            "uacct:picker2:0",
            "qpage:picker3:0",
            "qacct:picker3:0",
            "qlimit:picker3:1",
            "confirm:abc123",
            "cancel:abc123",
            "cancel_input",
            "cancel",
            "menu:back",
            "menu:key_lookup",
        ]
        account = {"alias": "alice", "key": "alice-key", "daily": 4_000_000, "weekly": "default"}
        with mock.patch("telegram_alerts.handlers.prompt_key_reveal_picker", return_value={"text": "Show key picker"}), \
             mock.patch("telegram_alerts.handlers.get_snapshot", return_value={"created_at": 1, "quota_error": "", "service_lines": [], "system_alerts": {}, "quota_signals": {}, "quota_rows": []}), \
             mock.patch("telegram_alerts.pickers.get_usage_breakdown_for_key", return_value={"daily": empty_usage_bucket(), "weekly": empty_usage_bucket()}), \
             mock.patch("telegram_alerts.pickers.quota_account_by_key", return_value=account), \
             mock.patch("telegram_alerts.actions.execute_quota_set", return_value=("Quota updated.", "alice-key")):
            for callback in callbacks:
                scoped_state = json.loads(json.dumps(state))
                with self.subTest(callback=callback):
                    result = handle_callback(callback, scoped_state, chat_id="chat", user_id="user", message_id=1)
                    self.assertNotEqual(result, "Unknown button action.")

    def test_cleanup_state_prunes_removed_feature_state_keys(self):
        state = {
            "acked": {"service:cliproxy": "old"},
            "language": "en",
            "silenced_until": 999999,
            "silenced_until_by_chat": {"chat": 999999},
            "start_acknowledged": {"chat": 1},
            "recent_start": {"chat": 1},
            "suppress_start_until": {"chat": 999999},
            "suppressed_change_keys": {"key": 999999},
        }

        self.assertTrue(cleanup_state(state))
        for key in ("acked", "language", "silenced_until", "silenced_until_by_chat", "start_acknowledged", "recent_start", "suppress_start_until", "suppressed_change_keys"):
            self.assertNotIn(key, state)

    def test_quota_enforcer_only_disable_restore_changes_stay_silent(self):
        old = {
            "key-1": {
                "alias": "alice",
                "cpa_deleted": False,
                "in_quota": True,
                "in_proxy_config": True,
                "disabled_by_quota": False,
                "daily": 4_000_000,
                "weekly": "default",
            }
        }
        new = {
            "key-1": {
                "alias": "alice",
                "cpa_deleted": False,
                "in_quota": True,
                "in_proxy_config": False,
                "disabled_by_quota": True,
                "daily": 4_000_000,
                "weekly": "default",
            }
        }

        self.assertEqual(build_change_events(old, new), [])

    def test_reauth_auto_disable_enable_status_only_change_is_not_added_or_removed(self):
        old = {
            "auth:codex-one.json": {
                "kind": "auth_account",
                "file_name": "codex-one.json",
                "alias": "codex-one",
                "type": "codex",
                "disabled": False,
            }
        }
        disabled = {
            "auth:codex-one.json": {
                "kind": "auth_account",
                "file_name": "codex-one.json",
                "alias": "codex-one",
                "type": "codex",
                "disabled": True,
            }
        }

        disabled_events = build_change_events(old, disabled)
        enabled_events = build_change_events(disabled, old)

        self.assertEqual([event["logical_type"] for event in disabled_events], ["auth_account_changed"])
        self.assertEqual([event["logical_type"] for event in enabled_events], ["auth_account_changed"])
        self.assertNotIn("auth_account_removed", repr(disabled_events + enabled_events))
        self.assertNotIn("auth_account_added", repr(disabled_events + enabled_events))


if __name__ == "__main__":
    unittest.main()
