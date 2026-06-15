import unittest
from unittest import mock

from telegram_alerts.actions import execute_key_reveal
from telegram_alerts.change_watch import build_change_events, logical_event
from telegram_alerts.keyboards import button, inline_keyboard, reply, silent_reply
from telegram_alerts.models import Alert
from telegram_alerts.snapshot import (
    alert_to_dict,
    build_snapshot,
    dict_to_alert,
    quota_alerts_from_context,
    quota_rows_from_context,
    sanitize_quota_row,
)
from telegram_alerts.telegram_client import edit_telegram_message_result, send_reply
from telegram_alerts.usage import empty_usage_bucket, summarize_usage_models


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


class ContractShapeTests(unittest.TestCase):
    def test_reply_and_silent_reply_shapes(self):
        markup = inline_keyboard([[button("Menu", "menu:back")]])
        data = reply("hello", markup)

        self.assertEqual(data["text"], "hello")
        self.assertEqual(data["reply_markup"], markup)
        self.assertEqual(silent_reply(), {"skip_send": True})

    def test_send_reply_honors_skip_send_without_calling_telegram(self):
        with mock.patch("telegram_alerts.telegram_client.send_telegram") as send_telegram:
            self.assertTrue(send_reply({"skip_send": True}, chat_id="chat"))

        send_telegram.assert_not_called()

    def test_send_reply_passes_inline_reply_markup_unchanged(self):
        markup = inline_keyboard([[button("Menu", "menu:back")]])
        with mock.patch("telegram_alerts.telegram_client.send_telegram") as send_telegram:
            send_reply(reply("hello", markup), chat_id="chat")

        send_telegram.assert_called_once_with("hello", dry_run=False, chat_id="chat", reply_markup=markup)

    def test_send_reply_removes_stale_reply_keyboard_before_inline_message(self):
        markup = inline_keyboard([[button("Menu", "menu:back")]])
        with mock.patch("telegram_alerts.telegram_client.send_telegram", side_effect=[
            [{"chat_id": "chat", "message_id": 41}],
            [{"chat_id": "chat", "message_id": 42}],
        ]) as send_telegram, \
             mock.patch("telegram_alerts.telegram_client.delete_telegram_message") as delete_message:
            result = send_reply({"text": "hello", "reply_markup": markup, "remove_keyboard": True}, chat_id="chat")

        self.assertEqual(result, [{"chat_id": "chat", "message_id": 42}])
        self.assertEqual(send_telegram.call_count, 2)
        self.assertEqual(send_telegram.call_args_list[0].kwargs, {"dry_run": False, "chat_id": "chat", "reply_markup": {"remove_keyboard": True}})
        self.assertEqual(send_telegram.call_args_list[1], mock.call("hello", dry_run=False, chat_id="chat", reply_markup=markup))
        delete_message.assert_called_once_with("chat", 41)

    def test_send_reply_keyboard_cleanup_failure_does_not_block_reply(self):
        with mock.patch("telegram_alerts.telegram_client.remove_telegram_reply_keyboard", side_effect=RuntimeError("boom")), \
             mock.patch("telegram_alerts.telegram_client.send_telegram") as send_telegram:
            result = send_reply({"skip_send": True, "remove_keyboard": True}, chat_id="chat")

        self.assertTrue(result)
        send_telegram.assert_not_called()

    def test_edit_telegram_message_result_shape_for_dry_run(self):
        with mock.patch("telegram_alerts.telegram_client.DRY_RUN", True):
            result = edit_telegram_message_result("chat", 1, "hello")

        self.assertEqual(result["ok"], True)
        self.assertEqual(result["reason"], "dry_run")

    def test_edit_telegram_message_result_shape_for_too_long(self):
        with mock.patch("telegram_alerts.telegram_client.DRY_RUN", False), \
             mock.patch("telegram_alerts.telegram_client.TELEGRAM_BOT_TOKEN", "token"):
            result = edit_telegram_message_result("chat", 1, "x" * 5000)

        self.assertEqual(result["ok"], False)
        self.assertEqual(result["reason"], "too_long")

    def test_alert_dict_round_trip_shape(self):
        alert = Alert("service:demo", "warning", "Demo warning", "body", "fp")
        data = alert_to_dict(alert)
        restored = dict_to_alert(data)

        self.assertEqual(set(data), {"alert_id", "severity", "title", "body", "fingerprint"})
        self.assertEqual(restored, alert)

    def test_logical_event_and_build_change_events_shape(self):
        event = logical_event("key-1", "key_added", "API key added", "alice", evidence={"added_to": ["quota config"]})
        self.assertEqual(set(event), {"key", "logical_type", "title", "account", "changes", "evidence"})
        self.assertEqual(event["changes"], [])

        events = build_change_events(
            {},
            {
                "key-1": {
                    "alias": "alice",
                    "cpa_deleted": False,
                    "in_quota": True,
                    "in_proxy_config": True,
                    "disabled_by_quota": False,
                    "daily": 100,
                    "weekly": "default",
                }
            },
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["logical_type"], "key_added")
        self.assertEqual(events[0]["account"], "alice")

    def test_sanitized_quota_row_shape_does_not_expose_full_key(self):
        full_key = "alice-secret-key-value"
        row = sanitize_quota_row({
            "name": "alice",
            "alias": "Alice",
            "key": full_key,
            "masked": "alice***value",
            "status": "active",
            "daily_used": 10,
            "daily_limit": 100,
            "daily_percent": 10.0,
            "weekly_used": 20,
            "weekly_limit": 400,
            "weekly_percent": 5.0,
            "effective_percent": 10.0,
        })

        self.assertEqual(set(row), {
            "name", "alias", "masked", "status", "daily_used", "daily_limit", "daily_percent",
            "weekly_used", "weekly_limit", "weekly_percent", "effective_percent",
        })
        self.assertNotIn("key", row)
        self.assertNotIn(full_key, str(row))

    def test_build_snapshot_minimal_payload_shape(self):
        quota_row = {
            "name": "alice",
            "alias": "Alice",
            "key": "alice-secret-key-value",
            "masked": "alice***value",
            "status": "active",
            "daily_used": 10,
            "daily_limit": 100,
            "daily_percent": 10.0,
            "weekly_used": 20,
            "weekly_limit": 400,
            "weekly_percent": 5.0,
            "effective_percent": 10.0,
        }
        gpt_pool = {
            "enabled_codex_count": 1,
            "primary": {"checked_count": 1, "avg_left_percent": 80.0, "lowest_left_percent": 80.0},
            "secondary": {"checked_count": 1, "avg_left_percent": 70.0, "lowest_left_percent": 70.0},
            "error": "",
        }
        with mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({}, auth_observation(healthy=["acct-ok"]))), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value={"items": []}), \
             mock.patch("telegram_alerts.snapshot.quota_alerts_from_context", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.quota_rows_from_context", return_value=[quota_row]), \
             mock.patch("telegram_alerts.snapshot.gpt_pool_capacity_snapshot", return_value=gpt_pool):
            snapshot = build_snapshot(interactive=True)

        self.assertEqual(set(snapshot), {
            "created_at", "service_lines", "system_alerts", "auth_quota_observation", "quota_signals",
            "quota_rows", "quota_error", "gpt_pool_capacity", "capacity_demand_rate",
            "gpt_pool_5h_observation", "enforcer_age",
        })
        self.assertEqual(snapshot["system_alerts"], {})
        self.assertIn("gpt_pool_5h_observation", snapshot)
        self.assertEqual(snapshot["gpt_pool_capacity"], gpt_pool)
        self.assertEqual(len(snapshot["quota_rows"]), 1)
        self.assertNotIn("key", snapshot["quota_rows"][0])

    def test_build_snapshot_handles_none_http_results_without_worker_crash(self):
        with mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=None), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({}, auth_observation(healthy=["acct-ok"]))), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value={"items": []}), \
             mock.patch("telegram_alerts.snapshot.quota_alerts_from_context", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.quota_rows_from_context", return_value=[]):
            snapshot = build_snapshot(interactive=True)

        self.assertEqual(snapshot["service_lines"], [])
        self.assertEqual(snapshot["system_alerts"], {})
        self.assertEqual(snapshot["quota_rows"], [])

    def test_quota_context_helpers_treat_explicit_none_as_empty(self):
        context = {
            "items": None,
            "disabled": None,
            "config_keys": None,
            "alias_by_key": None,
            "usage": None,
        }

        self.assertEqual(quota_alerts_from_context(context), [])
        self.assertEqual(quota_rows_from_context(context), [])

    def test_usage_bucket_and_breakdown_shapes(self):
        bucket = empty_usage_bucket()
        self.assertEqual(set(bucket), {
            "total_tokens", "input_tokens", "output_tokens", "reasoning_tokens", "cached_tokens",
            "cache_read_tokens", "cache_creation_tokens", "requests", "failed", "models", "fallback_trim",
        })

        model = {
            "model": "claude",
            "requests": 2,
            "failed": 1,
            "input_tokens": 10,
            "output_tokens": 20,
            "reasoning_tokens": 3,
            "cached_tokens": 4,
            "cache_read_tokens": 5,
            "cache_creation_tokens": 6,
            "total_tokens": 30,
        }
        summary = summarize_usage_models([model], fallback_trim=True)
        breakdown = {"daily": summary, "weekly": empty_usage_bucket()}

        self.assertTrue(summary["fallback_trim"])
        self.assertEqual(summary["requests"], 2)
        self.assertEqual(set(breakdown), {"daily", "weekly"})

    def test_key_reveal_result_remains_string_contract(self):
        text = execute_key_reveal({"alias": "alice", "key": "secret-key"})
        self.assertIsInstance(text, str)
        self.assertIn("API key: secret-key", text)


if __name__ == "__main__":
    unittest.main()
