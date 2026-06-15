import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import telegram_alerts.change_watch as change_watch
import telegram_alerts.quota_config as quota_config
import telegram_alerts.usage as usage_module
from telegram_alerts.change_watch import (
    build_change_events,
    flush_pending_change_notifications,
    format_change_event,
    is_change_event_suppressed,
    merge_pending_change_event,
    process_change_notifications,
)


def api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True, disabled_by_quota=False, manually_disabled=False, daily=4_000_000, weekly="default"):
    return {
        "alias": alias,
        "cpa_deleted": cpa_deleted,
        "in_quota": in_quota,
        "in_proxy_config": in_proxy_config,
        "disabled_by_quota": disabled_by_quota,
        "manually_disabled": manually_disabled,
        "daily": daily,
        "weekly": weekly,
    }


def auth_record(alias="codex-account", disabled=False, account_type="codex", read_error=None):
    record = {
        "kind": "auth_account",
        "file_name": "codex-one.json",
        "alias": alias,
        "type": account_type,
        "disabled": disabled,
    }
    if read_error is not None:
        record["read_error"] = read_error
    return record


def auth_transition_state(status="disabled", expires_at=999, reasons=None):
    ref = hashlib.sha256(b"auth-file:codex-one.json").hexdigest()[:16]
    item = {"status": status, "expires_at": expires_at}
    if reasons is not None:
        item["reasons"] = list(reasons)
    return {
        "auth_weekly_recent_transitions": {
            ref: item,
        },
    }


def collect_notification(old, new, state=None, now=10):
    watch = {}
    sent_messages = []
    events = build_change_events(old, new)
    state = state or {}
    with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
         mock.patch.object(change_watch, "now_ts", return_value=0):
        for event in events:
            if not is_change_event_suppressed(state, event):
                merge_pending_change_event(watch, event)
    with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
         mock.patch.object(change_watch, "now_ts", return_value=now), \
         mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
        sent = flush_pending_change_notifications(watch, state=state)
    return sent, sent_messages


def collect_notification_payloads(old, new, state=None, now=10):
    watch = {}
    sent_payloads = []
    events = build_change_events(old, new)
    state = state or {}
    with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
         mock.patch.object(change_watch, "now_ts", return_value=0):
        for event in events:
            if not is_change_event_suppressed(state, event):
                merge_pending_change_event(watch, event)
    with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
         mock.patch.object(change_watch, "now_ts", return_value=now), \
         mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_payloads.append((text, kwargs.get("reply_markup"))) or True):
        sent = flush_pending_change_notifications(watch, state=state)
    return sent, sent_payloads


def write_quota_file(path, keys):
    import json
    path.write_text(json.dumps({"timezone": "Asia/Ho_Chi_Minh", "keys": keys}), encoding="utf-8")


def write_proxy_config(path, keys):
    if not keys:
        path.write_text("api-keys: []\n", encoding="utf-8")
        return
    lines = ["api-keys:"]
    for key in keys:
        lines.append(f'  - "{key}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def create_usage_db(path):
    con = sqlite3.connect(path)
    try:
        con.execute(
            """
            CREATE TABLE cpa_api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT UNIQUE,
                display_key TEXT,
                key_alias TEXT,
                is_deleted INTEGER DEFAULT 0,
                last_synced_at TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            """
        )
        con.execute(
            """
            CREATE TABLE usage_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_group_key TEXT,
                total_tokens INTEGER DEFAULT 0,
                timestamp TEXT
            )
            """
        )
        con.commit()
    finally:
        con.close()


def insert_cpa_key(db_path, api_key, alias="Alice", display_key="old-display", is_deleted=0):
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cpa_api_keys
              (api_key, display_key, key_alias, is_deleted, last_synced_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'old', 'old', 'old')
            """,
            (api_key, display_key, alias, is_deleted),
        )
        con.commit()
    finally:
        con.close()


def fetch_cpa_rows(db_path):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in con.execute("SELECT api_key, display_key, key_alias, is_deleted FROM cpa_api_keys ORDER BY api_key")]
    finally:
        con.close()


def count_usage_rows(db_path):
    con = sqlite3.connect(db_path)
    try:
        return con.execute("SELECT COUNT(*) FROM usage_events").fetchone()[0]
    finally:
        con.close()


class CpaRegistrySyncTests(unittest.TestCase):
    def run_sync(self, quota_keys, proxy_keys, existing_rows, usage_rows=(), state_payload=None):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "app.db"
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            create_usage_db(db_path)
            write_quota_file(quota_path, quota_keys)
            write_proxy_config(config_path, proxy_keys)
            import json
            base_state = {"disabled_by_quota": []}
            if state_payload is not None:
                base_state.update(state_payload)
            state_path.write_text(json.dumps(base_state) + "\n", encoding="utf-8")
            for row in existing_rows:
                insert_cpa_key(db_path, **row)
            con = sqlite3.connect(db_path)
            try:
                for key, tokens in usage_rows:
                    con.execute(
                        "INSERT INTO usage_events (api_group_key, total_tokens, timestamp) VALUES (?, ?, '2026-06-10 00:00:00')",
                        (key, tokens),
                    )
                con.commit()
            finally:
                con.close()

            with mock.patch.object(quota_config, "USAGE_DB", db_path), \
                 mock.patch.object(quota_config, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(quota_config, "QUOTA_STATE", state_path), \
                 mock.patch.object(quota_config, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(usage_module, "USAGE_DB", db_path), \
                 mock.patch.object(usage_module, "load_quota_data", return_value=("Asia/Ho_Chi_Minh", [], set(), set())):
                changed = quota_config.sync_cpa_registry_from_quotas()
                alias_map = quota_config.load_cpa_alias_map()
                picker_accounts = usage_module.usage_accounts_for_picker()[1]
                rows = fetch_cpa_rows(db_path)
                usage_count = count_usage_rows(db_path)
            return changed, rows, alias_map, picker_accounts, usage_count

    def test_soft_deletes_cpa_row_absent_from_quota_and_proxy(self):
        changed, rows, alias_map, picker_accounts, usage_count = self.run_sync(
            quota_keys=[],
            proxy_keys=[],
            existing_rows=[{"api_key": "test-key-removed", "alias": "Alice", "display_key": "old-display", "is_deleted": 0}],
            usage_rows=[("test-key-removed", 123)],
        )

        self.assertEqual(changed, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["api_key"], "test-key-removed")
        self.assertEqual(rows[0]["is_deleted"], 1)
        self.assertEqual(rows[0]["key_alias"], "Alice")
        self.assertEqual(rows[0]["display_key"], "old-display")
        self.assertEqual(usage_count, 1)
        self.assertNotIn("test-key-removed", alias_map)
        self.assertEqual(picker_accounts, [])

    def test_does_not_soft_delete_quota_disabled_key_when_quota_snapshot_misses_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "app.db"
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            create_usage_db(db_path)
            write_quota_file(quota_path, [])
            write_proxy_config(config_path, [])
            state_path.write_text('{"disabled_by_quota": ["test-key-disabled"]}\n', encoding="utf-8")
            insert_cpa_key(db_path, api_key="test-key-disabled", alias="Disabled", display_key="old-display", is_deleted=0)

            with mock.patch.object(quota_config, "USAGE_DB", db_path), \
                 mock.patch.object(quota_config, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(quota_config, "QUOTA_STATE", state_path), \
                 mock.patch.object(quota_config, "CLIPROXY_CONFIG", config_path):
                changed = quota_config.sync_cpa_registry_from_quotas()
                rows = fetch_cpa_rows(db_path)

        self.assertEqual(changed, 0)
        self.assertEqual(rows[0]["api_key"], "test-key-disabled")
        self.assertEqual(rows[0]["is_deleted"], 0)

    def test_does_not_soft_delete_manually_disabled_key_when_quota_snapshot_misses_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "app.db"
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            create_usage_db(db_path)
            write_quota_file(quota_path, [])
            write_proxy_config(config_path, [])
            state_path.write_text('{"manually_disabled_keys": ["test-key-manual"]}\n', encoding="utf-8")
            insert_cpa_key(db_path, api_key="test-key-manual", alias="Manual", display_key="old-display", is_deleted=0)

            with mock.patch.object(quota_config, "USAGE_DB", db_path), \
                 mock.patch.object(quota_config, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(quota_config, "QUOTA_STATE", state_path), \
                 mock.patch.object(quota_config, "CLIPROXY_CONFIG", config_path):
                changed = quota_config.sync_cpa_registry_from_quotas()
                rows = fetch_cpa_rows(db_path)
                alias_map = quota_config.load_cpa_alias_map()

        self.assertEqual(changed, 0)
        self.assertEqual(rows[0]["api_key"], "test-key-manual")
        self.assertEqual(rows[0]["is_deleted"], 0)
        self.assertEqual(alias_map["test-key-manual"], "Manual")

    def test_does_not_delete_when_quota_present_but_proxy_absent(self):
        changed, rows, alias_map, picker_accounts, usage_count = self.run_sync(
            quota_keys=[{"name": "Alice Quota", "key": "test-key-quota", "daily_token_limit": 1000}],
            proxy_keys=[],
            existing_rows=[{"api_key": "test-key-quota", "alias": "Alice CPA", "display_key": "tes*********-quota", "is_deleted": 0}],
            usage_rows=[("test-key-quota", 123)],
        )

        self.assertEqual(changed, 0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["is_deleted"], 0)
        self.assertIn("test-key-quota", alias_map)
        self.assertEqual(alias_map["test-key-quota"], "Alice CPA")
        self.assertEqual(len(picker_accounts), 1)
        self.assertEqual(usage_count, 1)

    def test_does_not_delete_when_proxy_present_but_quota_absent(self):
        changed, rows, alias_map, picker_accounts, usage_count = self.run_sync(
            quota_keys=[],
            proxy_keys=["test-key-proxy"],
            existing_rows=[{"api_key": "test-key-proxy", "alias": "Proxy Only", "display_key": "old-display", "is_deleted": 0}],
            usage_rows=[("test-key-proxy", 123)],
        )

        self.assertEqual(changed, 0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["is_deleted"], 0)
        self.assertIn("test-key-proxy", alias_map)
        self.assertEqual(len(picker_accounts), 1)
        self.assertEqual(usage_count, 1)

    def test_empty_quotas_still_allows_safe_cleanup_when_proxy_readable(self):
        changed, rows, alias_map, picker_accounts, usage_count = self.run_sync(
            quota_keys=[],
            proxy_keys=[],
            existing_rows=[
                {"api_key": "test-key-removed", "alias": "Removed", "display_key": "old-display", "is_deleted": 0},
                {"api_key": "test-key-already-deleted", "alias": "Deleted", "display_key": "old-display", "is_deleted": 1},
            ],
            usage_rows=[("test-key-removed", 123), ("test-key-already-deleted", 456)],
        )

        self.assertEqual(changed, 1)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["api_key"]: row["is_deleted"] for row in rows}, {
            "test-key-already-deleted": 1,
            "test-key-removed": 1,
        })
        self.assertEqual(alias_map, {})
        self.assertEqual(picker_accounts, [])
        self.assertEqual(usage_count, 2)

    def test_preserves_unrelated_active_cpa_keys(self):
        changed, rows, alias_map, picker_accounts, usage_count = self.run_sync(
            quota_keys=[{"name": "Active Quota", "key": "test-key-active", "daily_token_limit": 1000}],
            proxy_keys=["test-key-active"],
            existing_rows=[
                {"api_key": "test-key-active", "alias": "Active CPA", "display_key": "old-active", "is_deleted": 0},
                {"api_key": "test-key-removed", "alias": "Removed CPA", "display_key": "old-removed", "is_deleted": 0},
            ],
            usage_rows=[("test-key-active", 123), ("test-key-removed", 456)],
        )

        by_key = {row["api_key"]: row for row in rows}
        self.assertEqual(changed, 2)
        self.assertEqual(by_key["test-key-active"]["is_deleted"], 0)
        self.assertEqual(by_key["test-key-active"]["key_alias"], "Active CPA")
        self.assertEqual(by_key["test-key-removed"]["is_deleted"], 1)
        self.assertIn("test-key-active", alias_map)
        self.assertNotIn("test-key-removed", alias_map)
        self.assertEqual([account["key"] for account in picker_accounts], ["test-key-active"])
        self.assertEqual(usage_count, 2)

    def test_quota_disabled_active_cpa_row_stays_active_when_proxy_absent(self):
        changed, rows, alias_map, picker_accounts, usage_count = self.run_sync(
            quota_keys=[{"name": "Quota Alias", "key": "test-key-disabled", "daily_token_limit": 1000}],
            proxy_keys=[],
            existing_rows=[{"api_key": "test-key-disabled", "alias": "Existing Alias", "display_key": "tes*********sabled", "is_deleted": 0}],
            usage_rows=[("test-key-disabled", 123)],
            state_payload={"disabled_by_quota": ["test-key-disabled"]},
        )

        self.assertEqual(changed, 0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["is_deleted"], 0)
        self.assertIn("test-key-disabled", alias_map)
        self.assertEqual(alias_map["test-key-disabled"], "Existing Alias")
        self.assertEqual([account["key"] for account in picker_accounts], ["test-key-disabled"])
        self.assertEqual(usage_count, 1)

    def test_quota_disabled_quota_managed_deleted_cpa_row_is_reactivated(self):
        changed, rows, alias_map, picker_accounts, usage_count = self.run_sync(
            quota_keys=[{"name": "Quota Alias", "key": "test-key-disabled", "daily_token_limit": 1000}],
            proxy_keys=[],
            existing_rows=[{"api_key": "test-key-disabled", "alias": "Old Alias", "display_key": "old-display", "is_deleted": 1}],
            usage_rows=[("test-key-disabled", 123)],
            state_payload={"disabled_by_quota": ["test-key-disabled"]},
        )

        self.assertEqual(changed, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["is_deleted"], 0)
        self.assertEqual(rows[0]["key_alias"], "Quota Alias")
        self.assertNotEqual(rows[0]["display_key"], "old-display")
        self.assertIn("test-key-disabled", alias_map)
        self.assertEqual(alias_map["test-key-disabled"], "Quota Alias")
        self.assertEqual([account["key"] for account in picker_accounts], ["test-key-disabled"])
        self.assertEqual(usage_count, 1)

    def test_manually_disabled_quota_managed_deleted_cpa_row_is_reactivated(self):
        changed, rows, alias_map, picker_accounts, usage_count = self.run_sync(
            quota_keys=[{"name": "Manual Alias", "key": "test-key-manual", "daily_token_limit": 1000}],
            proxy_keys=[],
            existing_rows=[{"api_key": "test-key-manual", "alias": "Old Alias", "display_key": "old-display", "is_deleted": 1}],
            usage_rows=[("test-key-manual", 123)],
            state_payload={"manually_disabled_keys": ["test-key-manual"]},
        )

        self.assertEqual(changed, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["is_deleted"], 0)
        self.assertEqual(rows[0]["key_alias"], "Manual Alias")
        self.assertNotEqual(rows[0]["display_key"], "old-display")
        self.assertIn("test-key-manual", alias_map)
        self.assertEqual(alias_map["test-key-manual"], "Manual Alias")
        self.assertEqual([account["key"] for account in picker_accounts], ["test-key-manual"])
        self.assertEqual(usage_count, 1)

    def test_protected_quota_disabled_tombstone_in_quota_is_reactivated(self):
        changed, rows, alias_map, picker_accounts, usage_count = self.run_sync(
            quota_keys=[{"name": "Protected Alias", "key": "test-key-protected", "daily_token_limit": 1000}],
            proxy_keys=[],
            existing_rows=[{"api_key": "test-key-protected", "alias": "Old Alias", "display_key": "old-display", "is_deleted": 1}],
            usage_rows=[("test-key-protected", 123)],
            state_payload={"disabled_by_quota": [], "cpa_deleted_while_quota_disabled": ["test-key-protected"]},
        )

        self.assertEqual(changed, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["is_deleted"], 0)
        self.assertEqual(rows[0]["key_alias"], "Protected Alias")
        self.assertIn("test-key-protected", alias_map)
        self.assertEqual(alias_map["test-key-protected"], "Protected Alias")
        self.assertEqual([account["key"] for account in picker_accounts], ["test-key-protected"])
        self.assertEqual(usage_count, 1)

    def test_quota_sync_preserves_soft_deleted_cpa_row_as_manual_delete_evidence(self):
        changed, rows, alias_map, picker_accounts, usage_count = self.run_sync(
            quota_keys=[{"name": "Quota Alias", "key": "test-key-restore", "daily_token_limit": 1000}],
            proxy_keys=[],
            existing_rows=[{"api_key": "test-key-restore", "alias": "Existing Alias", "display_key": "old-display", "is_deleted": 1}],
            usage_rows=[("test-key-restore", 123)],
        )

        self.assertEqual(changed, 0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["is_deleted"], 1)
        self.assertEqual(rows[0]["key_alias"], "Existing Alias")
        self.assertEqual(rows[0]["display_key"], "old-display")
        self.assertNotIn("test-key-restore", alias_map)
        self.assertEqual(picker_accounts, [])
        self.assertEqual(usage_count, 1)

    def test_skips_soft_delete_when_proxy_config_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "app.db"
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "missing-config.yaml"
            create_usage_db(db_path)
            write_quota_file(quota_path, [])
            insert_cpa_key(db_path, api_key="test-key-unreadable", alias="Unreadable", display_key="old-display", is_deleted=0)

            with mock.patch.object(quota_config, "USAGE_DB", db_path), \
                 mock.patch.object(quota_config, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(quota_config, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(quota_config, "log") as log_mock:
                changed = quota_config.sync_cpa_registry_from_quotas()
                rows = fetch_cpa_rows(db_path)

        self.assertEqual(changed, 0)
        self.assertEqual(rows[0]["is_deleted"], 0)
        logged = "\n".join(str(call.args[0]) for call in log_mock.call_args_list if call.args)
        self.assertIn("CPA", logged)
        self.assertNotIn("test-key-unreadable", logged)


class ChangeWatchNotificationTests(unittest.TestCase):
    def test_proxy_account_removed_renders_exact_operator_template(self):
        old = {"auth:codex-example-user-11@example.com": auth_record(alias="codex-example-user-11@example.com")}
        new = {}

        events = build_change_events(old, new)
        text = format_change_event(events[0])

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].get("logical_type"), "auth_account_removed")
        self.assertEqual(text, "Proxy account removed\n\n- codex-example-user-11@example.com")
        self.assertNotIn("Account:", text)
        self.assertNotIn("Removed from:", text)
        self.assertNotIn("---", text)

    def test_proxy_account_added_renders_exact_operator_template(self):
        old = {}
        new = {"auth:codex-example-user-11@example.com": auth_record(alias="codex-example-user-11@example.com")}

        events = build_change_events(old, new)
        text = format_change_event(events[0])

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].get("logical_type"), "auth_account_added")
        self.assertEqual(text, "Proxy account added\n\n- codex-example-user-11@example.com")
        self.assertNotIn("Account:", text)
        self.assertNotIn("Added to:", text)
        self.assertNotIn("---", text)

    def test_two_proxy_account_adds_group_into_one_plural_message(self):
        old = {}
        new = {
            "auth:codex-example-user-1@example.com": auth_record(alias="codex-example-user-1@example.com"),
            "auth:codex-example-user-2@example.com": auth_record(alias="codex-example-user-2@example.com"),
        }

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, [
            "Proxy accounts added\n\n"
            "- codex-example-user-1@example.com\n"
            "- codex-example-user-2@example.com"
        ])
        self.assertNotIn("Proxy account added\n\nProxy account added", "\n".join(messages))
        self.assertNotIn("Account:", messages[0])

    def test_two_proxy_account_removals_group_into_one_plural_message(self):
        old = {
            "auth:codex-example-user-1@example.com": auth_record(alias="codex-example-user-1@example.com"),
            "auth:codex-example-user-2@example.com": auth_record(alias="codex-example-user-2@example.com"),
        }
        new = {}

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, [
            "Proxy accounts removed\n\n"
            "- codex-example-user-1@example.com\n"
            "- codex-example-user-2@example.com"
        ])
        self.assertNotIn("Account:", messages[0])

    def test_proxy_account_group_does_not_truncate_large_batches(self):
        old = {}
        new = {
            f"auth:codex-batch-{index:02d}@example.com": auth_record(alias=f"codex-batch-{index:02d}@example.com")
            for index in range(25)
        }

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 1)
        self.assertEqual(len(messages), 1)
        self.assertTrue(messages[0].startswith("Proxy accounts added\n\n"))
        for index in range(25):
            self.assertIn(f"- codex-batch-{index:02d}@example.com", messages[0])
        self.assertEqual(messages[0].count("\n- "), 25)
        self.assertNotIn("... and", messages[0])
        self.assertNotIn("Change notification summary", messages[0])

    def test_proxy_account_added_prefers_codex_label_when_plain_label_exists(self):
        old = {}
        new = {
            "auth:codex-example-user-6@example.com.json": auth_record(alias="example-user-6@example.com"),
        }

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["Proxy account added\n\n- codex-example-user-6@example.com"])
        self.assertNotIn("- example-user-6@example.com", messages[0])

    def test_api_key_adds_are_not_grouped_as_proxy_accounts(self):
        old = {}
        new = {
            "key-1": api_record(alias="alice"),
            "key-2": api_record(alias="bob"),
        }

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 2)
        self.assertEqual(messages, [
            "API key created\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M",
            "API key created\n\nUser: bob\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M",
        ])
        self.assertNotIn("Proxy accounts added", "\n".join(messages))

    def test_logical_full_removal_hides_sources_and_has_one_footer(self):
        old = {"key-1": api_record(alias="alice")}
        new = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}

        events = build_change_events(old, new)
        text = format_change_event(events[0])

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].get("logical_type"), "key_removed")
        self.assertIn("API key deleted", text)
        self.assertIn("User: alice", text)
        self.assertIn("Status: Removed", text)
        self.assertNotIn("Removed from:", text)
        self.assertNotIn("proxy config", text)
        self.assertNotIn("web management", text)
        self.assertNotIn("quota config", text)
        self.assertNotIn("If unexpected, recreate the key or restore from backup.", text)

    def test_late_quota_removal_tail_does_not_send_second_notification(self):
        old = {"key-1": api_record(alias="alice")}
        mid = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=True, in_proxy_config=False)}
        new = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        watch = {}
        sent_messages = []

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            merge_pending_change_event(watch, build_change_events(old, mid)[0])

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=11), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)

        with mock.patch.object(change_watch, "now_ts", return_value=30):
            for event in build_change_events(mid, new):
                merge_pending_change_event(watch, event)

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=50), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 0)

        self.assertEqual(len(sent_messages), 1)
        self.assertIn("API key deleted", sent_messages[0])
        self.assertNotIn("Removed from:", sent_messages[0])
        self.assertIn("Status: Removed", sent_messages[0])
        self.assertNotIn("If unexpected, recreate the key or restore from backup.", sent_messages[0])

    def test_multi_source_add_uses_one_logical_message_without_sources(self):
        old = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        new = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True)}

        events = build_change_events(old, new)
        text = format_change_event(events[0])

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].get("logical_type"), "key_added")
        self.assertEqual(text, "API key created\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M")
        self.assertNotIn("Added to:", text)
        self.assertNotIn("proxy config", text)
        self.assertNotIn("web management", text)
        self.assertNotIn("quota config", text)

    def test_registry_only_tail_after_removal_does_not_emit_key_added(self):
        removed_partial = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=True, in_proxy_config=False)}
        registry_tail = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=False)}

        self.assertEqual(build_change_events(removed_partial, registry_tail), [])

    def test_create_remove_lifecycle_suppresses_add_after_removed_tail(self):
        absent = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        active = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True)}
        removed_partial = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=True, in_proxy_config=False)}
        registry_tail = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=False)}
        removed_final = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=False, in_proxy_config=False)}
        watch = {}
        sent_messages = []

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            for event in build_change_events(absent, active):
                merge_pending_change_event(watch, event)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=4), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=10):
            for event in build_change_events(active, removed_partial):
                merge_pending_change_event(watch, event)
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=21), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)

        with mock.patch.object(change_watch, "now_ts", return_value=22):
            for event in build_change_events(removed_partial, registry_tail):
                merge_pending_change_event(watch, event)
            for event in build_change_events(registry_tail, removed_final):
                merge_pending_change_event(watch, event)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "now_ts", return_value=40), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 0)

        self.assertEqual(sent_messages, [
            "API key created\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M",
            "API key deleted\n\nUser: alice\nStatus: Removed",
        ])

    def test_true_readd_after_completed_removal_lifecycle_sends_key_added(self):
        removed = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=False, in_proxy_config=False)}
        active = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True)}

        sent, messages = collect_notification(removed, active)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key created\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M"])

    def test_external_quota_change_formats_as_quota_updated(self):
        old = {"key-1": api_record(alias="alice", daily=4_000_000, weekly=16_000_000)}
        new = {"key-1": api_record(alias="alice", daily=20_000_000, weekly=80_000_000)}

        events = build_change_events(old, new)
        text = format_change_event(events[0])

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].get("logical_type"), "quota_changed")
        self.assertIn("Quota updated", text)
        self.assertIn("User: alice", text)
        self.assertIn("Daily: 4.0M -> 20.0M", text)
        self.assertIn("Weekly: 16.0M -> 80.0M", text)

    def test_external_alias_change_formats_old_to_new_account_label(self):
        old = {"key-1": api_record(alias="old")}
        new = {"key-1": api_record(alias="new")}

        events = build_change_events(old, new)
        text = format_change_event(events[0])

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].get("logical_type"), "alias_changed")
        self.assertEqual(text, "API key changed\n\nUser: old -> new")

    def test_bot_confirmed_key_create_allows_one_matching_key_added_notification(self):
        old = {"hominhquang-secret-key": api_record(alias="hominhquang", cpa_deleted=True, in_quota=False, in_proxy_config=False, daily=None, weekly="default")}
        new = {"hominhquang-secret-key": api_record(alias="hominhquang", cpa_deleted=False, in_quota=True, in_proxy_config=True, daily=30_000_000, weekly=120_000_000)}
        state = {"action_audit": [{"type": "key_create", "key": "hominhquang-secret-key", "suppress_change_until": 160}]}

        sent, messages = collect_notification(old, new, state=state)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key created\n\nUser: hominhquang\nStatus: Active\nDaily quota: 30M\nWeekly quota: 120M"])
        self.assertNotIn("hominhquang-secret-key", messages[0])

    def test_bot_confirmed_key_create_fast_paths_after_verified_snapshot_change(self):
        old = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        new = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True)}
        state = {"action_audit": [{"type": "key_create", "key": "key-1", "at": 0}]}

        sent, messages = collect_notification(old, new, state=state, now=1)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key created\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M"])

    def test_external_key_create_still_waits_for_debounce(self):
        old = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        new = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True)}

        sent, messages = collect_notification(old, new, now=1)

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_bot_confirmed_key_create_does_not_send_two_key_added_notifications(self):
        old = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        new = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True)}
        watch = {}
        sent_messages = []
        event = build_change_events(old, new)[0]
        state = {"action_audit": [{"type": "key_create", "key": "key-1", "suppress_change_until": 160}]}

        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            if not is_change_event_suppressed(state, event):
                merge_pending_change_event(watch, event)
            if not is_change_event_suppressed(state, event):
                merge_pending_change_event(watch, event)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=10), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)
            self.assertEqual(flush_pending_change_notifications(watch), 0)
        self.assertEqual(sent_messages, ["API key created\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M"])

    def test_bot_confirmed_key_create_does_not_suppress_later_key_removed(self):
        state = {"action_audit": [{"type": "key_create", "key": "key-1", "suppress_change_until": 160}]}
        event = {"key": "key-1", "logical_type": "key_removed", "title": "API key removed", "account": "alice", "changes": []}

        with mock.patch.object(change_watch, "now_ts", return_value=120):
            self.assertFalse(is_change_event_suppressed(state, event))

    def test_bot_confirmed_quota_set_allows_one_matching_quota_notification(self):
        old = {"key-1": api_record(alias="alice", daily=4_000_000, weekly=16_000_000)}
        new = {"key-1": api_record(alias="alice", daily=20_000_000, weekly=80_000_000)}
        state = {"action_audit": [{"type": "quota_set", "key": "key-1", "suppress_change_until": 160}]}

        sent, messages = collect_notification(old, new, state=state)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["Quota updated\n\nUser: alice\nDaily: 4.0M -> 20.0M\nWeekly: 16.0M -> 80.0M"])

    def test_bot_confirmed_quota_set_fast_paths_after_verified_snapshot_change(self):
        old = {"key-1": api_record(alias="alice", daily=4_000_000, weekly=16_000_000)}
        new = {"key-1": api_record(alias="alice", daily=20_000_000, weekly=80_000_000)}
        state = {"action_audit": [{"type": "quota_set", "key": "key-1", "at": 0}]}

        sent, messages = collect_notification(old, new, state=state, now=1)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["Quota updated\n\nUser: alice\nDaily: 4.0M -> 20.0M\nWeekly: 16.0M -> 80.0M"])

    def test_external_quota_set_still_waits_for_debounce(self):
        old = {"key-1": api_record(alias="alice", daily=4_000_000, weekly=16_000_000)}
        new = {"key-1": api_record(alias="alice", daily=20_000_000, weekly=80_000_000)}

        sent, messages = collect_notification(old, new, now=1)

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_bot_confirmed_quota_set_does_not_send_two_quota_notifications(self):
        old = {"key-1": api_record(alias="alice", daily=4_000_000, weekly=16_000_000)}
        new = {"key-1": api_record(alias="alice", daily=20_000_000, weekly=80_000_000)}
        watch = {}
        sent_messages = []
        event = build_change_events(old, new)[0]
        state = {"action_audit": [{"type": "quota_set", "key": "key-1", "suppress_change_until": 160}]}

        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            if not is_change_event_suppressed(state, event):
                merge_pending_change_event(watch, event)
            if not is_change_event_suppressed(state, event):
                merge_pending_change_event(watch, event)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=10), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)
            self.assertEqual(flush_pending_change_notifications(watch), 0)
        self.assertEqual(sent_messages, ["Quota updated\n\nUser: alice\nDaily: 4.0M -> 20.0M\nWeekly: 16.0M -> 80.0M"])

    def test_bot_confirmed_quota_set_does_not_suppress_alias_or_removal_events(self):
        state = {"action_audit": [{"type": "quota_set", "key": "key-1", "suppress_change_until": 160}]}
        alias_event = {"key": "key-1", "logical_type": "alias_changed", "title": "API key changed", "account": "old -> new", "changes": []}
        removal_event = {"key": "key-1", "logical_type": "key_removed", "title": "API key removed", "account": "alice", "changes": []}

        with mock.patch.object(change_watch, "now_ts", return_value=120):
            self.assertFalse(is_change_event_suppressed(state, alias_event))
            self.assertFalse(is_change_event_suppressed(state, removal_event))

    def test_action_audit_ttl_does_not_suppress_key_added_notification(self):
        state = {"action_audit": [{"type": "key_create", "key": "key-1", "suppress_change_until": 160}]}
        event = {"key": "key-1", "logical_type": "key_added", "title": "API key added", "account": "alice", "changes": []}

        with mock.patch.object(change_watch, "now_ts", return_value=120):
            self.assertFalse(is_change_event_suppressed(state, event))

    def test_action_audit_for_one_key_does_not_affect_unrelated_key(self):
        state = {"action_audit": [{"type": "key_create", "key": "key-1", "suppress_change_until": 160}]}
        event = {"key": "key-2", "logical_type": "key_added", "title": "API key added", "account": "bob", "changes": []}

        with mock.patch.object(change_watch, "now_ts", return_value=120):
            self.assertFalse(is_change_event_suppressed(state, event))

    def test_external_manual_key_add_sends_one_notification(self):
        old = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        new = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True)}

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key created\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M"])

    def test_external_manual_quota_edit_sends_one_notification(self):
        old = {"key-1": api_record(alias="alice", daily=4_000_000, weekly=16_000_000)}
        new = {"key-1": api_record(alias="alice", daily=20_000_000, weekly=80_000_000)}

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["Quota updated\n\nUser: alice\nDaily: 4.0M -> 20.0M\nWeekly: 16.0M -> 80.0M"])

    def test_recent_removal_suppression_allows_new_lifecycle_after_readd(self):
        active = {"key-1": api_record(alias="alice")}
        removed = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        watch = {}
        sent_messages = []

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            merge_pending_change_event(watch, build_change_events(active, removed)[0])
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=11), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)

        with mock.patch.object(change_watch, "now_ts", return_value=12):
            merge_pending_change_event(watch, build_change_events(removed, active)[0])
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=16), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=17):
            merge_pending_change_event(watch, build_change_events(active, removed)[0])
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=28), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)

        self.assertEqual([message.split("\n", 1)[0] for message in sent_messages], ["API key deleted", "API key created", "API key deleted"])

    def test_manual_removal_after_bot_created_key_sends_one_notification(self):
        old = {"key-1": api_record(alias="alice")}
        new = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        state = {"action_audit": [{"type": "key_create", "key": "key-1", "suppress_change_until": 160}]}
        watch = {}
        sent_messages = []
        event = build_change_events(old, new)[0]

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            if not is_change_event_suppressed(state, event):
                merge_pending_change_event(watch, event)
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=11), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)
        self.assertEqual(sent_messages, ["API key deleted\n\nUser: alice\nStatus: Removed"])

    def test_more_than_twenty_logical_changes_are_not_silently_dropped(self):
        old = {
            f"key-{index}": api_record(alias=f"acct-{index}", daily=4_000_000, weekly=16_000_000)
            for index in range(25)
        }
        new = {
            key: dict(value, daily=20_000_000, weekly=80_000_000)
            for key, value in old.items()
        }

        events = build_change_events(old, new)

        self.assertEqual(len(events), 25)
        self.assertEqual({event["logical_type"] for event in events}, {"quota_changed"})

    def test_bulk_change_flush_sends_details_plus_secret_safe_summary(self):
        old = {
            f"sk-secret-{index:02d}-abcdefghijklmnopqrstuvwxyz": api_record(alias=f"acct-{index}", daily=4_000_000, weekly=16_000_000)
            for index in range(25)
        }
        new = {
            key: dict(value, daily=20_000_000, weekly=80_000_000)
            for key, value in old.items()
        }
        watch = {"snapshot": new}
        sent_messages = []

        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            for event in build_change_events(old, new):
                merge_pending_change_event(watch, event)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=10), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            sent = flush_pending_change_notifications(watch)

        self.assertEqual(sent, 21)
        self.assertEqual(len(sent_messages), 21)
        self.assertIn("Quota updated", sent_messages[0])
        summary = sent_messages[-1]
        self.assertIn("Change notification summary", summary)
        self.assertIn("5 more", summary)
        self.assertIn("quota", summary.lower())
        self.assertNotIn("sk-secret", summary)
        self.assertNotIn("Added to:", summary)
        self.assertNotIn("Removed from:", summary)
        self.assertNotIn("proxy config", summary)
        self.assertNotIn("quota config", summary)

    def test_pending_removal_is_cancelled_when_key_reappears_before_holdback(self):
        active = {"key-1": api_record(alias="alice")}
        missing = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        watch = {"snapshot": missing}
        sent_messages = []

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            merge_pending_change_event(watch, build_change_events(active, missing)[0])
        watch["snapshot"] = active
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=4):
            merge_pending_change_event(watch, build_change_events(missing, active)[0])
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)

        self.assertEqual(sent_messages, ["API key created\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M"])
        self.assertNotIn("key-1:key_removed", watch.get("pending", {}))

    def test_flush_skips_pending_removal_when_snapshot_is_present_again(self):
        active = {"key-1": api_record(alias="alice")}
        missing = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        watch = {"snapshot": missing}
        sent_messages = []

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            merge_pending_change_event(watch, build_change_events(active, missing)[0])
        watch["snapshot"] = active
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 0)

        self.assertEqual(sent_messages, [])
        self.assertNotIn("key-1:key_removed", watch.get("pending", {}))

    def test_still_missing_after_holdback_sends_one_removal(self):
        active = {"key-1": api_record(alias="alice")}
        missing = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        watch = {"snapshot": missing}
        sent_messages = []

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            merge_pending_change_event(watch, build_change_events(active, missing)[0])
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)

        self.assertEqual(sent_messages, ["API key deleted\n\nUser: alice\nStatus: Removed"])

    def test_quota_enforcer_only_disable_stays_silent(self):
        active = {"key-1": api_record(alias="alice", disabled_by_quota=False, in_proxy_config=True)}
        disabled = {"key-1": api_record(alias="alice", disabled_by_quota=True, in_proxy_config=False)}

        self.assertEqual(build_change_events(active, disabled), [])

    def test_quota_disabled_key_absent_from_config_does_not_emit_removed_notification(self):
        active = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True, disabled_by_quota=False)}
        disabled = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=False, disabled_by_quota=True)}

        sent, messages = collect_notification(active, disabled)

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_single_manual_disable_renders_exact_operator_template(self):
        active = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False)}
        disabled = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}

        sent, messages = collect_notification(active, disabled)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key disabled\n\nUser: alice\nStatus: Disabled"])

    def test_change_watch_snapshot_prefers_full_quota_name_over_short_cpa_alias_for_manual_labels(self):
        key = "hominhquang-secret-key"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "app.db"
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            create_usage_db(db_path)
            insert_cpa_key(db_path, api_key=key, alias="quang", display_key="display", is_deleted=0)
            write_quota_file(
                quota_path,
                [{"name": "hominhquang", "key": key, "daily_token_limit": 75_000_000, "weekly_token_limit": 300_000_000}],
            )
            write_proxy_config(config_path, [])
            state_path.write_text('{"manually_disabled_keys": ["hominhquang-secret-key"]}\n', encoding="utf-8")

            with mock.patch.object(quota_config, "USAGE_DB", db_path), \
                 mock.patch.object(change_watch, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(change_watch, "QUOTA_STATE", state_path), \
                 mock.patch.object(change_watch, "load_quotas_json", side_effect=quota_config.load_quotas_json), \
                 mock.patch.object(quota_config, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(quota_config, "QUOTA_STATE", state_path):
                snapshot = change_watch.change_watch_snapshot()

        self.assertEqual(snapshot[key]["alias"], "hominhquang")
        event = build_change_events(
            {key: dict(snapshot[key], manually_disabled=False, in_proxy_config=True)},
            {key: snapshot[key]},
        )[0]
        self.assertEqual(format_change_event(event), "API key disabled\n\nUser: hominhquang\nStatus: Disabled")
        self.assertNotIn("quang", format_change_event(event).replace("hominhquang", ""))

    def test_bot_confirmed_key_disable_still_sends_automatic_manual_notification(self):
        active = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False)}
        disabled = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}
        state = {"action_audit": [{"type": "key_disable", "key": "key-1", "suppress_change_until": 160}]}

        sent, messages = collect_notification(active, disabled, state=state)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key disabled\n\nUser: kieuoanh\nStatus: Disabled"])

    def test_bot_confirmed_key_disable_fast_paths_after_verified_snapshot_change(self):
        active = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False)}
        disabled = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}
        state = {"action_audit": [{"type": "key_disable", "key": "key-1", "at": 0}]}

        sent, messages = collect_notification(active, disabled, state=state, now=1)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key disabled\n\nUser: kieuoanh\nStatus: Disabled"])

    def test_external_key_disable_still_waits_for_debounce(self):
        active = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False)}
        disabled = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}

        sent, messages = collect_notification(active, disabled, now=1)

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_manual_disable_notification_has_no_buttons(self):
        active = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False)}
        disabled = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}

        sent, payloads = collect_notification_payloads(active, disabled)

        self.assertEqual(sent, 1)
        self.assertEqual(payloads[0][0], "API key disabled\n\nUser: kieuoanh\nStatus: Disabled")
        self.assertIsNone(payloads[0][1])

    def test_multiple_manual_disables_group_into_exact_operator_template(self):
        active = {
            "key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False),
            "key-2": api_record(alias="bob", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False),
        }
        disabled = {
            "key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True),
            "key-2": api_record(alias="bob", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True),
        }

        sent, messages = collect_notification(active, disabled)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API keys disabled\n\nUser: alice\nStatus: Disabled\n\nUser: bob\nStatus: Disabled"])

    def test_single_manual_enable_renders_exact_operator_template(self):
        disabled = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}
        active = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False)}

        sent, messages = collect_notification(disabled, active)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key enabled\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M"])

    def test_bot_confirmed_key_enable_still_sends_automatic_manual_notification(self):
        disabled = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}
        active = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False)}
        state = {"action_audit": [{"type": "key_enable", "key": "key-1", "suppress_change_until": 160}]}

        sent, messages = collect_notification(disabled, active, state=state)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key enabled\n\nUser: kieuoanh\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M"])

    def test_bot_confirmed_key_enable_fast_paths_after_verified_snapshot_change(self):
        disabled = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}
        active = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False)}
        state = {"action_audit": [{"type": "key_enable", "key": "key-1", "at": 0}]}

        sent, messages = collect_notification(disabled, active, state=state, now=1)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key enabled\n\nUser: kieuoanh\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M"])

    def test_manual_enable_notification_has_no_buttons(self):
        disabled = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}
        active = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False)}

        sent, payloads = collect_notification_payloads(disabled, active)

        self.assertEqual(sent, 1)
        self.assertEqual(payloads[0][0], "API key enabled\n\nUser: kieuoanh\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M")
        self.assertIsNone(payloads[0][1])

    def test_key_removed_notification_has_no_buttons(self):
        active = {"key-1": api_record(alias="kieuoanh")}
        removed = {"key-1": api_record(alias="kieuoanh", cpa_deleted=True, in_quota=False, in_proxy_config=False)}

        sent, payloads = collect_notification_payloads(active, removed, now=20)

        self.assertEqual(sent, 1)
        self.assertEqual(payloads[0][0], "API key deleted\n\nUser: kieuoanh\nStatus: Removed")
        self.assertIsNone(payloads[0][1])

    def test_bot_confirmed_key_delete_fast_paths_after_verified_snapshot_removal(self):
        active = {"key-1": api_record(alias="kieuoanh")}
        removed = {"key-1": api_record(alias="kieuoanh", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        state = {"action_audit": [{"type": "key_delete", "key": "key-1", "at": 0}]}

        sent, messages = collect_notification(active, removed, state=state, now=1)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key deleted\n\nUser: kieuoanh\nStatus: Removed"])

    def test_bot_confirmed_key_delete_fast_path_does_not_send_when_snapshot_still_has_key(self):
        state = {"action_audit": [{"type": "key_delete", "key": "key-1", "at": 0}]}
        watch = {
            "snapshot": {"key-1": api_record(alias="kieuoanh")},
            "pending": {
                "key-1:key_removed": {
                    "key": "key-1",
                    "logical_type": "key_removed",
                    "title": "API key removed",
                    "account": "kieuoanh",
                    "changes": [],
                    "evidence": {},
                    "first_seen": 0,
                    "updated_at": 0,
                }
            },
        }
        sent_messages = []

        with mock.patch.object(change_watch, "now_ts", return_value=1), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch, state=state), 0)

        self.assertEqual(sent_messages, [])
        self.assertNotIn("key-1:key_removed", watch.get("pending", {}))

    def test_bot_confirmed_fast_path_does_not_repeat_after_send(self):
        active = {"key-1": api_record(alias="kieuoanh")}
        removed = {"key-1": api_record(alias="kieuoanh", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        state = {"action_audit": [{"type": "key_delete", "key": "key-1", "at": 0}]}
        watch = {}
        sent_messages = []
        event = build_change_events(active, removed)[0]

        with mock.patch.object(change_watch, "now_ts", return_value=0):
            merge_pending_change_event(watch, event)
        with mock.patch.object(change_watch, "now_ts", return_value=1), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch, state=state), 1)
            self.assertEqual(flush_pending_change_notifications(watch, state=state), 0)

        self.assertEqual(sent_messages, ["API key deleted\n\nUser: kieuoanh\nStatus: Removed"])

    def test_old_bot_action_audit_does_not_fast_path_new_event(self):
        active = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False)}
        disabled = {"key-1": api_record(alias="kieuoanh", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}
        state = {"action_audit": [{"type": "key_disable", "key": "key-1", "at": -200}]}

        sent, messages = collect_notification(active, disabled, state=state, now=1)

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_multiple_manual_enables_group_into_exact_operator_template(self):
        disabled = {
            "key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True),
            "key-2": api_record(alias="bob", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True),
        }
        active = {
            "key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False),
            "key-2": api_record(alias="bob", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False),
        }

        sent, messages = collect_notification(disabled, active)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API keys enabled\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M\n\nUser: bob\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M"])

    def test_manual_disable_and_enable_are_not_rendered_as_added_or_removed(self):
        active = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True, manually_disabled=False)}
        disabled = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}

        _sent_disable, disable_messages = collect_notification(active, disabled)
        _sent_enable, enable_messages = collect_notification(disabled, active)
        text = "\n".join(disable_messages + enable_messages)

        self.assertNotIn("API key created", text)
        self.assertNotIn("API key deleted", text)
        self.assertNotIn("Proxy account added", text)
        self.assertNotIn("Proxy account removed", text)

    def test_manual_delete_after_manual_disabled_state_emits_removed_notification(self):
        disabled = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=False, manually_disabled=True)}
        removed = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False, manually_disabled=False)}

        sent, messages = collect_notification(disabled, removed, now=20)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key deleted\n\nUser: alice\nStatus: Removed"])

    def test_proxy_config_tail_then_quota_disable_stays_silent(self):
        active = {"key-1": api_record(alias="alice", disabled_by_quota=False, in_proxy_config=True)}
        proxy_tail = {"key-1": api_record(alias="alice", disabled_by_quota=False, in_proxy_config=False)}
        disabled = {"key-1": api_record(alias="alice", disabled_by_quota=True, in_proxy_config=False)}
        watch = {"snapshot": proxy_tail}
        sent_messages = []

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            for event in build_change_events(active, proxy_tail):
                merge_pending_change_event(watch, event)
        watch["snapshot"] = disabled
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=4):
            for event in build_change_events(proxy_tail, disabled):
                merge_pending_change_event(watch, event)
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 0)

        self.assertEqual(sent_messages, [])
        self.assertNotIn("key-1:key_removed", watch.get("pending", {}))

    def test_hominhquang_quota_update_plus_quota_disable_emits_only_quota_update(self):
        active = {
            "key-1": api_record(
                alias="hominhquang",
                cpa_deleted=False,
                in_quota=True,
                in_proxy_config=True,
                disabled_by_quota=False,
                daily=50_000_000,
                weekly="default",
            )
        }
        disabled_after_quota_edit = {
            "key-1": api_record(
                alias="hominhquang",
                cpa_deleted=False,
                in_quota=True,
                in_proxy_config=False,
                disabled_by_quota=True,
                daily=75_000_000,
                weekly="default",
            )
        }

        sent, messages = collect_notification(active, disabled_after_quota_edit)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["Quota updated\n\nUser: hominhquang\nDaily: 50.0M -> 75.0M"])
        self.assertNotIn("API key deleted", "\n".join(messages))
        self.assertNotIn("API key created", "\n".join(messages))

    def test_pending_removal_is_cancelled_when_current_snapshot_is_quota_disabled_tail(self):
        watch = {
            "snapshot": {
                "key-1": api_record(
                    alias="hominhquang",
                    cpa_deleted=False,
                    in_quota=True,
                    in_proxy_config=False,
                    disabled_by_quota=True,
                    daily=75_000_000,
                    weekly="default",
                )
            },
            "pending": {
                "key-1:key_removed": {
                    "key": "key-1",
                    "logical_type": "key_removed",
                    "title": "API key removed",
                    "account": "hominhquang",
                    "changes": [],
                    "evidence": {},
                    "first_seen": 0,
                    "updated_at": 0,
                }
            },
        }
        sent_messages = []

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 0)

        self.assertEqual(sent_messages, [])
        self.assertNotIn("key-1:key_removed", watch.get("pending", {}))

    def test_known_active_removal_is_suppressed_after_cpa_tombstone_seen_while_quota_disabled(self):
        active = {
            "key-1": api_record(
                alias="hominhquang",
                cpa_deleted=False,
                in_quota=True,
                in_proxy_config=True,
                disabled_by_quota=False,
                daily=50_000_000,
                weekly="default",
            )
        }
        quota_disabled_tombstone = {
            "key-1": api_record(
                alias="hominhquang",
                cpa_deleted=True,
                in_quota=True,
                in_proxy_config=False,
                disabled_by_quota=True,
                daily=50_000_000,
                weekly="default",
            )
        }
        quota_raised_tail = {
            "key-1": api_record(
                alias="hominhquang",
                cpa_deleted=True,
                in_quota=True,
                in_proxy_config=False,
                disabled_by_quota=False,
                daily=75_000_000,
                weekly="default",
            )
        }
        fully_removed_tail = {
            "key-1": api_record(
                alias="hominhquang",
                cpa_deleted=True,
                in_quota=False,
                in_proxy_config=False,
                disabled_by_quota=False,
                daily=None,
                weekly="default",
            )
        }
        state = {
            "change_watch": {
                "snapshot": active,
                "fingerprint": change_watch.change_watch_fingerprint(active),
                "checked_at": 0,
                "known_active_keys": {
                    "key-1": {"account": "hominhquang", "last_seen": 0, "last_present": 0},
                },
            }
        }
        sent_messages = []

        with mock.patch.object(change_watch, "change_watch_snapshot", return_value=quota_disabled_tombstone), \
             mock.patch.object(change_watch, "CHANGE_WATCH_INTERVAL_SECONDS", 1), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=10), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            process_change_notifications(state, force=True)
        with mock.patch.object(change_watch, "change_watch_snapshot", return_value=quota_raised_tail), \
             mock.patch.object(change_watch, "CHANGE_WATCH_INTERVAL_SECONDS", 1), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            process_change_notifications(state, force=True)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=25), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            flush_pending_change_notifications(state["change_watch"])
        with mock.patch.object(change_watch, "change_watch_snapshot", return_value=fully_removed_tail), \
             mock.patch.object(change_watch, "CHANGE_WATCH_INTERVAL_SECONDS", 1), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=40), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            process_change_notifications(state, force=True)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=60), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            flush_pending_change_notifications(state["change_watch"])

        self.assertEqual(sent_messages, ["Quota updated\n\nUser: hominhquang\nDaily: 50.0M -> 75.0M"])
        self.assertNotIn("API key deleted", "\n".join(sent_messages))
        self.assertNotIn("key-1:key_removed", state["change_watch"].get("pending", {}))

    def test_cpa_tombstone_seen_while_quota_disabled_does_not_emit_key_removed(self):
        quota_disabled_tombstone = {
            "key-1": api_record(
                alias="hominhquang",
                cpa_deleted=True,
                in_quota=True,
                in_proxy_config=False,
                disabled_by_quota=True,
                daily=75_000_000,
                weekly="default",
            )
        }
        fully_removed_tail = {
            "key-1": api_record(
                alias="hominhquang",
                cpa_deleted=True,
                in_quota=False,
                in_proxy_config=False,
                disabled_by_quota=False,
                daily=None,
                weekly="default",
            )
        }

        sent, messages = collect_notification(quota_disabled_tombstone, fully_removed_tail, now=20)

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_flush_skips_pending_removal_when_snapshot_is_quota_disabled(self):
        active = {"key-1": api_record(alias="alice")}
        missing = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        disabled = {"key-1": api_record(alias="alice", disabled_by_quota=True, in_proxy_config=False)}
        watch = {"snapshot": missing}
        sent_messages = []

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            merge_pending_change_event(watch, build_change_events(active, missing)[0])
        watch["snapshot"] = disabled
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 0)

        self.assertEqual(sent_messages, [])
        self.assertNotIn("key-1:key_removed", watch.get("pending", {}))

    def test_quota_enforcer_only_restore_stays_silent(self):
        disabled = {"key-1": api_record(alias="alice", disabled_by_quota=True, in_proxy_config=False)}
        active = {"key-1": api_record(alias="alice", disabled_by_quota=False, in_proxy_config=True)}

        self.assertEqual(build_change_events(disabled, active), [])

    def test_quota_restore_does_not_emit_api_key_added_notification(self):
        disabled = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=False, disabled_by_quota=True)}
        active = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True, disabled_by_quota=False)}

        sent, messages = collect_notification(disabled, active)

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_quota_restore_with_limit_increase_emits_only_quota_update(self):
        disabled = {
            "key-1": api_record(
                alias="exampleuser",
                cpa_deleted=False,
                in_quota=True,
                in_proxy_config=False,
                disabled_by_quota=True,
                daily=200_000_000,
                weekly="default",
            )
        }
        active = {
            "key-1": api_record(
                alias="exampleuser",
                cpa_deleted=False,
                in_quota=True,
                in_proxy_config=True,
                disabled_by_quota=False,
                daily=300_000_000,
                weekly="default",
            )
        }

        sent, messages = collect_notification(disabled, active)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["Quota updated\n\nUser: exampleuser\nDaily: 200.0M -> 300.0M"])
        self.assertNotIn("API key created", "\n".join(messages))

    def test_quota_update_while_quota_disabled_emits_only_quota_update(self):
        disabled_before = {
            "key-1": api_record(
                alias="exampleuser",
                cpa_deleted=False,
                in_quota=True,
                in_proxy_config=False,
                disabled_by_quota=True,
                daily=200_000_000,
                weekly="default",
            )
        }
        disabled_after = {
            "key-1": api_record(
                alias="exampleuser",
                cpa_deleted=False,
                in_quota=True,
                in_proxy_config=False,
                disabled_by_quota=True,
                daily=300_000_000,
                weekly="default",
            )
        }

        sent, messages = collect_notification(disabled_before, disabled_after)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["Quota updated\n\nUser: exampleuser\nDaily: 200.0M -> 300.0M"])
        self.assertNotIn("API key created", "\n".join(messages))

    def test_silent_quota_disabled_snapshot_returns_changed_so_state_is_saved(self):
        disabled = {"key-1": api_record(alias="exampleuser", in_proxy_config=False, disabled_by_quota=True)}
        state = {
            "change_watch": {
                "snapshot": {},
                "fingerprint": change_watch.change_watch_fingerprint({}),
                "checked_at": 0,
            }
        }
        sent_messages = []

        with mock.patch.object(change_watch, "change_watch_snapshot", return_value=disabled), \
             mock.patch.object(change_watch, "CHANGE_WATCH_INTERVAL_SECONDS", 1), \
             mock.patch.object(change_watch, "now_ts", return_value=10), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            changed = process_change_notifications(state, force=True)

        self.assertEqual(changed, 1)
        self.assertEqual(sent_messages, [])
        self.assertEqual(state["change_watch"]["snapshot"], disabled)

    def test_quota_restore_with_protected_stale_cpa_tombstone_stays_silent(self):
        disabled = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=True, in_proxy_config=False, disabled_by_quota=True)}
        active = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=True, in_proxy_config=True, disabled_by_quota=False)}

        sent, messages = collect_notification(disabled, active)

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_manual_delete_after_quota_disabled_state_emits_removed_notification(self):
        disabled = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=False, disabled_by_quota=True)}
        removed = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False, disabled_by_quota=False)}

        sent, messages = collect_notification(disabled, removed, now=20)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key deleted\n\nUser: alice\nStatus: Removed"])

    def test_manual_delete_while_another_key_is_quota_disabled_emits_only_manual_removal(self):
        old = {
            "key-disabled": api_record(alias="tuankhang", cpa_deleted=False, in_quota=True, in_proxy_config=False, disabled_by_quota=True),
            "key-removed": api_record(alias="hotranquocthang", cpa_deleted=False, in_quota=True, in_proxy_config=True, disabled_by_quota=False),
        }
        new = {
            "key-disabled": api_record(alias="tuankhang", cpa_deleted=False, in_quota=True, in_proxy_config=False, disabled_by_quota=True),
            "key-removed": api_record(alias="hotranquocthang", cpa_deleted=True, in_quota=False, in_proxy_config=False, disabled_by_quota=False),
        }

        sent, messages = collect_notification(old, new, now=20)

        self.assertEqual(sent, 1)
        self.assertEqual(messages, ["API key deleted\n\nUser: hotranquocthang\nStatus: Removed"])

    def test_manual_delete_readd_still_emits_one_remove_then_one_add(self):
        active = {"key-1": api_record(alias="alice")}
        removed = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        watch = {"snapshot": active}
        sent_messages = []

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            merge_pending_change_event(watch, build_change_events(active, removed)[0])
        watch["snapshot"] = removed
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=25):
            merge_pending_change_event(watch, build_change_events(removed, active)[0])
        watch["snapshot"] = active
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=30), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)

        self.assertEqual([message.split("\n", 1)[0] for message in sent_messages], ["API key deleted", "API key created"])

    def test_manual_delete_is_not_mistaken_for_quota_enforcer_only_change(self):
        old = {"key-1": api_record(alias="alice")}
        new = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}

        events = build_change_events(old, new)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["logical_type"], "key_removed")
        self.assertEqual(events[0]["title"], "API key deleted")

    def test_quick_delete_after_sent_add_emits_one_removed_notification(self):
        absent = {"test-key-quick-delete": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        active = {"test-key-quick-delete": api_record(alias="alice", cpa_deleted=False, in_quota=True, in_proxy_config=True)}
        removed = {"test-key-quick-delete": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        state = {"change_watch": {"snapshot": absent, "fingerprint": change_watch.change_watch_fingerprint(absent), "checked_at": 0}}
        sent_messages = []

        with mock.patch.object(change_watch, "change_watch_snapshot", return_value=active), \
             mock.patch.object(change_watch, "CHANGE_WATCH_INTERVAL_SECONDS", 1), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=10), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            process_change_notifications(state, force=True)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            flush_pending_change_notifications(state["change_watch"])

        self.assertEqual(sent_messages, ["API key created\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M"])
        state["change_watch"]["snapshot"] = absent
        state["change_watch"]["fingerprint"] = change_watch.change_watch_fingerprint(absent)
        state["change_watch"].pop("pending", None)

        with mock.patch.object(change_watch, "change_watch_snapshot", return_value=removed), \
             mock.patch.object(change_watch, "CHANGE_WATCH_INTERVAL_SECONDS", 1), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=30), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            process_change_notifications(state, force=True)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=45), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            flush_pending_change_notifications(state["change_watch"])

        self.assertEqual(sent_messages, [
            "API key created\n\nUser: alice\nStatus: Active\nDaily quota: 4M\nWeekly quota: 16M",
            "API key deleted\n\nUser: alice\nStatus: Removed",
        ])
        self.assertNotIn("test-key-quick-delete", sent_messages[-1])

    def test_known_active_removed_snapshot_without_active_baseline_sends_one_delete(self):
        removed = {"test-key-known-active": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        state = {
            "change_watch": {
                "snapshot": removed,
                "fingerprint": change_watch.change_watch_fingerprint(removed),
                "checked_at": 0,
                "known_active_keys": {
                    "test-key-known-active": {"account": "alice", "last_seen": 10, "last_present": 10},
                },
            },
        }
        sent_messages = []

        with mock.patch.object(change_watch, "change_watch_snapshot", return_value=removed), \
             mock.patch.object(change_watch, "CHANGE_WATCH_INTERVAL_SECONDS", 1), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            process_change_notifications(state, force=True)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=35), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            flush_pending_change_notifications(state["change_watch"])

        self.assertEqual(sent_messages, ["API key deleted\n\nUser: alice\nStatus: Removed"])
        self.assertNotIn("test-key-known-active", sent_messages[0])

    def test_repeated_known_active_removed_snapshots_do_not_resend_delete(self):
        removed = {"test-key-repeat-delete": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        state = {
            "change_watch": {
                "snapshot": removed,
                "fingerprint": change_watch.change_watch_fingerprint(removed),
                "checked_at": 0,
                "known_active_keys": {
                    "test-key-repeat-delete": {"account": "alice", "last_seen": 10, "last_present": 10},
                },
            },
        }
        sent_messages = []

        with mock.patch.object(change_watch, "change_watch_snapshot", return_value=removed), \
             mock.patch.object(change_watch, "CHANGE_WATCH_INTERVAL_SECONDS", 1), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            process_change_notifications(state, force=True)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=35), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            flush_pending_change_notifications(state["change_watch"])

        with mock.patch.object(change_watch, "change_watch_snapshot", return_value=removed), \
             mock.patch.object(change_watch, "CHANGE_WATCH_INTERVAL_SECONDS", 1), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=50), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            process_change_notifications(state, force=True)
        with mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "now_ts", return_value=65), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            flush_pending_change_notifications(state["change_watch"])

        self.assertEqual(sent_messages, ["API key deleted\n\nUser: alice\nStatus: Removed"])

    def test_late_cpa_soft_delete_after_removal_does_not_send_duplicate_delete(self):
        active = {"key-1": api_record(alias="alice")}
        cpa_tail = {"key-1": api_record(alias="alice", cpa_deleted=False, in_quota=False, in_proxy_config=False)}
        soft_deleted = {"key-1": api_record(alias="alice", cpa_deleted=True, in_quota=False, in_proxy_config=False)}
        watch = {"snapshot": cpa_tail}
        sent_messages = []

        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=0):
            for event in build_change_events(active, cpa_tail):
                merge_pending_change_event(watch, event)
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=20), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 1)

        watch["snapshot"] = soft_deleted
        with mock.patch.object(change_watch, "now_ts", return_value=25):
            for event in build_change_events(cpa_tail, soft_deleted):
                merge_pending_change_event(watch, event)
        with mock.patch.object(change_watch, "REMOVAL_HOLDBACK_SECONDS", 10), \
             mock.patch.object(change_watch, "CHANGE_REMOVAL_DEBOUNCE_SECONDS", 8), \
             mock.patch.object(change_watch, "CHANGE_NOTIFICATION_DEBOUNCE_SECONDS", 3), \
             mock.patch.object(change_watch, "now_ts", return_value=40), \
             mock.patch.object(change_watch, "send_telegram", side_effect=lambda text, dry_run=False, **kwargs: sent_messages.append(text) or True):
            self.assertEqual(flush_pending_change_notifications(watch), 0)

        self.assertEqual(sent_messages, ["API key deleted\n\nUser: alice\nStatus: Removed"])

    def test_auth_weekly_auto_disable_transition_stays_silent(self):
        old = {"auth:codex-one.json": auth_record(disabled=False)}
        new = {"auth:codex-one.json": auth_record(disabled=True)}

        sent, messages = collect_notification(old, new, state=auth_transition_state("disabled"))

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_auth_weekly_auto_enable_transition_stays_silent(self):
        old = {"auth:codex-one.json": auth_record(disabled=True)}
        new = {"auth:codex-one.json": auth_record(disabled=False)}

        sent, messages = collect_notification(old, new, state=auth_transition_state("enabled"))

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_auth_daily_auto_disable_transition_stays_silent(self):
        old = {"auth:codex-one.json": auth_record(disabled=False)}
        new = {"auth:codex-one.json": auth_record(disabled=True)}

        sent, messages = collect_notification(old, new, state=auth_transition_state("disabled", reasons=["daily"]))

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_auth_daily_auto_enable_transition_stays_silent(self):
        old = {"auth:codex-one.json": auth_record(disabled=True)}
        new = {"auth:codex-one.json": auth_record(disabled=False)}

        sent, messages = collect_notification(old, new, state=auth_transition_state("enabled", reasons=["daily"]))

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_auth_overlapping_daily_weekly_transition_stays_silent(self):
        old = {"auth:codex-one.json": auth_record(disabled=False)}
        new = {"auth:codex-one.json": auth_record(disabled=True)}

        sent, messages = collect_notification(old, new, state=auth_transition_state("disabled", reasons=["daily", "weekly"]))

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_manual_auth_account_status_only_disable_stays_silent(self):
        old = {"auth:codex-one.json": auth_record(disabled=False)}
        new = {"auth:codex-one.json": auth_record(disabled=True)}

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_manual_auth_account_status_only_enable_stays_silent(self):
        old = {"auth:codex-one.json": auth_record(disabled=True)}
        new = {"auth:codex-one.json": auth_record(disabled=False)}

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 0)
        self.assertEqual(messages, [])

    def test_auth_alias_change_still_notifies(self):
        old = {"auth:codex-one.json": auth_record(alias="codex-account", disabled=False)}
        new = {"auth:codex-one.json": auth_record(alias="renamed-account", disabled=False)}

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 1)
        self.assertIn("Proxy account changed", messages[0])
        self.assertIn("Alias: codex-account -> renamed-account", messages[0])

    def test_auth_status_plus_alias_change_still_notifies(self):
        old = {"auth:codex-one.json": auth_record(alias="codex-account", disabled=False)}
        new = {"auth:codex-one.json": auth_record(alias="renamed-account", disabled=True)}

        sent, messages = collect_notification(old, new, state=auth_transition_state("disabled"))

        self.assertEqual(sent, 1)
        self.assertIn("Proxy account changed", messages[0])
        self.assertIn("Status: enabled -> disabled", messages[0])
        self.assertIn("Alias: codex-account -> renamed-account", messages[0])

    def test_auth_type_change_still_notifies(self):
        old = {"auth:codex-one.json": auth_record(account_type="codex", disabled=False)}
        new = {"auth:codex-one.json": auth_record(account_type="antigravity", disabled=False)}

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 1)
        self.assertIn("Proxy account changed", messages[0])
        self.assertIn("Type: codex -> antigravity", messages[0])

    def test_auth_read_error_change_still_notifies(self):
        old = {"auth:codex-one.json": auth_record(disabled=False)}
        new = {"auth:codex-one.json": auth_record(disabled=False, read_error="failed")}

        sent, messages = collect_notification(old, new)

        self.assertEqual(sent, 1)
        self.assertIn("Proxy account changed", messages[0])
        self.assertIn("Status: enabled -> unreadable", messages[0])
        self.assertIn("Read status changed", messages[0])

    def test_non_auth_status_only_event_is_not_suppressed(self):
        event = {
            "key": "key-1",
            "logical_type": "quota_changed",
            "title": "Quota updated",
            "account": "alice",
            "changes": ["Status: enabled -> disabled"],
        }

        self.assertFalse(is_change_event_suppressed({}, event))


if __name__ == "__main__":
    unittest.main()
