from __future__ import annotations

from contextlib import contextmanager
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import telegram_alerts.actions as actions_module
from telegram_alerts.handlers import handle_callback
import telegram_alerts.mutation_verification as verification_module
import telegram_alerts.quota_config as quota_config_module


@contextmanager
def unlocked_runtime():
    yield


def create_usage_db(path: Path, *, rows=()):
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
        for api_key, alias, is_deleted in rows:
            con.execute(
                """
                INSERT INTO cpa_api_keys
                  (api_key, display_key, key_alias, is_deleted, last_synced_at, created_at, updated_at)
                VALUES (?, 'masked', ?, ?, 'old', 'old', 'old')
                """,
                (api_key, alias, is_deleted),
            )
        con.commit()
    finally:
        con.close()


@contextmanager
def verifier_runtime(*, config_text="api-keys: []\n", quotas=None, state=None, db_rows=()):
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        config_path = base / "config.yaml"
        quota_path = base / "quotas.json"
        state_path = base / "state.json"
        db_path = base / "app.db"
        if config_text is not None:
            config_path.write_text(config_text, encoding="utf-8")
        if quotas is not None:
            quota_path.write_text(json.dumps(quotas) + "\n", encoding="utf-8")
        if state is not None:
            state_path.write_text(json.dumps(state) + "\n", encoding="utf-8")
        create_usage_db(db_path, rows=db_rows)
        with mock.patch.object(quota_config_module, "CLIPROXY_CONFIG", config_path), \
             mock.patch.object(quota_config_module, "QUOTA_CONFIG", quota_path), \
             mock.patch.object(quota_config_module, "QUOTA_STATE", state_path), \
             mock.patch.object(quota_config_module, "USAGE_DB", db_path):
            yield base, config_path, quota_path, state_path, db_path


@contextmanager
def action_runtime(**kwargs):
    with verifier_runtime(**kwargs) as paths:
        _base, config_path, _quota_path, state_path, _db_path = paths
        with mock.patch.object(actions_module, "CLIPROXY_CONFIG", config_path), \
             mock.patch.object(actions_module, "QUOTA_STATE", state_path), \
             mock.patch.object(actions_module, "quota_runtime_lock", unlocked_runtime), \
             mock.patch.object(actions_module, "backup_action_files", return_value="backup"):
            yield paths


class MutationVerificationTests(unittest.TestCase):
    def test_proxy_config_unavailable_warns_without_key_presence_mismatch(self):
        key = "sample-proxy-unavailable-key"
        with verifier_runtime(
            config_text=None,
            quotas={"keys": [{"key": key, "name": "sample", "daily_token_limit": 1}]},
            state={},
            db_rows=[(key, "sample", 0)],
        ):
            result = verification_module.verify_mutation("key_enable", {"key": key}, changed_key=key)

        self.assertEqual(result.warning_line(), "Saved, but verification could not confirm proxy config.")
        self.assertIn("proxy config", result.unavailable)
        self.assertNotIn("proxy config does not list this key", result.mismatches)
        self.assertNotIn(key, result.warning_line())

    def test_quota_config_unavailable_warns_without_missing_quota_mismatch(self):
        key = "sample-quota-unavailable-key"
        with verifier_runtime(
            config_text=f'api-keys:\n  - "{key}"\n',
            quotas=None,
            state={},
            db_rows=[(key, "sample", 0)],
        ):
            result = verification_module.verify_mutation("key_enable", {"key": key}, changed_key=key)

        self.assertEqual(result.warning_line(), "Saved, but verification could not confirm quota config.")
        self.assertIn("quota config", result.unavailable)
        self.assertNotIn("quota config is missing this key", result.mismatches)
        self.assertNotIn(key, result.warning_line())

    def test_key_delete_warns_when_quota_state_cannot_be_read(self):
        key = "sample-state-unavailable-key"
        with verifier_runtime(
            config_text="api-keys: []\n",
            quotas={"keys": []},
            state={},
            db_rows=[(key, "sample", 1)],
        ), mock.patch("telegram_alerts.mutation_verification.load_json", side_effect=OSError("state unavailable")):
            result = verification_module.verify_mutation("key_delete", {"key": key}, changed_key=key)

        self.assertEqual(result.warning_line(), "Saved, but verification could not confirm quota state.")
        self.assertIn("quota state", result.unavailable)
        self.assertFalse(result.mismatches)
        self.assertNotIn(key, result.warning_line())

    def test_quota_set_warns_when_before_marker_snapshot_cannot_be_read(self):
        key = "sample-quota-state-key"
        with verifier_runtime(
            config_text=f'api-keys:\n  - "{key}"\n',
            quotas={"keys": [{"key": key, "name": "sample", "daily_token_limit": 20_000_000}]},
            state={},
            db_rows=[(key, "sample", 0)],
        ):
            with mock.patch("telegram_alerts.mutation_verification.load_json", side_effect=OSError("state unavailable")):
                before = verification_module.quota_marker_snapshot()
            result = verification_module.verify_mutation(
                "quota_set",
                {"key": key, "daily": 20_000_000, "weekly": "default"},
                changed_key=key,
                before_markers=before,
            )

        self.assertEqual(result.warning_line(), "Saved, but verification could not confirm quota state.")
        self.assertIn("quota state", result.unavailable)
        self.assertFalse(result.mismatches)
        self.assertNotIn(key, result.warning_line())

    def test_key_create_verification_pass_keeps_existing_success_copy(self):
        key = "sample-created-key"
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "key_create",
                    "params": {"alias": "sample", "name": "sample", "daily": 20_000_000, "weekly": "default", "key": key},
                    "summary": "Pending API key creation\n\nUser: sample",
                    "expires_at": 99_999_999_999,
                }
            }
        }
        with action_runtime(config_text="api-keys: []\n", quotas={"keys": []}, state={}, db_rows=[]):
            result = handle_callback("confirm:abc123", state, chat_id="chat", user_id="user", message_id=1)

        self.assertEqual(
            result["text"],
            "API key created.\n\n"
            "User: sample\n"
            f"Base URL: {actions_module.API_PUBLIC_BASE_URL}\n"
            f"API key: {key}\n\n"
            "Keep this key private.",
        )
        self.assertEqual(result["text"].count(key), 1)
        self.assertNotIn("Saved, but verification", result["text"])

    def test_key_create_verification_mismatch_appends_short_secret_safe_warning(self):
        key = "sample-created-mismatch-key"
        state = {
            "pending_actions": {
                "chat:user": {
                    "code": "abc123",
                    "type": "key_create",
                    "params": {"alias": "sample", "name": "sample", "daily": 20_000_000, "weekly": "default", "key": key},
                    "summary": "Pending API key creation\n\nUser: sample",
                    "expires_at": 99_999_999_999,
                }
            }
        }
        with action_runtime(config_text="api-keys: []\n", quotas={"keys": []}, state={}, db_rows=[]), \
             mock.patch.object(actions_module, "write_config_api_keys", return_value=None):
            result = handle_callback("confirm:abc123", state, chat_id="chat", user_id="user", message_id=1)

        self.assertIn("API key created.", result["text"])
        self.assertIn("API key:", result["text"])
        self.assertIn("Saved, but verification found a mismatch: proxy config does not list this key.", result["text"])
        self.assertEqual(result["text"].count(key), 1)
        self.assertNotIn(key, result["text"].split("Saved, but", 1)[1])


if __name__ == "__main__":
    unittest.main()
