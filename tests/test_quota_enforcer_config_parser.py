import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "quota-enforcer" / "quota_enforcer.py"


def load_quota_enforcer_module():
    spec = importlib.util.spec_from_file_location("quota_enforcer_for_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class QuotaEnforcerConfigParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_quota_enforcer_module()

    def write_quota_file(self, path, keys):
        path.write_text(
            json.dumps({"timezone": "UTC", "dry_run": False, "keys": keys}, indent=2) + "\n",
            encoding="utf-8",
        )

    def write_cpa_db(self, path, rows):
        con = sqlite3.connect(path)
        try:
            con.execute(
                """
                CREATE TABLE cpa_api_keys (
                    api_key TEXT PRIMARY KEY,
                    is_deleted INTEGER DEFAULT 0
                )
                """
            )
            for key, is_deleted in rows:
                con.execute("INSERT INTO cpa_api_keys (api_key, is_deleted) VALUES (?, ?)", (key, int(is_deleted)))
            con.commit()
        finally:
            con.close()

    def test_parse_api_keys_block_returns_empty_list_for_inline_empty_block(self):
        lines, start, end, keys = self.module.parse_api_keys_block("server: true\napi-keys: []\nother: value\n")

        self.assertEqual(lines, ["server: true", "api-keys: []", "other: value"])
        self.assertEqual(start, 1)
        self.assertEqual(end, 2)
        self.assertEqual(keys, [])

    def test_parse_api_keys_block_preserves_non_empty_key_order(self):
        config_text = "server: true\napi-keys:\n  - \"alpha-key\"\n  - 'beta-key'\nother: value\n"

        lines, start, end, keys = self.module.parse_api_keys_block(config_text)

        self.assertEqual(lines, ["server: true", "api-keys:", "  - \"alpha-key\"", "  - 'beta-key'", "other: value"])
        self.assertEqual(start, 1)
        self.assertEqual(end, 4)
        self.assertEqual(keys, ["alpha-key", "beta-key"])

    def test_sync_keeps_existing_quota_item_absent_from_config_without_disabled_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            self.write_quota_file(quota_path, [{"name": "Quota Disabled", "key": "quota-disabled-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": []}), encoding="utf-8")

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path):
                cfg = self.module.load_quota_config()
                self.module.sync_quota_config_with_config_keys(cfg)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))

        self.assertEqual([item["name"] for item in saved["keys"]], ["Quota Disabled"])
        self.assertEqual([item["key"] for item in saved["keys"]], ["quota-disabled-key"])

    def test_main_keeps_over_daily_key_absent_from_config_and_marks_disabled_by_quota(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Quota Disabled", "key": "quota-disabled-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": []}), encoding="utf-8")

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"quota-disabled-key": {"today_tokens": 150, "week_tokens": 0, "requests_today": 1}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual([item["name"] for item in saved["keys"]], ["Quota Disabled"])
        self.assertEqual([item["key"] for item in saved["keys"]], ["quota-disabled-key"])
        self.assertEqual(state.get("disabled_by_quota"), ["quota-disabled-key"])

    def test_previously_disabled_quota_item_absent_from_config_survives_next_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Still Disabled", "key": "still-disabled-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": ["still-disabled-key"]}), encoding="utf-8")

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"still-disabled-key": {"today_tokens": 200, "week_tokens": 0, "requests_today": 2}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual([item["name"] for item in saved["keys"]], ["Still Disabled"])
        self.assertEqual([item["key"] for item in saved["keys"]], ["still-disabled-key"])
        self.assertEqual(state.get("disabled_by_quota"), ["still-disabled-key"])

    def test_cpa_deleted_prune_preserves_manually_disabled_quota_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            self.write_quota_file(quota_path, [{"name": "Manual Disabled", "key": "manual-disabled-key", "daily_token_limit": 100}])
            state = {"disabled_by_quota": [], "manually_disabled_keys": ["manual-disabled-key"]}

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path):
                cfg = self.module.load_quota_config()
                removed = self.module.prune_cpa_deleted_quota_items(
                    cfg,
                    state,
                    {"manual-disabled-key"},
                    dry_run=False,
                    cpa_evidence_reliable=True,
                )
                saved = json.loads(quota_path.read_text(encoding="utf-8"))

        self.assertEqual(removed, set())
        self.assertEqual([item["key"] for item in saved["keys"]], ["manual-disabled-key"])
        self.assertEqual(state.get("manually_disabled_keys"), ["manual-disabled-key"])

    def test_over_weekly_key_is_disabled_and_kept_in_quotas(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Weekly Disabled", "key": "weekly-disabled-key", "daily_token_limit": 100, "weekly_token_limit": 400}])
            config_path.write_text("api-keys:\n  - \"weekly-disabled-key\"\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": []}), encoding="utf-8")

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"weekly-disabled-key": {"today_tokens": 50, "week_tokens": 450, "requests_today": 1}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual([item["key"] for item in saved["keys"]], ["weekly-disabled-key"])
        self.assertEqual(state.get("disabled_by_quota"), ["weekly-disabled-key"])
        self.assertEqual(config_keys, [])

    def test_daily_recovered_but_weekly_exceeded_stays_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Weekly Still Disabled", "key": "weekly-still-disabled-key", "daily_token_limit": 100, "weekly_token_limit": 400}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": ["weekly-still-disabled-key"]}), encoding="utf-8")

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"weekly-still-disabled-key": {"today_tokens": 50, "week_tokens": 450, "requests_today": 1}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual(state.get("disabled_by_quota"), ["weekly-still-disabled-key"])
        self.assertEqual(config_keys, [])

    def test_daily_and_weekly_recovered_restores_key_and_clears_disabled_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Recovered", "key": "recovered-key", "daily_token_limit": 100, "weekly_token_limit": 400}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": ["recovered-key"]}), encoding="utf-8")

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"recovered-key": {"today_tokens": 50, "week_tokens": 250, "requests_today": 1}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual(state.get("disabled_by_quota"), [])
        self.assertEqual(config_keys, ["recovered-key"])

    def test_missing_weekly_limit_defaults_to_four_times_daily(self):
        with tempfile.TemporaryDirectory() as tmp:
            quota_path = Path(tmp) / "quotas.json"
            self.write_quota_file(quota_path, [{"name": "Default Weekly", "key": "default-weekly-key", "daily_token_limit": 100}])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path):
                cfg = self.module.load_quota_config()

        self.assertEqual(cfg["keys"][0]["weekly_token_limit"], 400)
        self.assertTrue(cfg["keys"][0]["_weekly_token_limit_defaulted"])

    def test_null_daily_and_weekly_limits_are_unlimited(self):
        with tempfile.TemporaryDirectory() as tmp:
            quota_path = Path(tmp) / "quotas.json"
            self.write_quota_file(quota_path, [{"name": "Unlimited", "key": "unlimited-key", "daily_token_limit": None, "weekly_token_limit": None}])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path):
                cfg = self.module.load_quota_config()

        self.assertIsNone(cfg["keys"][0]["daily_token_limit"])
        self.assertIsNone(cfg["keys"][0]["weekly_token_limit"])

    def test_manual_cpa_delete_removes_key_from_quotas_state_and_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [
                {"name": "Deleted", "key": "deleted-key", "daily_token_limit": 100},
                {"name": "Kept", "key": "kept-key", "daily_token_limit": 100},
            ])
            config_path.write_text("api-keys:\n  - \"deleted-key\"\n  - \"kept-key\"\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": []}), encoding="utf-8")
            self.write_cpa_db(usage_db, [("deleted-key", 1), ("kept-key", 0)])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={
                     "deleted-key": {"today_tokens": 0, "week_tokens": 0, "requests_today": 0},
                     "kept-key": {"today_tokens": 0, "week_tokens": 0, "requests_today": 0},
                 }), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual([item["key"] for item in saved["keys"]], ["kept-key"])
        self.assertEqual(state.get("disabled_by_quota"), [])
        self.assertEqual(config_keys, ["kept-key"])

    def test_cpa_active_quota_disabled_key_absent_from_config_is_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Active Disabled", "key": "active-disabled-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": ["active-disabled-key"]}), encoding="utf-8")
            self.write_cpa_db(usage_db, [("active-disabled-key", 0)])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"active-disabled-key": {"today_tokens": 150, "week_tokens": 0, "requests_today": 1}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual([item["key"] for item in saved["keys"]], ["active-disabled-key"])
        self.assertEqual(state.get("disabled_by_quota"), ["active-disabled-key"])

    def test_cpa_deleted_quota_disabled_key_absent_from_config_is_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Deleted Disabled", "key": "deleted-disabled-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": ["deleted-disabled-key"]}), encoding="utf-8")
            self.write_cpa_db(usage_db, [("deleted-disabled-key", 1)])
            logs = []

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"deleted-disabled-key": {"today_tokens": 150, "week_tokens": 0, "requests_today": 1}}), \
                 mock.patch.object(self.module, "log", side_effect=logs.append), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual([item["key"] for item in saved["keys"]], ["deleted-disabled-key"])
        self.assertEqual(state.get("disabled_by_quota"), ["deleted-disabled-key"])
        self.assertEqual(state.get("cpa_deleted_while_quota_disabled"), ["deleted-disabled-key"])
        self.assertEqual(config_keys, [])
        self.assertTrue(any("protected_stale_cpa_tombstone_count=1" in line for line in logs))
        self.assertFalse(any("deleted-disabled-key" in line for line in logs))

    def test_protected_cpa_tombstone_survives_daily_reset_and_restores_config_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Reset Restored", "key": "reset-restored-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": ["reset-restored-key"]}), encoding="utf-8")
            self.write_cpa_db(usage_db, [("reset-restored-key", 1)])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"reset-restored-key": {"today_tokens": 150, "week_tokens": 0, "requests_today": 1}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"reset-restored-key": {"today_tokens": 0, "week_tokens": 0, "requests_today": 0}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual([item["key"] for item in saved["keys"]], ["reset-restored-key"])
        self.assertEqual(state.get("disabled_by_quota"), [])
        self.assertEqual(state.get("cpa_deleted_while_quota_disabled"), ["reset-restored-key"])
        self.assertEqual(config_keys, ["reset-restored-key"])

    def test_active_cpa_delete_without_protection_still_prunes_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Active Deleted", "key": "active-deleted-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys:\n  - \"active-deleted-key\"\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": []}), encoding="utf-8")
            self.write_cpa_db(usage_db, [("active-deleted-key", 1)])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"active-deleted-key": {"today_tokens": 0, "week_tokens": 0, "requests_today": 0}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual(saved["keys"], [])
        self.assertEqual(state.get("disabled_by_quota"), [])
        self.assertNotIn("active-deleted-key", state.get("cpa_deleted_while_quota_disabled", []))
        self.assertEqual(config_keys, [])

    def test_protected_cpa_tombstone_clears_after_cpa_row_is_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Protection Cleared", "key": "protection-cleared-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys:\n  - \"protection-cleared-key\"\n", encoding="utf-8")
            state_path.write_text(json.dumps({
                "disabled_by_quota": [],
                "cpa_deleted_while_quota_disabled": ["protection-cleared-key"],
            }), encoding="utf-8")
            self.write_cpa_db(usage_db, [("protection-cleared-key", 0)])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"protection-cleared-key": {"today_tokens": 0, "week_tokens": 0, "requests_today": 0}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual(state.get("disabled_by_quota"), [])
        self.assertEqual(state.get("cpa_deleted_while_quota_disabled"), [])
        self.assertEqual(config_keys, ["protection-cleared-key"])

    def test_cpa_active_stale_disabled_state_over_limit_is_kept_and_readded_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Stale Disabled", "key": "stale-disabled-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": []}), encoding="utf-8")
            self.write_cpa_db(usage_db, [("stale-disabled-key", 0)])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"stale-disabled-key": {"today_tokens": 150, "week_tokens": 0, "requests_today": 1}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual([item["key"] for item in saved["keys"]], ["stale-disabled-key"])
        self.assertEqual(state.get("disabled_by_quota"), ["stale-disabled-key"])


if __name__ == "__main__":
    unittest.main()
