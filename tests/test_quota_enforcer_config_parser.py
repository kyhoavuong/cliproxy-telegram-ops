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

    def setUp(self):
        real_quota_config = self.module.BASE_DIR / "quota-enforcer" / "quotas.json"
        real_state_file = self.module.BASE_DIR / "quota-enforcer" / "state.json"
        real_proxy_config = self.module.BASE_DIR / "config" / "config.yaml"
        original_save_quota_config = self.module.save_quota_config
        original_save_quota_state = self.module.save_quota_state
        original_write_config_preserve_inode = self.module.write_config_preserve_inode
        runtime_guard_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(runtime_guard_tmp.cleanup)
        guarded_usage_db = Path(runtime_guard_tmp.name) / "missing-app.db"

        def guarded_save_quota_config(cfg):
            if Path(self.module.QUOTA_CONFIG) == real_quota_config:
                raise AssertionError("test attempted to write real quota-enforcer/quotas.json")
            return original_save_quota_config(cfg)

        def guarded_save_quota_state(state):
            if Path(self.module.STATE_FILE) == real_state_file:
                raise AssertionError("test attempted to write real quota-enforcer/state.json")
            return original_save_quota_state(state)

        def guarded_write_config(path, content):
            if Path(path) == real_proxy_config:
                raise AssertionError("test attempted to write real config/config.yaml")
            return original_write_config_preserve_inode(path, content)

        patchers = [
            mock.patch.object(self.module, "USAGE_DB", guarded_usage_db),
            mock.patch.object(self.module, "save_quota_config", side_effect=guarded_save_quota_config),
            mock.patch.object(self.module, "save_quota_state", side_effect=guarded_save_quota_state),
            mock.patch.object(self.module, "write_config_preserve_inode", side_effect=guarded_write_config),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

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

    def test_quota_enforcer_lock_path_is_shared_runtime_lock(self):
        self.assertEqual(
            self.module.LOCK_FILE,
            self.module.BASE_DIR / "quota-enforcer" / "quota_enforcer.lock",
        )

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

    def test_sync_does_not_create_unlimited_quota_rows_from_proxy_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            self.write_quota_file(quota_path, [{"name": "Managed", "key": "managed-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys:\n  - \"managed-key\"\n  - \"config-only-key\"\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": []}), encoding="utf-8")

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path):
                cfg = self.module.load_quota_config()
                self.module.sync_quota_config_with_config_keys(cfg)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))

        self.assertEqual([item["key"] for item in saved["keys"]], ["managed-key"])
        self.assertEqual(saved["keys"][0]["daily_token_limit"], 100)

    def test_empty_quotas_with_non_empty_proxy_config_does_not_recreate_unlimited_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [])
            config_path.write_text("api-keys:\n  - \"config-only-key\"\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": []}), encoding="utf-8")

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual(saved["keys"], [])
        self.assertEqual(config_keys, ["config-only-key"])

    def test_runtime_write_guards_block_unpatched_quota_config_writes(self):
        cfg = {"timezone": "UTC", "dry_run": False, "keys": []}

        with self.assertRaisesRegex(AssertionError, "real quota-enforcer/quotas.json"):
            self.module.save_quota_config(cfg)

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
            config_path = tmp_path / "config.yaml"
            self.write_quota_file(quota_path, [{"name": "Manual Disabled", "key": "manual-disabled-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state = {"disabled_by_quota": [], "manually_disabled_keys": ["manual-disabled-key"]}

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path):
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

    def test_cpa_deleted_prune_preserves_active_proxy_key_with_stale_cpa_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            self.write_quota_file(quota_path, [{"name": "Stale Active", "key": "stale-active-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys:\n  - \"stale-active-key\"\n", encoding="utf-8")
            state = {"disabled_by_quota": [], "manually_disabled_keys": ["stale-active-key"]}

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path):
                cfg = self.module.load_quota_config()
                removed = self.module.prune_cpa_deleted_quota_items(
                    cfg,
                    state,
                    {"stale-active-key"},
                    dry_run=False,
                    cpa_evidence_reliable=True,
                )
                saved = json.loads(quota_path.read_text(encoding="utf-8"))

        self.assertEqual(removed, set())
        self.assertEqual([item["key"] for item in saved["keys"]], ["stale-active-key"])
        self.assertEqual(state.get("manually_disabled_keys"), ["stale-active-key"])

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
            config_path.write_text("api-keys:\n  - \"kept-key\"\n", encoding="utf-8")
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

    def test_cpa_tombstone_created_between_disabled_run_and_daily_reset_is_protected(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Late Tombstone", "key": "late-tombstone-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": ["late-tombstone-key"]}), encoding="utf-8")
            self.write_cpa_db(usage_db, [("late-tombstone-key", 1)])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"late-tombstone-key": {"today_tokens": 0, "week_tokens": 0, "requests_today": 0}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual([item["key"] for item in saved["keys"]], ["late-tombstone-key"])
        self.assertEqual(state.get("disabled_by_quota"), [])
        self.assertEqual(state.get("cpa_deleted_while_quota_disabled"), ["late-tombstone-key"])
        self.assertEqual(config_keys, ["late-tombstone-key"])

    def test_reset_tombstone_is_saved_before_config_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Interrupted Restore", "key": "interrupted-restore-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({"disabled_by_quota": ["interrupted-restore-key"]}), encoding="utf-8")
            self.write_cpa_db(usage_db, [("interrupted-restore-key", 1)])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"interrupted-restore-key": {"today_tokens": 0, "week_tokens": 0, "requests_today": 0}}), \
                 mock.patch.object(self.module, "update_config_api_keys", side_effect=RuntimeError("stop before config restore")), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                with self.assertRaisesRegex(RuntimeError, "stop before config restore"):
                    self.module.main()
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual(state.get("disabled_by_quota"), [])
        self.assertEqual(state.get("cpa_deleted_while_quota_disabled"), ["interrupted-restore-key"])
        self.assertEqual(state.get("cpa_deleted_restore_pending"), ["interrupted-restore-key"])
        self.assertEqual(config_keys, [])

    def test_pending_reset_tombstone_survives_next_run_and_restores_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Pending Restore", "key": "pending-restore-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({
                "disabled_by_quota": [],
                "cpa_deleted_while_quota_disabled": ["pending-restore-key"],
                "cpa_deleted_restore_pending": ["pending-restore-key"],
            }), encoding="utf-8")
            self.write_cpa_db(usage_db, [("pending-restore-key", 1)])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"pending-restore-key": {"today_tokens": 0, "week_tokens": 0, "requests_today": 0}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual([item["key"] for item in saved["keys"]], ["pending-restore-key"])
        self.assertEqual(state.get("disabled_by_quota"), [])
        self.assertEqual(state.get("cpa_deleted_while_quota_disabled"), ["pending-restore-key"])
        self.assertNotIn("cpa_deleted_restore_pending", state)
        self.assertEqual(config_keys, ["pending-restore-key"])

    def test_cpa_delete_absent_from_proxy_config_prunes_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Active Deleted", "key": "active-deleted-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
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

    def test_cpa_delete_preserves_quota_row_when_proxy_config_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            missing_config_path = tmp_path / "missing-config.yaml"
            cfg = {
                "keys": [
                    {"name": "Unreadable Proxy", "key": "unreadable-proxy-key", "daily_token_limit": 100}
                ]
            }
            state = {"disabled_by_quota": []}

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", missing_config_path):
                removed = self.module.prune_cpa_deleted_quota_items(
                    cfg,
                    state,
                    {"unreadable-proxy-key"},
                    dry_run=False,
                    cpa_evidence_reliable=True,
                )

        self.assertEqual(removed, set())
        self.assertEqual([item["key"] for item in cfg["keys"]], ["unreadable-proxy-key"])

    def test_cpa_delete_preserves_quota_row_when_proxy_config_has_no_api_keys_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            self.write_quota_file(quota_path, [{"name": "Malformed Proxy", "key": "malformed-proxy-key", "daily_token_limit": 100}])
            config_path.write_text("server: true\n", encoding="utf-8")
            state = {"disabled_by_quota": []}

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path):
                cfg = self.module.load_quota_config()
                removed = self.module.prune_cpa_deleted_quota_items(
                    cfg,
                    state,
                    {"malformed-proxy-key"},
                    dry_run=False,
                    cpa_evidence_reliable=True,
                )
                saved = json.loads(quota_path.read_text(encoding="utf-8"))

        self.assertEqual(removed, set())
        self.assertEqual([item["key"] for item in saved["keys"]], ["malformed-proxy-key"])

    def test_existing_protected_tombstone_does_not_mask_later_manual_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            quota_path = tmp_path / "quotas.json"
            config_path = tmp_path / "config.yaml"
            state_path = tmp_path / "state.json"
            usage_db = tmp_path / "app.db"
            lock_path = tmp_path / "quota.lock"
            self.write_quota_file(quota_path, [{"name": "Later Deleted", "key": "later-deleted-key", "daily_token_limit": 100}])
            config_path.write_text("api-keys: []\n", encoding="utf-8")
            state_path.write_text(json.dumps({
                "disabled_by_quota": [],
                "cpa_deleted_while_quota_disabled": ["later-deleted-key"],
            }), encoding="utf-8")
            self.write_cpa_db(usage_db, [("later-deleted-key", 1)])

            with mock.patch.object(self.module, "QUOTA_CONFIG", quota_path), \
                 mock.patch.object(self.module, "CLIPROXY_CONFIG", config_path), \
                 mock.patch.object(self.module, "STATE_FILE", state_path), \
                 mock.patch.object(self.module, "USAGE_DB", usage_db), \
                 mock.patch.object(self.module, "LOCK_FILE", lock_path), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", ""), \
                 mock.patch.object(self.module, "get_usage_by_key", return_value={"later-deleted-key": {"today_tokens": 0, "week_tokens": 0, "requests_today": 0}}), \
                 mock.patch.object(self.module, "sys") as sys_mock:
                sys_mock.argv = ["quota_enforcer.py"]
                self.assertEqual(self.module.main(), 0)
                saved = json.loads(quota_path.read_text(encoding="utf-8"))
                state = json.loads(state_path.read_text(encoding="utf-8"))
                _, _, _, config_keys = self.module.parse_api_keys_block(config_path.read_text(encoding="utf-8"))

        self.assertEqual(saved["keys"], [])
        self.assertEqual(state.get("disabled_by_quota"), [])
        self.assertEqual(state.get("cpa_deleted_while_quota_disabled"), [])
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
