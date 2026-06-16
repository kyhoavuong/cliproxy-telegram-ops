import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "quota-enforcer" / "quota_enforcer.py"


def load_quota_enforcer_module():
    spec = importlib.util.spec_from_file_location("quota_enforcer_auth_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def write_auth_file(path, *, disabled=False, auth_type="codex", email="operator@example.test"):
    path.write_text(
        json.dumps({
            "type": auth_type,
            "email": email,
            "disabled": disabled,
            "keep_me": "unchanged",
        }, indent=2) + "\n",
        encoding="utf-8",
    )


def read_auth_file(path):
    return json.loads(path.read_text(encoding="utf-8"))


def fake_management_request(auth_files, quota_by_index, calls=None, fail_auth_files=False, auth_files_meta=None):
    def _request(path, method="GET", payload=None):
        if calls is not None:
            calls.append((path, method, payload))
        if path == "auth-files":
            if fail_auth_files:
                raise RuntimeError("management listing unavailable")
            payload = {"files": list(auth_files)}
            payload.update(auth_files_meta or {})
            return payload
        if path == "api-call":
            auth_index = payload["authIndex"]
            value = quota_by_index[auth_index]
            if isinstance(value, Exception):
                raise value
            primary_used, secondary_used = value
            return {
                "status_code": 200,
                "body": {
                    "rate_limit": {
                        "primary_window": {"usedPercent": primary_used},
                        "secondary_window": {"usedPercent": secondary_used},
                    }
                },
            }
        raise AssertionError(f"unexpected management path {path}")
    return _request


class AuthQuotaEnforcerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_quota_enforcer_module()

    def test_cliproxy_management_token_wins_over_cpa_management_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("CPA_MANAGEMENT_KEY=file-token\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {
                "CLIPROXY_MANAGEMENT_TOKEN": "cliproxy-token",
                "CPA_MANAGEMENT_KEY": "cpa-token",
            }, clear=True), \
                 mock.patch.object(self.module, "ENV_FILE", env_file, create=True):
                self.assertEqual(self.module.load_management_token(), "cliproxy-token")

    def test_env_file_cpa_management_key_used_when_process_env_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            env_file = base / ".env"
            auth_dir = base / "auth"
            auth_dir.mkdir()
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            env_file.write_text("# ignored\nCPA_MANAGEMENT_KEY='file-cpa-token'\n", encoding="utf-8")
            state = {"disabled_by_quota": []}
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]

            with mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch.object(self.module, "ENV_FILE", env_file, create=True), \
                 mock.patch.object(self.module, "AUTH_DIR", auth_dir, create=True), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", self.module.load_management_token(), create=True), \
                 mock.patch.object(self.module, "management_request", side_effect=fake_management_request(auth_files, {"auth-one": (10, 50)}), create=True):
                result = self.module.enforce_auth_weekly_quota(state, dry_run=False, ts=100)

            self.assertEqual(result["management_token_present"], 1)
            self.assertEqual(result["checked_auth_count"], 1)

    def run_enforcer(self, auth_dir, auth_files, quota_by_index, state=None, ts=100, calls=None, fail_auth_files=False, auth_files_meta=None):
        state = {"disabled_by_quota": []} if state is None else state
        with mock.patch.object(self.module, "AUTH_DIR", auth_dir, create=True), \
             mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", "management-token", create=True), \
             mock.patch.object(self.module, "management_request", side_effect=fake_management_request(auth_files, quota_by_index, calls=calls, fail_auth_files=fail_auth_files, auth_files_meta=auth_files_meta), create=True):
            return self.module.enforce_auth_weekly_quota(state, dry_run=False, ts=ts)

    def test_env_token_present_existing_path_performs_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]
            state = {"disabled_by_quota": []}

            result = self.run_enforcer(auth_dir, auth_files, {"auth-one": (10, 50)}, state=state)

            self.assertEqual(result["management_token_present"], 1)
            self.assertEqual(result["auth_files_count"], 1)
            self.assertEqual(result["codex_candidate_count"], 1)
            self.assertEqual(result["checked_auth_count"], 1)

    def test_daily_zero_enabled_codex_auth_account_is_auto_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]
            state = {"disabled_by_quota": []}

            result = self.run_enforcer(auth_dir, auth_files, {"auth-one": (100, 20)}, state=state)

            data = read_auth_file(auth_path)
            ref = self.module.auth_quota_ref(auth_path.name)
            marker = state["auth_weekly_auto_disabled"][ref]
            self.assertTrue(data["disabled"])
            self.assertEqual(data["keep_me"], "unchanged")
            self.assertEqual(marker.get("reasons"), ["daily"])
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_disabled_count"], 1)
            self.assertEqual(result["auto_enabled_count"], 0)

    def test_weekly_zero_enabled_codex_auth_account_is_auto_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]
            state = {"disabled_by_quota": []}

            result = self.run_enforcer(auth_dir, auth_files, {"auth-one": (20, 100)}, state=state)

            data = read_auth_file(auth_path)
            ref = self.module.auth_quota_ref(auth_path.name)
            marker = state["auth_weekly_auto_disabled"][ref]
            self.assertTrue(data["disabled"])
            self.assertEqual(data["keep_me"], "unchanged")
            self.assertEqual(marker.get("reasons"), ["weekly"])
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_disabled_count"], 1)
            self.assertEqual(result["auto_enabled_count"], 0)

    def test_daily_and_weekly_zero_records_both_reasons(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]
            state = {"disabled_by_quota": []}

            result = self.run_enforcer(auth_dir, auth_files, {"auth-one": (100, 100)}, state=state)

            ref = self.module.auth_quota_ref(auth_path.name)
            marker = state["auth_weekly_auto_disabled"][ref]
            self.assertTrue(read_auth_file(auth_path)["disabled"])
            self.assertEqual(marker.get("reasons"), ["daily", "weekly"])
            self.assertEqual(result["auto_disabled_count"], 1)

    def test_reauth_evidence_auto_disables_codex_auth_account_with_separate_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "status": "unauthorized_401", "disabled": False}]
            state = {"disabled_by_quota": [], "auth_weekly_auto_disabled": {}}

            result = self.run_enforcer(auth_dir, auth_files, {"auth-one": (10, 50)}, state=state)

            ref = self.module.auth_quota_ref(auth_path.name)
            self.assertTrue(read_auth_file(auth_path)["disabled"])
            self.assertIn(ref, state.get("auth_reauth_auto_disabled", {}))
            self.assertEqual(state.get("auth_weekly_auto_disabled"), {})
            self.assertEqual(result["reauth_auto_disabled_count"], 1)

    def test_reauth_evidence_from_quota_call_auto_disables_codex_auth_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]
            state = {"disabled_by_quota": []}

            result = self.run_enforcer(
                auth_dir,
                auth_files,
                {"auth-one": RuntimeError("HTTP 401 unauthorized_401 invalidated token")},
                state=state,
            )

            ref = self.module.auth_quota_ref(auth_path.name)
            self.assertTrue(read_auth_file(auth_path)["disabled"])
            self.assertIn(ref, state.get("auth_reauth_auto_disabled", {}))
            self.assertEqual(result["reauth_auto_disabled_count"], 1)
            self.assertEqual(result["quota_check_failed_count"], 0)

    def test_reauth_auto_disabled_account_recovers_when_auth_and_both_quotas_are_healthy(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=True)
            ref = self.module.auth_quota_ref(auth_path.name)
            state = {
                "disabled_by_quota": [],
                "auth_reauth_auto_disabled": {ref: {"auth_index": "auth-one", "disabled_at": 100, "last_seen_at": 100}},
            }

            result = self.run_enforcer(auth_dir, [], {"auth-one": (10, 50)}, state=state, ts=200)

            self.assertFalse(read_auth_file(auth_path)["disabled"])
            self.assertEqual(state.get("auth_reauth_auto_disabled"), {})
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["reauth_auto_enabled_count"], 1)

    def test_reauth_auto_disabled_account_stays_disabled_when_primary_quota_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=True)
            ref = self.module.auth_quota_ref(auth_path.name)
            state = {
                "disabled_by_quota": [],
                "auth_reauth_auto_disabled": {ref: {"auth_index": "auth-one", "disabled_at": 100, "last_seen_at": 100}},
            }

            result = self.run_enforcer(auth_dir, [], {"auth-one": (100, 50)}, state=state, ts=200)

            self.assertTrue(read_auth_file(auth_path)["disabled"])
            self.assertIn(ref, state.get("auth_reauth_auto_disabled", {}))
            self.assertEqual(result["reauth_auto_enabled_count"], 0)

    def test_reauth_auto_disabled_account_stays_disabled_when_secondary_quota_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=True)
            ref = self.module.auth_quota_ref(auth_path.name)
            state = {
                "disabled_by_quota": [],
                "auth_reauth_auto_disabled": {ref: {"auth_index": "auth-one", "disabled_at": 100, "last_seen_at": 100}},
            }

            result = self.run_enforcer(auth_dir, [], {"auth-one": (10, 100)}, state=state, ts=200)

            self.assertTrue(read_auth_file(auth_path)["disabled"])
            self.assertIn(ref, state.get("auth_reauth_auto_disabled", {}))
            self.assertEqual(result["reauth_auto_enabled_count"], 0)

    def test_incomplete_auth_files_payload_does_not_reauth_disable(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "status": "unauthorized_401", "disabled": False}]
            state = {"disabled_by_quota": []}

            result = self.run_enforcer(
                auth_dir,
                auth_files,
                {"auth-one": (10, 50)},
                state=state,
                auth_files_meta={"incomplete": True},
            )

            self.assertFalse(read_auth_file(auth_path)["disabled"])
            self.assertEqual(state.get("auth_reauth_auto_disabled"), {})
            self.assertEqual(result["checked_auth_count"], 0)

    def test_both_daily_and_weekly_recovered_account_is_auto_enabled_only_after_auto_disable(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]
            state = {"disabled_by_quota": []}

            self.run_enforcer(auth_dir, auth_files, {"auth-one": (20, 100)}, state=state, ts=100)
            result = self.run_enforcer(auth_dir, auth_files, {"auth-one": (10, 50)}, state=state, ts=200)

            data = read_auth_file(auth_path)
            self.assertFalse(data["disabled"])
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_disabled_count"], 0)
            self.assertEqual(result["auto_enabled_count"], 1)
            self.assertEqual(state.get("auth_weekly_auto_disabled"), {})

    def test_manually_disabled_auth_account_with_healthy_quota_is_auto_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=True)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": True}]

            result = self.run_enforcer(auth_dir, auth_files, {"auth-one": (20, 50)})

            data = read_auth_file(auth_path)
            self.assertFalse(data["disabled"])
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_enabled_count"], 1)
            self.assertEqual(result["skipped_manual_disabled_count"], 0)

    def test_manually_disabled_auth_account_with_exhausted_quota_is_tracked_for_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=True)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": True}]
            state = {"disabled_by_quota": []}

            result = self.run_enforcer(auth_dir, auth_files, {"auth-one": (100, 50)}, state=state, ts=100)

            ref = self.module.auth_quota_ref(auth_path.name)
            data = read_auth_file(auth_path)
            self.assertTrue(data["disabled"])
            self.assertEqual(state["auth_weekly_auto_disabled"][ref].get("reasons"), ["daily"])
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_disabled_count"], 1)
            self.assertEqual(result["auto_enabled_count"], 0)
            self.assertEqual(result["skipped_manual_disabled_count"], 0)

            result = self.run_enforcer(auth_dir, auth_files, {"auth-one": (20, 50)}, state=state, ts=200)

            self.assertFalse(read_auth_file(auth_path)["disabled"])
            self.assertEqual(state.get("auth_weekly_auto_disabled"), {})
            self.assertEqual(result["auto_enabled_count"], 1)
            self.assertEqual(result["skipped_manual_disabled_count"], 0)

    def test_auto_disabled_account_is_rechecked_and_enabled_when_auth_files_omits_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            state = {"disabled_by_quota": []}
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]
            self.run_enforcer(auth_dir, auth_files, {"auth-one": (20, 100)}, state=state, ts=100)
            calls = []

            result = self.run_enforcer(auth_dir, [], {"auth-one": (10, 50)}, state=state, ts=200, calls=calls)

            self.assertFalse(read_auth_file(auth_path)["disabled"])
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_enabled_count"], 1)
            self.assertEqual(state.get("auth_weekly_auto_disabled"), {})
            self.assertIn(("api-call", "POST", mock.ANY), calls)

    def test_marked_auto_disabled_account_stays_disabled_when_weekly_still_zero_and_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            state = {"disabled_by_quota": []}
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]
            self.run_enforcer(auth_dir, auth_files, {"auth-one": (20, 100)}, state=state, ts=100)

            result = self.run_enforcer(auth_dir, [], {"auth-one": (10, 100)}, state=state, ts=200)

            self.assertTrue(read_auth_file(auth_path)["disabled"])
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_enabled_count"], 0)
            self.assertTrue(state.get("auth_weekly_auto_disabled"))

    def test_auth_files_failure_still_rechecks_marked_auto_disabled_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            state = {"disabled_by_quota": []}
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]
            self.run_enforcer(auth_dir, auth_files, {"auth-one": (20, 100)}, state=state, ts=100)

            result = self.run_enforcer(auth_dir, [], {"auth-one": (10, 50)}, state=state, ts=200, fail_auth_files=True)

            self.assertFalse(read_auth_file(auth_path)["disabled"])
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_enabled_count"], 1)
            self.assertEqual(state.get("auth_weekly_auto_disabled"), {})

    def test_one_marked_account_quota_failure_does_not_block_another_recheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            first_path = auth_dir / "codex-one.json"
            second_path = auth_dir / "codex-two.json"
            write_auth_file(first_path, disabled=False)
            write_auth_file(second_path, disabled=False)
            state = {"disabled_by_quota": []}
            auth_files = [
                {"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False},
                {"name": "codex-two.json", "type": "codex", "auth_index": "auth-two", "disabled": False},
            ]
            self.run_enforcer(auth_dir, auth_files, {"auth-one": (20, 100), "auth-two": (20, 100)}, state=state, ts=100)

            result = self.run_enforcer(auth_dir, [], {"auth-one": RuntimeError("quota unavailable"), "auth-two": (10, 50)}, state=state, ts=200)

            self.assertTrue(read_auth_file(first_path)["disabled"])
            self.assertFalse(read_auth_file(second_path)["disabled"])
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_enabled_count"], 1)
            self.assertEqual(result["quota_check_failed_count"], 1)
            self.assertEqual(len(state.get("auth_weekly_auto_disabled", {})), 1)

    def test_marked_account_with_missing_auth_file_keeps_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            ref = self.module.auth_quota_ref("codex-missing.json")
            state = {
                "disabled_by_quota": [],
                "auth_weekly_auto_disabled": {
                    ref: {"auth_index": "auth-one", "reasons": ["weekly"]},
                },
            }

            result = self.run_enforcer(auth_dir, [], {"auth-one": (10, 50)}, state=state, ts=200)

            self.assertIn(ref, state.get("auth_weekly_auto_disabled", {}))
            self.assertEqual(result["checked_auth_count"], 0)
            self.assertEqual(result["auto_enabled_count"], 0)

    def test_marked_account_with_unreadable_auth_json_keeps_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            auth_path.write_text("{not-json", encoding="utf-8")
            ref = self.module.auth_quota_ref(auth_path.name)
            state = {
                "disabled_by_quota": [],
                "auth_weekly_auto_disabled": {
                    ref: {"auth_index": "auth-one", "reasons": ["weekly"]},
                },
            }

            result = self.run_enforcer(auth_dir, [], {"auth-one": (10, 50)}, state=state, ts=200)

            self.assertEqual(auth_path.read_text(encoding="utf-8"), "{not-json")
            self.assertIn(ref, state.get("auth_weekly_auto_disabled", {}))
            self.assertEqual(result["auto_enabled_count"], 0)

    def test_manual_disabled_account_omitted_from_auth_files_is_not_auto_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=True)
            state = {"disabled_by_quota": []}

            result = self.run_enforcer(auth_dir, [], {"auth-one": (10, 50)}, state=state, ts=200)

            self.assertTrue(read_auth_file(auth_path)["disabled"])
            self.assertEqual(result["checked_auth_count"], 0)
            self.assertEqual(result["auto_enabled_count"], 0)

    def test_weekly_recovers_but_daily_still_zero_remains_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]
            state = {"disabled_by_quota": []}

            self.run_enforcer(auth_dir, auth_files, {"auth-one": (100, 100)}, state=state, ts=100)
            result = self.run_enforcer(auth_dir, auth_files, {"auth-one": (100, 50)}, state=state, ts=200)

            ref = self.module.auth_quota_ref(auth_path.name)
            data = read_auth_file(auth_path)
            self.assertTrue(data["disabled"])
            self.assertEqual(state["auth_weekly_auto_disabled"][ref].get("reasons"), ["daily"])
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_enabled_count"], 0)

    def test_daily_recovers_but_weekly_still_zero_remains_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            auth_files = [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}]
            state = {"disabled_by_quota": []}

            self.run_enforcer(auth_dir, auth_files, {"auth-one": (100, 100)}, state=state, ts=100)
            result = self.run_enforcer(auth_dir, auth_files, {"auth-one": (10, 100)}, state=state, ts=200)

            ref = self.module.auth_quota_ref(auth_path.name)
            data = read_auth_file(auth_path)
            self.assertTrue(data["disabled"])
            self.assertEqual(state["auth_weekly_auto_disabled"][ref].get("reasons"), ["weekly"])
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_enabled_count"], 0)

    def test_auth_quota_enforcer_logs_and_results_are_aggregate_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-secret@example.test.json"
            write_auth_file(auth_path, disabled=False, email="codex-secret@example.test")
            auth_files = [{"name": "codex-secret@example.test.json", "type": "codex", "auth_index": "auth-secret-index", "disabled": False}]
            messages = []
            state = {"disabled_by_quota": []}

            with mock.patch.object(self.module, "log", side_effect=lambda message: messages.append(message)):
                result = self.run_enforcer(auth_dir, auth_files, {"auth-secret-index": (10, 100)}, state=state)

            combined = "\n".join(messages + [repr(result)])
            persisted = repr(state)
            self.assertIn("management_token_present=1", combined)
            self.assertIn("auth_files_count=1", combined)
            self.assertIn("codex_candidate_count=1", combined)
            self.assertIn("checked_auth_count=1", combined)
            self.assertIn("auto_disabled_count=1", combined)
            self.assertNotIn("codex-secret@example.test", combined)
            self.assertNotIn("codex-secret@example.test.json", combined)
            self.assertNotIn("auth-secret-index", combined)
            self.assertNotIn("management-token", combined)
            self.assertNotIn("auth-secret-index", combined)
            self.assertNotIn("codex-secret@example.test", persisted)
            self.assertNotIn("codex-secret@example.test.json", persisted)
            self.assertIn("auth-secret-index", persisted)

    def test_missing_process_env_and_env_file_token_logs_management_token_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("OTHER=value\n", encoding="utf-8")
            messages = []
            state = {"disabled_by_quota": []}

            with mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch.object(self.module, "ENV_FILE", env_file, create=True), \
                 mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", self.module.load_management_token(), create=True), \
                 mock.patch.object(self.module, "management_request", side_effect=AssertionError("management API should not be called")), \
                 mock.patch.object(self.module, "log", side_effect=lambda message: messages.append(message)):
                result = self.module.enforce_auth_weekly_quota(state, dry_run=False, ts=100)

            combined = "\n".join(messages + [repr(result)])
            self.assertEqual(result["management_token_present"], 0)
            self.assertEqual(result["checked_auth_count"], 0)
            self.assertEqual(result["auth_files_count"], 0)
            self.assertEqual(result["codex_candidate_count"], 0)
            self.assertIn("management_token_present=0", combined)
            self.assertIn("checked_auth_count=0", combined)

    def run_auth_quota_if_due(self, auth_dir, auth_files, quota_by_index, state=None, ts=100, calls=None, force=False):
        state = {"disabled_by_quota": []} if state is None else state
        with mock.patch.object(self.module, "AUTH_DIR", auth_dir, create=True), \
             mock.patch.object(self.module, "AUTH_QUOTA_ENFORCER_COOLDOWN_SECONDS", 300, create=True), \
             mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", "management-token", create=True), \
             mock.patch.object(self.module, "management_request", side_effect=fake_management_request(auth_files, quota_by_index, calls=calls), create=True):
            return self.module.enforce_auth_quota_if_due(state, dry_run=False, ts=ts, force=force)

    def test_auth_quota_cooldown_first_run_performs_checks_and_records_next_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            calls = []
            state = {"disabled_by_quota": []}

            result = self.run_auth_quota_if_due(
                auth_dir,
                [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}],
                {"auth-one": (10, 50)},
                state=state,
                ts=100,
                calls=calls,
            )

            self.assertIn(("api-call", "POST", mock.ANY), calls)
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(state.get("last_auth_quota_check_at"), 100)
            self.assertEqual(state.get("next_auth_quota_check_at"), 400)

    def test_auth_quota_cooldown_before_expiry_skips_without_management_api_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            write_auth_file(auth_dir / "codex-one.json", disabled=False)
            state = {
                "disabled_by_quota": [],
                "last_auth_quota_check_at": 100,
                "next_auth_quota_check_at": 400,
            }
            messages = []
            calls = []

            with mock.patch.object(self.module, "log", side_effect=lambda message: messages.append(message)):
                result = self.run_auth_quota_if_due(
                    auth_dir,
                    [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}],
                    {"auth-one": (10, 50)},
                    state=state,
                    ts=200,
                    calls=calls,
                )

            self.assertEqual(calls, [])
            self.assertEqual(result["checked_auth_count"], 0)
            self.assertIn("auth_quota_skipped_cooldown=1", "\n".join(messages))
            self.assertIn("next_auth_quota_check_at=400", "\n".join(messages))
            self.assertEqual(state.get("last_auth_quota_check_at"), 100)
            self.assertEqual(state.get("next_auth_quota_check_at"), 400)

    def test_auth_quota_cooldown_after_expiry_performs_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            state = {
                "disabled_by_quota": [],
                "last_auth_quota_check_at": 100,
                "next_auth_quota_check_at": 400,
            }
            calls = []

            result = self.run_auth_quota_if_due(
                auth_dir,
                [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}],
                {"auth-one": (10, 50)},
                state=state,
                ts=401,
                calls=calls,
            )

            self.assertIn(("api-call", "POST", mock.ANY), calls)
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(state.get("last_auth_quota_check_at"), 401)
            self.assertEqual(state.get("next_auth_quota_check_at"), 701)

    def test_auth_quota_cooldown_force_bypasses_wait(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir = Path(tmp)
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=False)
            state = {
                "disabled_by_quota": [],
                "last_auth_quota_check_at": 100,
                "next_auth_quota_check_at": 400,
            }
            calls = []

            result = self.run_auth_quota_if_due(
                auth_dir,
                [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}],
                {"auth-one": (10, 50)},
                state=state,
                ts=200,
                calls=calls,
                force=True,
            )

            self.assertIn(("api-call", "POST", mock.ANY), calls)
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(state.get("last_auth_quota_check_at"), 200)
            self.assertEqual(state.get("next_auth_quota_check_at"), 500)

    def test_main_still_enforces_user_api_key_quota_when_auth_quota_cooldown_skips(self):
        state = {
            "disabled_by_quota": [],
            "last_auth_quota_check_at": 100,
            "next_auth_quota_check_at": 400,
        }
        cfg = {
            "keys": [{
                "name": "Alice",
                "key": "test-key",
                "daily_token_limit": 100,
                "weekly_token_limit": 400,
            }],
            "dry_run": False,
            "timezone": "UTC",
        }
        usage = {"test-key": {"today_tokens": 150, "week_tokens": 150, "requests_today": 3}}

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(self.module, "LOCK_FILE", Path(tmp) / "quota.lock", create=True), \
             mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", "management-token", create=True), \
             mock.patch.object(self.module, "AUTH_QUOTA_ENFORCER_COOLDOWN_SECONDS", 300, create=True), \
             mock.patch.object(self.module, "sys") as sys_mock, \
             mock.patch.object(self.module, "load_quota_config", return_value=cfg), \
             mock.patch.object(self.module, "sync_quota_config_with_config_keys") as sync_mock, \
             mock.patch.object(self.module, "get_usage_by_key", return_value=usage) as usage_mock, \
             mock.patch.object(self.module, "load_quota_state", return_value=state), \
             mock.patch.object(self.module, "save_quota_state") as save_state_mock, \
             mock.patch.object(self.module, "update_config_api_keys") as update_config_mock, \
             mock.patch.object(self.module, "management_request", side_effect=AssertionError("auth quota management should be skipped")), \
             mock.patch.object(self.module, "now_ts", return_value=200):
            sys_mock.argv = ["quota_enforcer.py"]

            self.assertEqual(self.module.main(), 0)

        sync_mock.assert_called_once_with(cfg)
        usage_mock.assert_called_once_with(cfg["keys"], "UTC")
        self.assertGreaterEqual(save_state_mock.call_count, 1)
        self.assertEqual(save_state_mock.call_args_list[0].args[0].get("disabled_by_quota"), ["test-key"])
        update_config_mock.assert_called_once_with([], ["test-key"], False)

    def run_migration(self, auth_dir, backup_dir, auth_files, quota_by_index, state=None, ts=100):
        state = {"disabled_by_quota": []} if state is None else state
        with mock.patch.object(self.module, "AUTH_DIR", auth_dir, create=True), \
             mock.patch.object(self.module, "MANUAL_BACKUPS_DIR", backup_dir, create=True), \
             mock.patch.object(self.module, "CLIPROXY_MANAGEMENT_TOKEN", "management-token", create=True), \
             mock.patch.object(self.module, "management_request", side_effect=fake_management_request(auth_files, quota_by_index), create=True):
            return self.module.run_auth_weekly_manual_disabled_migration(state, ts=ts)

    def test_migration_reenables_eligible_manually_disabled_codex_accounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            auth_dir = base / "auth"
            backup_dir = base / "backups"
            auth_dir.mkdir()
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=True)
            state = {"disabled_by_quota": []}

            result = self.run_migration(
                auth_dir,
                backup_dir,
                [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}],
                {"auth-one": (10, 50)},
                state=state,
            )

            self.assertFalse(read_auth_file(auth_path)["disabled"])
            self.assertEqual(result["total_codex_auth_count"], 1)
            self.assertEqual(result["disabled_codex_count"], 1)
            self.assertEqual(result["migrated_enabled_count"], 1)
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_disabled_count"], 0)
            self.assertEqual(result["auto_enabled_count"], 0)
            self.assertEqual(state.get("auth_weekly_auto_disabled"), {})

    def test_migration_auto_disables_weekly_zero_accounts_with_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            auth_dir = base / "auth"
            backup_dir = base / "backups"
            auth_dir.mkdir()
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=True)
            state = {"disabled_by_quota": []}

            result = self.run_migration(
                auth_dir,
                backup_dir,
                [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}],
                {"auth-one": (10, 100)},
                state=state,
            )

            self.assertTrue(read_auth_file(auth_path)["disabled"])
            self.assertEqual(result["migrated_enabled_count"], 1)
            self.assertEqual(result["checked_auth_count"], 1)
            self.assertEqual(result["auto_disabled_count"], 1)
            self.assertTrue(state.get("auth_weekly_auto_disabled"))

    def test_migration_skips_non_codex_unreadable_and_already_marked_disabled_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            auth_dir = base / "auth"
            backup_dir = base / "backups"
            auth_dir.mkdir()
            codex_path = auth_dir / "codex-one.json"
            antigravity_path = auth_dir / "antigravity-one.json"
            unreadable_path = auth_dir / "broken.json"
            write_auth_file(codex_path, disabled=True)
            write_auth_file(antigravity_path, disabled=True, auth_type="antigravity")
            unreadable_path.write_text("{", encoding="utf-8")
            state = {
                "disabled_by_quota": [],
                "auth_weekly_auto_disabled": {
                    self.module.auth_quota_ref(codex_path.name): {"auth_index": "auth-one", "disabled_at": 1, "last_seen_at": 1},
                },
            }

            result = self.run_migration(auth_dir, backup_dir, [], {}, state=state)

            self.assertTrue(read_auth_file(codex_path)["disabled"])
            self.assertTrue(read_auth_file(antigravity_path)["disabled"])
            self.assertEqual(unreadable_path.read_text(encoding="utf-8"), "{")
            self.assertEqual(result["total_codex_auth_count"], 1)
            self.assertEqual(result["disabled_codex_count"], 1)
            self.assertEqual(result["migrated_enabled_count"], 0)

    def test_migration_creates_backup_before_auth_file_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            auth_dir = base / "auth"
            backup_dir = base / "backups"
            auth_dir.mkdir()
            auth_path = auth_dir / "codex-one.json"
            write_auth_file(auth_path, disabled=True)

            result = self.run_migration(
                auth_dir,
                backup_dir,
                [{"name": "codex-one.json", "type": "codex", "auth_index": "auth-one", "disabled": False}],
                {"auth-one": (10, 50)},
            )

            backup_path = Path(result["backup_path"])
            self.assertTrue(backup_path.is_dir())
            self.assertTrue(read_auth_file(backup_path / "codex-one.json")["disabled"])
            self.assertFalse(read_auth_file(auth_path)["disabled"])


if __name__ == "__main__":
    unittest.main()
