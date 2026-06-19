import hashlib
import unittest
from unittest import mock

import time

import telegram_alerts.app as app
import telegram_alerts.handlers as handlers
import telegram_alerts.health as health
import telegram_alerts.snapshot as snapshot_module
import telegram_alerts.usage as usage_module
from telegram_alerts.health import (
    Alert,
    build_alert_message,
    build_resolved_message,
    check_auth_quota_status,
    collect_alerts,
    quota_inspection_payload,
    quota_inspection_unavailable_alert,
)


def inspection_payload(*items, running=False):
    return {"running": running, "results": list(items)}


def inspection_payload_with_total(items, running=False, completed=False, total=None):
    results = list(items)
    return {
        "running": running,
        "completed": completed,
        "total": len(results) if total is None else total,
        "results": results,
    }


def auth_item(name="alice@example.com", status="unauthorized_401", error="HTTP 401: unauthorized", auth_index="auth-1"):
    return {
        "file_name": name,
        "name": name,
        "auth_index": auth_index,
        "status": status,
        "error": error,
        "refreshed_at": "2026-06-08T20:00:00+07:00",
    }


def auth_index_key(value):
    return hashlib.sha256(str(value or "").strip().encode("utf-8", errors="replace")).hexdigest()[:16]


def auth_observation(complete=True, healthy=None, failed=None, reason=""):
    healthy = list(healthy or [])
    failed = list(failed or [])
    observed = sorted(set(healthy) | set(failed))
    return {
        "complete": complete,
        "reason": reason,
        "observed_identity_keys": observed,
        "healthy_identity_keys": healthy,
        "failed_identity_keys": failed,
        "failed_labels": {key: key for key in failed},
    }


def gpt_observation(complete=True, margin=None, low=False, recovered=False, reason=""):
    return {
        "complete": complete,
        "reason": reason,
        "margin": margin,
        "low": low,
        "recovered": recovered,
        "enabled_codex_count": 8,
        "primary_checked_count": 8 if complete else 6,
        "secondary_checked_count": 8 if complete else 6,
        "demand_tokens_5h": 100_000_000 if complete else None,
    }


class QuotaInspectionPayloadRefreshTests(unittest.TestCase):
    def test_count_mismatch_is_complete_when_active_codex_identities_are_fully_observed(self):
        calls = []
        rows = [
            auth_item(name=f"active-{idx}", status="normal", auth_index=f"codex-{idx}")
            for idx in range(1, 22)
        ]
        active_complete_with_inactive_total = {
            **inspection_payload_with_total(rows, running=False, completed=False, total=26),
            "cached": 21,
            "normal": 21,
            "unknown": 5,
        }
        inspection_responses = [
            active_complete_with_inactive_total,
            active_complete_with_inactive_total,
        ]

        def fake_request(path, method="GET", payload=None, cookie=None):
            calls.append((path, method, payload))
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path == "quota/inspection":
                return 200, inspection_responses.pop(0), ""
            if path.startswith("usage/identities/page"):
                self.assertIn("active_only=true", path)
                return 200, {
                    "items": [
                        {"auth_index": f"codex-{idx}", "type": "codex"}
                        for idx in range(1, 22)
                    ],
                    "totalPages": 1,
                }, ""
            if path == "quota/refresh":
                self.assertEqual(payload, {"auth_indexes": [f"codex-{idx}" for idx in range(1, 22)]})
                return 200, {"queued": 21}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch.object(health.time, "sleep"):
            data = quota_inspection_payload(refresh_before_check=True, wait_for_refresh=True, wait_seconds=0)

        self.assertEqual(health.auth_quota_incomplete_reason(data), "")
        self.assertNotIn("active_only=false", repr(calls))

    def test_count_mismatch_refreshes_all_known_codex_identities_from_inactive_identity_list(self):
        calls = []
        incomplete = inspection_payload_with_total(
            [auth_item(name=f"known-{idx}", status="normal", auth_index=f"codex-{idx}") for idx in range(1, 7)]
            + [auth_item(name="antigravity", status="normal", auth_index="antigravity-1")],
            total=9,
        )
        complete = inspection_payload_with_total(
            [auth_item(name=f"known-{idx}", status="normal", auth_index=f"codex-{idx}") for idx in range(1, 9)],
            total=8,
        )
        inspection_responses = [incomplete, complete]

        def fake_request(path, method="GET", payload=None, cookie=None):
            calls.append((path, method, payload))
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path == "quota/inspection":
                return 200, inspection_responses.pop(0), ""
            if path.startswith("usage/identities/page"):
                self.assertIn("active_only=false", path)
                return 200, {
                    "items": [
                        {"auth_index": f"codex-{idx}", "type": "codex", "disabled": idx > 6}
                        for idx in range(1, 9)
                    ] + [
                        {"auth_index": "antigravity-1", "type": "antigravity"},
                    ]
                }, ""
            if path == "quota/refresh":
                return 200, {"queued": 8}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch.object(health.time, "sleep"):
            data = quota_inspection_payload(refresh_before_check=True, wait_for_refresh=True, wait_seconds=1)

        self.assertEqual(data, complete)
        self.assertIn("usage/identities/page?auth_type=1&active_only=false&page=1&page_size=500", [call[0] for call in calls])
        refresh_payloads = [call[2] for call in calls if call[0] == "quota/refresh"]
        self.assertEqual(refresh_payloads, [{"auth_indexes": [f"codex-{idx}" for idx in range(1, 9)]}])

    def test_complete_inspection_refreshes_returned_rows_without_identity_fallback(self):
        complete = inspection_payload_with_total(
            [auth_item(name=f"known-{idx}", status="normal", auth_index=f"codex-{idx}") for idx in range(1, 9)],
            total=8,
        )
        calls = []

        def fake_request(path, method="GET", payload=None, cookie=None):
            calls.append((path, method, payload))
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path == "quota/inspection":
                return 200, complete, ""
            if path.startswith("usage/identities/page"):
                self.fail("complete inspections must not call the active_only=false identity fallback")
            if path == "quota/refresh":
                self.assertEqual(payload, {"auth_indexes": [f"codex-{idx}" for idx in range(1, 9)]})
                return 200, {"queued": 8}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch.object(health.time, "sleep"):
            data = quota_inspection_payload(refresh_before_check=True, wait_for_refresh=True, wait_seconds=1)

        self.assertEqual(data, complete)
        self.assertNotIn("active_only=false", repr(calls))

    def test_results_none_uses_identity_fallback_when_available(self):
        incomplete = {"running": False, "total": 3, "results": None}
        complete = inspection_payload_with_total(
            [auth_item(name=f"known-{idx}", status="normal", auth_index=f"codex-{idx}") for idx in range(1, 4)],
            total=3,
        )
        inspection_responses = [incomplete, complete]

        refresh_payloads = []

        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path == "quota/inspection":
                return 200, inspection_responses.pop(0), ""
            if path.startswith("usage/identities/page"):
                self.assertIn("active_only=false", path)
                return 200, {"items": [{"auth_index": f"codex-{idx}", "type": "codex"} for idx in range(1, 4)]}, ""
            if path == "quota/refresh":
                refresh_payloads.append(payload)
                return 200, {"queued": 3}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch.object(health.time, "sleep"):
            data = quota_inspection_payload(refresh_before_check=True, wait_for_refresh=True, wait_seconds=1)

        self.assertEqual(data, complete)
        self.assertEqual(refresh_payloads, [{"auth_indexes": ["codex-1", "codex-2", "codex-3"]}])

    def test_all_known_codex_auth_indexes_prefers_identity_over_id_for_usage_keeper_requests(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path.startswith("usage/identities/page"):
                self.assertIn("active_only=false", path)
                return 200, {
                    "items": [
                        {"id": "internal-row-1", "identity": "quota-cache-row-1", "type": "codex"},
                        {"id": "internal-row-2", "identity": "quota-cache-row-2", "type": "codex"},
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            indexes = health.all_known_codex_auth_indexes("session=abc")

        self.assertEqual(indexes, ["quota-cache-row-1", "quota-cache-row-2"])
        self.assertNotIn("internal-row-", repr(indexes))

    def test_identity_fallback_unavailable_fails_safe_without_secret_logging(self):
        secret_auth_index = "codex-secret-auth-index"
        inspection = inspection_payload_with_total(
            [auth_item(name="known", status="normal", auth_index=secret_auth_index)],
            total=2,
        )
        calls = []

        def fake_request(path, method="GET", payload=None, cookie=None):
            calls.append((path, method, payload))
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path == "quota/inspection":
                return 200, inspection, ""
            if path.startswith("usage/identities/page"):
                raise RuntimeError(f"identity endpoint failed for {secret_auth_index}")
            if path == "quota/refresh":
                return 200, {"queued": 1}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.health.log") as log, \
             mock.patch.object(health.time, "sleep"):
            data = quota_inspection_payload(refresh_before_check=True, wait_for_refresh=False, wait_seconds=0)

        self.assertEqual(data, inspection)
        self.assertEqual(health.auth_quota_incomplete_reason(data), "count-mismatch")
        self.assertIn(("quota/refresh", "POST", {"auth_indexes": [secret_auth_index]}), calls)
        self.assertNotIn(secret_auth_index, repr(log.call_args_list))


class GptPoolCapacityTests(unittest.TestCase):
    def test_gpt_pool_capacity_accepts_runtime_identity_and_quota_cache_schema(self):
        calls = []

        def fake_request(path, method="GET", payload=None, cookie=None):
            calls.append((path, method, payload))
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "identities": [
                        {
                            "identity": "codex-runtime-1",
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
                            "identity": "antigravity-runtime",
                            "type": "antigravity",
                            "disabled": False,
                            "is_deleted": False,
                            "auth_type": 1,
                        },
                        {
                            "identity": "codex-disabled-runtime",
                            "type": "codex",
                            "disabled": True,
                            "is_deleted": False,
                            "auth_type": 1,
                        },
                        {
                            "identity": "codex-deleted-runtime",
                            "type": "codex",
                            "disabled": False,
                            "is_deleted": True,
                            "auth_type": 1,
                        },
                    ]
                }, ""
            if path == "quota/cache":
                self.assertEqual(payload, {"auth_indexes": ["codex-runtime-1", "codex-runtime-2"]})
                return 200, {
                    "items": [
                        {
                            "auth_index": "codex-runtime-1",
                            "status": "completed",
                            "quota": {
                                "quota": [
                                    {"key": "rate_limit.primary_window", "label": "5h", "usedPercent": 20},
                                    {"key": "rate_limit.secondary_window", "label": "Weekly", "usedPercent": 60},
                                ]
                            },
                        },
                        {
                            "auth_index": "codex-runtime-2",
                            "status": "completed",
                            "quota": {
                                "quota": [
                                    {"key": "rate_limit.primary_window", "label": "5h", "usedPercent": 35},
                                    {"key": "rate_limit.secondary_window", "label": "Weekly", "usedPercent": 75},
                                ]
                            },
                        },
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            pool = health.gpt_pool_capacity_snapshot()

        self.assertEqual(pool["enabled_codex_count"], 2)
        self.assertEqual(pool["primary"]["checked_count"], 2)
        self.assertEqual(pool["primary"]["avg_left_percent"], 72.5)
        self.assertEqual(pool["primary"]["lowest_left_percent"], 65.0)
        self.assertEqual(pool["primary"]["left_tokens"], 29_000_000.0)
        self.assertEqual(pool["secondary"]["checked_count"], 2)
        self.assertEqual(pool["secondary"]["avg_left_percent"], 32.5)
        self.assertEqual(pool["secondary"]["lowest_left_percent"], 25.0)
        self.assertEqual(pool["secondary"]["left_tokens"], 91_000_000.0)
        self.assertEqual(calls[0][0], "auth/login")

    def test_gpt_pool_capacity_uses_identity_not_id_for_quota_cache(self):
        cache_payloads = []

        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "items": [
                        {"id": "internal-row-1", "identity": "quota-cache-row-1", "type": "codex", "disabled": False},
                        {"id": "internal-row-2", "identity": "quota-cache-row-2", "type": "codex", "disabled": False},
                    ]
                }, ""
            if path == "quota/cache":
                cache_payloads.append(payload)
                self.assertEqual(payload, {"auth_indexes": ["quota-cache-row-1", "quota-cache-row-2"]})
                return 200, {
                    "items": [
                        {
                            "id": "internal-row-1",
                            "identity": "quota-cache-row-1",
                            "quotas": [
                                {"key": "rate_limit.primary_window", "usedPercent": 10},
                                {"key": "rate_limit.secondary_window", "usedPercent": 20},
                            ],
                        },
                        {
                            "id": "internal-row-2",
                            "identity": "quota-cache-row-2",
                            "quotas": [
                                {"key": "rate_limit.primary_window", "usedPercent": 30},
                                {"key": "rate_limit.secondary_window", "usedPercent": 40},
                            ],
                        },
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            pool = health.gpt_pool_capacity_snapshot(allow_management_fallback=False)

        self.assertEqual(cache_payloads, [{"auth_indexes": ["quota-cache-row-1", "quota-cache-row-2"]}])
        self.assertEqual(pool["enabled_codex_count"], 2)
        self.assertEqual(pool["primary"]["checked_count"], 2)
        self.assertEqual(pool["secondary"]["checked_count"], 2)
        self.assertEqual(pool["primary"]["avg_left_percent"], 80.0)
        self.assertEqual(pool["secondary"]["avg_left_percent"], 70.0)
        self.assertNotIn("internal-row-", repr(pool))

    def test_gpt_pool_capacity_uses_only_enabled_codex_identities(self):
        calls = []

        def fake_request(path, method="GET", payload=None, cookie=None):
            calls.append((path, method, payload))
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "items": [
                        {"auth_index": "codex-enabled-1", "type": "codex", "disabled": False},
                        {"auth_index": "codex-enabled-2", "auth_type": "codex", "active": True},
                        {"auth_index": "codex-disabled", "type": "codex", "disabled": True},
                        {"auth_index": "ag-enabled", "type": "antigravity", "disabled": False},
                    ]
                }, ""
            if path == "quota/cache":
                self.assertEqual(payload, {"auth_indexes": ["codex-enabled-1", "codex-enabled-2"]})
                return 200, {
                    "results": [
                        {
                            "auth_index": "codex-enabled-1",
                            "quotas": [
                                {"key": "rate_limit.primary_window", "usedPercent": 20},
                                {"key": "rate_limit.secondary_window", "usedPercent": 60},
                            ],
                        },
                        {
                            "auth_index": "codex-enabled-2",
                            "quotas": [
                                {"key": "rate_limit.primary_window", "usedPercent": 40},
                                {"key": "rate_limit.secondary_window", "usedPercent": 80},
                            ],
                        },
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            pool = health.gpt_pool_capacity_snapshot()

        self.assertEqual(pool["enabled_codex_count"], 2)
        self.assertEqual(pool["primary"]["checked_count"], 2)
        self.assertEqual(pool["primary"]["avg_left_percent"], 70.0)
        self.assertEqual(pool["primary"]["lowest_left_percent"], 60.0)
        self.assertEqual(pool["secondary"]["checked_count"], 2)
        self.assertEqual(pool["secondary"]["avg_left_percent"], 30.0)
        self.assertEqual(pool["secondary"]["lowest_left_percent"], 20.0)
        self.assertEqual(calls[0][0], "auth/login")

    def test_gpt_pool_capacity_excludes_free_primary_window_from_plus_capacity(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "items": [
                        {"auth_index": "codex-plus-1", "type": "codex"},
                        {"auth_index": "codex-plus-2", "type": "codex"},
                        {"auth_index": "codex-plus-3", "type": "codex"},
                        {"auth_index": "codex-plus-4", "type": "codex"},
                        {"auth_index": "codex-free", "type": "codex"},
                    ]
                }, ""
            if path == "quota/cache":
                self.assertEqual(payload, {"auth_indexes": ["codex-plus-1", "codex-plus-2", "codex-plus-3", "codex-plus-4", "codex-free"]})
                plus_items = [
                    {
                        "auth_index": f"codex-plus-{idx}",
                        "quotas": [
                            {"key": "rate_limit.primary_window", "planType": "plus", "window": {"seconds": 18000}, "usedPercent": 20},
                            {"key": "rate_limit.secondary_window", "planType": "plus", "window": {"seconds": 604800}, "usedPercent": 30},
                        ],
                    }
                    for idx in range(1, 5)
                ]
                return 200, {
                    "items": [
                        *plus_items,
                        {
                            "auth_index": "codex-free",
                            "quotas": [
                                {"key": "rate_limit.primary_window", "planType": "free", "window": {"seconds": 2592000}, "usedPercent": 5},
                            ],
                        },
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            pool = health.gpt_pool_capacity_snapshot(allow_management_fallback=False)

        self.assertEqual(pool["enabled_codex_count"], 4)
        self.assertEqual(pool["usable_codex_count"], 4)
        self.assertEqual(pool["free_codex_count"], 1)
        self.assertEqual(pool["primary"]["checked_count"], 4)
        self.assertEqual(pool["secondary"]["checked_count"], 4)
        self.assertEqual(pool["primary"]["left_tokens"], 64_000_000.0)
        self.assertEqual(pool["secondary"]["left_tokens"], 392_000_000.0)
        self.assertEqual(pool["missing_rows_count"], 0)
        self.assertTrue(health.gpt_pool_capacity_complete(pool))
        self.assertNotIn("codex-free", repr(pool))

    def test_gpt_pool_capacity_counts_team_plan_as_plus_compatible(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "items": [
                        {"id": "internal-team-row", "identity": "quota-cache-team", "type": "codex"},
                    ]
                }, ""
            if path == "quota/cache":
                self.assertEqual(payload, {"auth_indexes": ["quota-cache-team"]})
                return 200, {
                    "items": [{
                        "identity": "quota-cache-team",
                        "quotas": [
                            {"key": "rate_limit.primary_window", "planType": "team", "window": {"seconds": 18000}, "usedPercent": 10},
                            {"key": "rate_limit.secondary_window", "planType": "team", "window": {"seconds": 604800}, "usedPercent": 20},
                        ],
                    }]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            pool = health.gpt_pool_capacity_snapshot(allow_management_fallback=False)

        self.assertEqual(pool["enabled_codex_count"], 1)
        self.assertNotIn("free_codex_count", pool)
        self.assertEqual(pool["primary"]["checked_count"], 1)
        self.assertEqual(pool["secondary"]["checked_count"], 1)
        self.assertEqual(pool["primary"]["left_tokens"], 18_000_000.0)
        self.assertEqual(pool["secondary"]["left_tokens"], 112_000_000.0)
        self.assertTrue(health.gpt_pool_capacity_complete(pool))
        self.assertNotIn("quota-cache-team", repr(pool))
        self.assertNotIn("internal-team-row", repr(pool))

    def test_gpt_pool_capacity_counts_edu_plan_with_plus_windows_as_usable_not_free(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "items": [
                        {"id": "internal-edu-row", "identity": "quota-cache-edu", "type": "codex"},
                    ]
                }, ""
            if path == "quota/cache":
                self.assertEqual(payload, {"auth_indexes": ["quota-cache-edu"]})
                return 200, {
                    "items": [{
                        "identity": "quota-cache-edu",
                        "quotas": [
                            {"key": "rate_limit.primary_window", "planType": "edu", "window": {"seconds": 18000}, "usedPercent": 10},
                            {"key": "rate_limit.secondary_window", "planType": "edu", "window": {"seconds": 604800}, "usedPercent": 20},
                        ],
                    }]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            pool = health.gpt_pool_capacity_snapshot(allow_management_fallback=False)

        self.assertEqual(pool["enabled_codex_count"], 1)
        self.assertNotIn("free_codex_count", pool)
        self.assertEqual(pool["primary"]["checked_count"], 1)
        self.assertEqual(pool["secondary"]["checked_count"], 1)
        self.assertEqual(pool["primary"]["left_tokens"], 18_000_000.0)
        self.assertEqual(pool["secondary"]["left_tokens"], 112_000_000.0)
        self.assertTrue(health.gpt_pool_capacity_complete(pool))
        self.assertNotIn("quota-cache-edu", repr(pool))
        self.assertNotIn("internal-edu-row", repr(pool))

    def test_gpt_pool_capacity_does_not_report_non_free_nonmatching_plan_as_free(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [{"auth_index": "codex-unknown", "type": "codex"}]}, ""
            if path == "quota/cache":
                return 200, {"items": [{
                    "auth_index": "codex-unknown",
                    "quotas": [
                        {"key": "rate_limit.primary_window", "planType": "enterprise", "window": {"seconds": 3600}, "usedPercent": 10},
                        {"key": "rate_limit.secondary_window", "planType": "enterprise", "window": {"seconds": 86400}, "usedPercent": 20},
                    ],
                }]}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            pool = health.gpt_pool_capacity_snapshot(allow_management_fallback=False)

        self.assertEqual(pool["enabled_codex_count"], 1)
        self.assertNotIn("usable_codex_count", pool)
        self.assertNotIn("free_codex_count", pool)
        self.assertEqual(pool["primary"]["checked_count"], 0)
        self.assertEqual(pool["secondary"]["checked_count"], 0)
        self.assertEqual(pool["missing_rows_count"], 1)
        self.assertFalse(health.gpt_pool_capacity_complete(pool))
        self.assertNotIn("codex-unknown", repr(pool))

    def test_build_snapshot_does_not_add_free_warning_for_team_plan(self):
        pool = {
            "source": "usage_keeper",
            "enabled_codex_count": 1,
            "primary": {"checked_count": 1, "avg_left_percent": 90.0, "lowest_left_percent": 90.0, "left_tokens": 18_000_000.0},
            "secondary": {"checked_count": 1, "avg_left_percent": 80.0, "lowest_left_percent": 80.0, "left_tokens": 112_000_000.0},
            "error": "",
        }

        with mock.patch.object(snapshot_module, "check_http_services_detailed", return_value=[]), \
             mock.patch.object(snapshot_module, "collect_alerts_with_auth_observation", return_value=({}, auth_observation())), \
             mock.patch.object(snapshot_module, "load_quota_context", return_value={}), \
             mock.patch.object(snapshot_module, "quota_alerts_from_context", return_value=[]), \
             mock.patch.object(snapshot_module, "quota_rows_from_context", return_value=[]), \
             mock.patch.object(snapshot_module, "gpt_pool_capacity_snapshot", return_value=pool), \
             mock.patch.object(snapshot_module, "usage_rate_estimate", return_value={"tokens_per_hour": 1, "error": ""}):
            result = snapshot_module.build_snapshot()

        self.assertNotIn("auth:codex-free-plan", result["system_alerts"])

    def test_build_snapshot_adds_free_codex_plan_warning_alert(self):
        pool = {
            "source": "usage_keeper",
            "enabled_codex_count": 4,
            "usable_codex_count": 4,
            "free_codex_count": 1,
            "free_codex_labels": ["codex-edu-account@example.com"],
            "free_codex_hashes": [auth_index_key("codex-free")],
            "primary": {"checked_count": 4, "avg_left_percent": 80.0, "lowest_left_percent": 80.0, "left_tokens": 64_000_000.0},
            "secondary": {"checked_count": 4, "avg_left_percent": 70.0, "lowest_left_percent": 70.0, "left_tokens": 392_000_000.0},
            "error": "",
        }

        with mock.patch.object(snapshot_module, "check_http_services_detailed", return_value=[]), \
             mock.patch.object(snapshot_module, "collect_alerts_with_auth_observation", return_value=({}, auth_observation())), \
             mock.patch.object(snapshot_module, "load_quota_context", return_value={}), \
             mock.patch.object(snapshot_module, "quota_alerts_from_context", return_value=[]), \
             mock.patch.object(snapshot_module, "quota_rows_from_context", return_value=[]), \
             mock.patch.object(snapshot_module, "gpt_pool_capacity_snapshot", return_value=pool), \
             mock.patch.object(snapshot_module, "usage_rate_estimate", return_value={"tokens_per_hour": 1, "error": ""}):
            result = snapshot_module.build_snapshot()

        alert = result["system_alerts"].get("auth:codex-free-plan")
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "warning")
        self.assertEqual(alert["title"], "Codex accounts downgraded to Free")
        self.assertIn("- Account codex-edu-account@example.com is reported to have a Free quota", alert["body"])
        self.assertNotIn("codex-free", alert["body"])
        text = build_alert_message(Alert(**alert))
        self.assertEqual(text.splitlines()[0], "[WARN] Codex accounts downgraded to Free")
        self.assertNotIn("Impact:", text)
        self.assertIn("Evidence:\n- Account codex-edu-account@example.com is reported to have a Free quota and is excluded from the GPT Plus pool capacity.", text)
        self.assertIn("Action:\nReplace the account or renew Plus.", text)

    def test_codex_free_plan_alert_falls_back_to_short_hash_without_safe_label(self):
        alert = health.codex_free_plan_alert({
            "free_codex_count": 1,
            "free_codex_hashes": ["a328f1bfb2740811"],
        })

        self.assertIsNotNone(alert)
        self.assertEqual(alert.title, "Codex accounts downgraded to Free")
        text = build_alert_message(alert)

        self.assertIn("- Account hash a328f1bfb2740811 is reported to have a Free quota", text)
        self.assertNotIn("Impact:", text)

    def test_gpt_pool_capacity_missing_quota_rows_reduce_coverage(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "items": [
                        {"auth_index": "codex-1", "type": "codex"},
                        {"auth_index": "codex-2", "type": "codex"},
                    ]
                }, ""
            if path == "quota/cache":
                return 200, {
                    "results": [
                        {"auth_index": "codex-1", "quotas": [{"key": "rate_limit.primary_window", "usedPercent": 25}]},
                        {"auth_index": "codex-2", "quotas": []},
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.health.management_gpt_pool_capacity_snapshot", return_value=health.empty_gpt_pool_capacity("management unavailable", source="management_fallback")):
            pool = health.gpt_pool_capacity_snapshot()

        self.assertEqual(pool["enabled_codex_count"], 2)
        self.assertEqual(pool["primary"]["checked_count"], 1)
        self.assertEqual(pool["primary"]["avg_left_percent"], 75.0)
        self.assertEqual(pool["primary"]["lowest_left_percent"], 75.0)
        self.assertEqual(pool["secondary"]["checked_count"], 0)
        self.assertIsNone(pool["secondary"]["avg_left_percent"])
        self.assertIsNone(pool["secondary"]["lowest_left_percent"])

    def test_gpt_pool_capacity_skips_management_fallback_when_usage_keeper_complete(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [{"auth_index": "codex-1", "type": "codex"}]}, ""
            if path == "quota/cache":
                return 200, {
                    "items": [{
                        "auth_index": "codex-1",
                        "quota": {"quota": [
                            {"key": "rate_limit.primary_window", "usedPercent": 20},
                            {"key": "rate_limit.secondary_window", "usedPercent": 40},
                        ]},
                    }]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.health.management_gpt_pool_capacity_snapshot") as fallback:
            pool = health.gpt_pool_capacity_snapshot()

        fallback.assert_not_called()
        self.assertEqual(pool["source"], "usage_keeper")
        self.assertEqual(pool["enabled_codex_count"], 1)
        self.assertEqual(pool["primary"]["checked_count"], 1)
        self.assertEqual(pool["secondary"]["checked_count"], 1)

    def test_gpt_pool_capacity_uses_management_fallback_when_usage_keeper_incomplete(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [{"auth_index": "codex-1", "type": "codex"}, {"auth_index": "codex-2", "type": "codex"}]}, ""
            if path == "quota/cache":
                return 200, {
                    "items": [
                        {"auth_index": "codex-1", "quota": {"quota": [{"key": "rate_limit.primary_window", "usedPercent": 20}]}},
                        {"auth_index": "codex-2", "quota": {"quota": []}},
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        fallback_pool = {
            "source": "management_fallback",
            "enabled_codex_count": 2,
            "primary": {"checked_count": 2, "avg_left_percent": 65.0, "lowest_left_percent": 60.0, "left_tokens": 26_000_000.0},
            "secondary": {"checked_count": 2, "avg_left_percent": 45.0, "lowest_left_percent": 30.0, "left_tokens": 126_000_000.0},
            "error": "",
            "usage_keeper_checked_count": 1,
            "management_checked_count": 2,
            "missing_rows_count": 0,
        }
        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.health.management_gpt_pool_capacity_snapshot", return_value=fallback_pool) as fallback:
            pool = health.gpt_pool_capacity_snapshot()

        fallback.assert_called_once_with(enabled_count_hint=2)
        self.assertEqual(pool["source"], "management_fallback")
        self.assertEqual(pool["enabled_codex_count"], 2)
        self.assertEqual(pool["primary"]["checked_count"], 2)
        self.assertEqual(pool["secondary"]["checked_count"], 2)

    def test_management_fallback_complete_builds_aggregate_capacity(self):
        calls = []

        def fake_management_request(path, method="GET", payload=None):
            calls.append((path, method, payload))
            if path == "auth-files":
                return {
                    "files": [
                        {"name": "codex-secret@example.com.json", "type": "codex", "auth_index": "auth-secret-1", "disabled": False},
                        {"name": "codex-token-secret.json", "provider": "codex", "auth_index": "auth-secret-2", "disabled": False},
                        {"name": "codex-disabled.json", "type": "codex", "auth_index": "auth-disabled", "disabled": True},
                        {"name": "ag.json", "type": "antigravity", "auth_index": "ag-1"},
                    ]
                }
            if path == "api-call":
                auth_index = payload["authIndex"]
                used = {"auth-secret-1": (20, 60), "auth-secret-2": (40, 80)}[auth_index]
                return {
                    "status_code": 200,
                    "body": {
                        "rate_limit": {
                            "primary_window": {"used_percent": used[0], "reset_after_seconds": 100},
                            "secondary_window": {"usedPercent": used[1], "reset_after_seconds": 200},
                        }
                    },
                }
            raise AssertionError(f"unexpected management path {path}")

        with mock.patch("telegram_alerts.health.CLIPROXY_MANAGEMENT_TOKEN", "management-secret-token"), \
             mock.patch("telegram_alerts.health.management_request", side_effect=fake_management_request):
            pool = health.management_gpt_pool_capacity_snapshot(enabled_count_hint=2)

        self.assertEqual(pool["source"], "management_fallback")
        self.assertEqual(pool["enabled_codex_count"], 2)
        self.assertEqual(pool["primary"]["checked_count"], 2)
        self.assertEqual(pool["primary"]["avg_left_percent"], 70.0)
        self.assertEqual(pool["primary"]["lowest_left_percent"], 60.0)
        self.assertEqual(pool["secondary"]["checked_count"], 2)
        self.assertEqual(pool["secondary"]["avg_left_percent"], 30.0)
        self.assertEqual(pool["secondary"]["lowest_left_percent"], 20.0)
        self.assertNotIn("secret@example.com", repr(pool))
        self.assertNotIn("auth-secret", repr(pool))
        self.assertNotIn("management-secret-token", repr(pool))
        self.assertEqual(len([call for call in calls if call[0] == "api-call"]), 2)

    def test_management_fallback_unavailable_keeps_incomplete_usage_keeper_capacity(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [{"auth_index": "codex-1", "type": "codex"}, {"auth_index": "codex-2", "type": "codex"}]}, ""
            if path == "quota/cache":
                return 200, {"items": [{"auth_index": "codex-1", "quotas": [{"key": "rate_limit.primary_window", "usedPercent": 20}]}]}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.health.management_gpt_pool_capacity_snapshot", return_value=health.empty_gpt_pool_capacity("management unavailable", source="management_fallback")):
            pool = health.gpt_pool_capacity_snapshot()

        self.assertEqual(pool["source"], "usage_keeper")
        self.assertEqual(pool["enabled_codex_count"], 2)
        self.assertEqual(pool["primary"]["checked_count"], 1)
        self.assertEqual(pool["secondary"]["checked_count"], 0)

    def test_reauth_auth_health_still_uses_quota_inspection_only(self):
        payload = inspection_payload_with_total([auth_item(name="normal", status="normal", auth_index="auth-1")], total=1)
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload) as inspection, \
             mock.patch("telegram_alerts.health.management_gpt_pool_capacity_snapshot") as fallback:
            alerts, observation = health.check_auth_quota_status_with_observation()

        inspection.assert_called_once()
        fallback.assert_not_called()
        self.assertEqual(alerts, [])
        self.assertTrue(observation["complete"])

    def test_gpt_pool_capacity_unavailable_is_sanitized(self):
        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", ""):
            pool = health.gpt_pool_capacity_snapshot()

        self.assertEqual(pool["enabled_codex_count"], 0)
        self.assertEqual(pool["primary"]["checked_count"], 0)
        self.assertEqual(pool["secondary"]["checked_count"], 0)
        self.assertIn("unavailable", pool["error"])

    def test_capacity_demand_rate_estimate_averages_realtime_token_velocity(self):
        calls = []

        def fake_request(path, method="GET", payload=None, cookie=None):
            calls.append((path, method, payload, cookie))
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path == "usage/overview/realtime?window=60m":
                return 200, {
                    "window": "60m",
                    "token_velocity": [
                        {"tokens_per_minute": 1000, "tokens": 120000},
                        {"tokens_per_minute": 2000, "tokens": 240000},
                        {"tokens": 999999},
                    ],
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.usage.usage_rate_estimate") as local:
            rate = usage_module.capacity_demand_rate_estimate()

        local.assert_not_called()
        self.assertEqual(rate["tokens_per_hour"], 90_000)
        self.assertEqual(rate["tokens"], 90_000)
        self.assertEqual(rate["source"], "usage_keeper_realtime")
        self.assertEqual(rate["source_label"], "Usage Keeper realtime 60m")
        self.assertEqual(rate["display_suffix"], "60m realtime")
        self.assertEqual(rate["error"], "")
        self.assertEqual(calls[1][0], "usage/overview/realtime?window=60m")

    def test_capacity_demand_rate_estimate_falls_back_when_realtime_malformed(self):
        local_rate = {
            "tokens": 6_000_000,
            "requests": 7,
            "hours": 3.0,
            "tokens_per_hour": 2_000_000,
            "lookback_hours": 3,
            "source": "recent",
            "error": "",
        }

        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path == "usage/overview/realtime?window=60m":
                return 200, {"token_velocity": [{"tokens": 120000}]}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.usage.usage_rate_estimate", return_value=local_rate) as local:
            rate = usage_module.capacity_demand_rate_estimate()

        local.assert_called_once()
        self.assertEqual(rate["tokens_per_hour"], 2_000_000)
        self.assertEqual(rate["source_label"], "local usage estimate")
        self.assertNotIn("display_suffix", rate)
        self.assertEqual(rate["error"], "")

    def test_gpt_pool_capacity_recent_cache_fills_missing_weekly_row(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "identities": [
                        {"identity": "codex-a@example.com", "type": "codex", "disabled": False, "is_deleted": False},
                        {"identity": "codex-b@example.com", "type": "codex", "disabled": False, "is_deleted": False},
                        {"identity": "codex-c@example.com", "type": "codex", "disabled": False, "is_deleted": False},
                    ]
                }, ""
            if path == "quota/cache":
                return 200, {
                    "items": [
                        {"auth_index": "codex-a@example.com", "quota": {"quota": [
                            {"key": "rate_limit.primary_window", "usedPercent": 10},
                            {"key": "rate_limit.secondary_window", "usedPercent": 20},
                        ]}},
                        {"auth_index": "codex-b@example.com", "quota": {"quota": [
                            {"key": "rate_limit.primary_window", "usedPercent": 30},
                            {"key": "rate_limit.secondary_window", "usedPercent": 40},
                        ]}},
                        {"auth_index": "codex-c@example.com", "quota": {"quota": [
                            {"key": "rate_limit.primary_window", "usedPercent": 50},
                        ]}},
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        recent_cache = {
            "created_at": 1_000,
            "identities": {
                health.gpt_pool_recent_cache_identity_key("codex-c@example.com"): {"secondary": 40.0},
                health.gpt_pool_recent_cache_identity_key("codex-old@example.com"): {"primary": 1.0, "secondary": 1.0},
            },
        }

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.health.management_gpt_pool_capacity_snapshot") as management_fallback:
            pool, next_cache = health.gpt_pool_capacity_snapshot_with_recent_cache(
                recent_cache=recent_cache,
                cache_now=1_030,
                cache_max_age_seconds=60,
                allow_management_fallback=False,
            )

        management_fallback.assert_not_called()
        self.assertEqual(pool["enabled_codex_count"], 3)
        self.assertEqual(pool["primary"]["checked_count"], 3)
        self.assertEqual(pool["secondary"]["checked_count"], 3)
        self.assertEqual(pool["secondary"]["avg_left_percent"], 60.0)
        self.assertEqual(pool["secondary"]["lowest_left_percent"], 40.0)
        self.assertEqual(pool["usage_keeper_checked_count"], 3)
        self.assertEqual(pool["missing_rows_count"], 0)
        text = snapshot_module.build_capacity_reply(
            {"created_at": 1_030, "enforcer_age": "1s", "quota_error": "", "quota_rows": [], "gpt_pool_capacity": pool},
            {"tokens_per_hour": 1_000_000, "lookback_hours": 1, "hours": 1, "tokens": 1_000_000, "requests": 1, "source": "recent", "error": ""},
        )
        self.assertIn("5h avail:", text)
        self.assertIn("Weekly avail:", text)
        self.assertNotIn("Quota data updating", text)
        self.assertNotIn("codex-a@example.com", repr(next_cache))
        self.assertNotIn("codex-b@example.com", repr(next_cache))
        self.assertNotIn("codex-c@example.com", repr(next_cache))
        self.assertNotIn("codex-old@example.com", repr(next_cache))

    def test_gpt_pool_capacity_current_weekly_row_wins_over_recent_cache(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [{"auth_index": "codex-current", "type": "codex"}]}, ""
            if path == "quota/cache":
                return 200, {"items": [{"auth_index": "codex-current", "quotas": [
                    {"key": "rate_limit.primary_window", "usedPercent": 10},
                    {"key": "rate_limit.secondary_window", "usedPercent": 20},
                ]}]}, ""
            raise AssertionError(f"unexpected request {path}")

        recent_cache = {
            "created_at": 2_000,
            "identities": {
                health.gpt_pool_recent_cache_identity_key("codex-current"): {"primary": 1.0, "secondary": 5.0},
            },
        }

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            pool, next_cache = health.gpt_pool_capacity_snapshot_with_recent_cache(
                recent_cache=recent_cache,
                cache_now=2_030,
                cache_max_age_seconds=60,
                allow_management_fallback=False,
            )

        self.assertEqual(pool["primary"]["checked_count"], 1)
        self.assertEqual(pool["secondary"]["checked_count"], 1)
        self.assertEqual(pool["primary"]["avg_left_percent"], 90.0)
        self.assertEqual(pool["secondary"]["avg_left_percent"], 80.0)
        self.assertEqual(pool["primary"]["left_tokens"], 18_000_000.0)
        self.assertEqual(pool["secondary"]["left_tokens"], 112_000_000.0)
        self.assertEqual(next_cache["identities"][health.gpt_pool_recent_cache_identity_key("codex-current")]["secondary"], 80.0)
        self.assertNotIn("codex-current", repr(next_cache))

    def test_auth_quota_observation_and_state_store_failed_auth_index_hashes(self):
        payload = inspection_payload_with_total([
            auth_item(name="codex-one", status="unauthorized_401", auth_index="codex-reauth-1"),
            auth_item(name="codex-two", status="needs_reauth", auth_index="codex-reauth-2"),
            auth_item(name="codex-limit", status="limit_reached", auth_index="codex-limit"),
            {
                "file_name": "codex-secret@example.com.json",
                "name": "codex-secret@example.com",
                "status": "unauthorized_401",
                "error": "HTTP 401 bearer secret-token",
            },
        ], total=4)

        observation = health.auth_quota_observation_from_payload(payload)
        state = {}
        app.update_auth_inspection_state(state, observation, ts=1_000)
        saved = state[app.AUTH_INSPECTION_STATE_KEY]

        self.assertTrue(observation["complete"])
        self.assertEqual(
            observation["failed_auth_index_keys"],
            sorted({auth_index_key("codex-reauth-1"), auth_index_key("codex-reauth-2")}),
        )
        self.assertEqual(saved["failed_auth_index_keys"], observation["failed_auth_index_keys"])
        self.assertNotIn(auth_index_key("codex-limit"), saved["failed_auth_index_keys"])
        self.assertNotIn("codex-reauth-1", repr(saved))
        self.assertIn("codex-secret@example.com", repr(saved))
        self.assertNotIn("secret-token", repr(saved))

    def test_capacity_recent_complete_unauthorized_excludes_matched_auth_index(self):
        calls = []
        auth_state = {}
        observation = health.auth_quota_observation_from_payload(inspection_payload_with_total([
            auth_item(name="broken-account", status="unauthorized_401", auth_index="codex-broken"),
            auth_item(name="healthy-account-a", status="normal", auth_index="codex-ok-a"),
            auth_item(name="healthy-account-b", status="normal", auth_index="codex-ok-b"),
        ], total=3))
        app.update_auth_inspection_state(auth_state, observation, ts=1_000)

        def fake_request(path, method="GET", payload=None, cookie=None):
            calls.append((path, method, payload))
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [
                    {"auth_index": "codex-broken", "type": "codex"},
                    {"auth_index": "codex-ok-a", "type": "codex"},
                    {"auth_index": "codex-ok-b", "type": "codex"},
                ]}, ""
            if path == "quota/cache":
                self.assertEqual(payload, {"auth_indexes": ["codex-ok-a", "codex-ok-b"]})
                return 200, {"items": [
                    {"auth_index": "codex-ok-a", "quotas": [
                        {"key": "rate_limit.primary_window", "usedPercent": 20},
                        {"key": "rate_limit.secondary_window", "usedPercent": 40},
                    ]},
                    {"auth_index": "codex-ok-b", "quotas": [
                        {"key": "rate_limit.primary_window", "usedPercent": 40},
                        {"key": "rate_limit.secondary_window", "usedPercent": 80},
                    ]},
                ]}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.health.management_gpt_pool_capacity_snapshot") as management_fallback:
            pool, next_cache = health.gpt_pool_capacity_snapshot_with_recent_cache(
                recent_cache={},
                cache_now=1_030,
                cache_max_age_seconds=60,
                allow_management_fallback=False,
                auth_inspection_state=auth_state[app.AUTH_INSPECTION_STATE_KEY],
            )

        management_fallback.assert_not_called()
        self.assertEqual(pool["enabled_codex_count"], 2)
        self.assertEqual(pool["total_enabled_codex_count"], 3)
        self.assertEqual(pool["excluded_reauth_count"], 1)
        self.assertEqual(pool["usable_codex_count"], 2)
        self.assertEqual(pool["primary"]["checked_count"], 2)
        self.assertEqual(pool["secondary"]["checked_count"], 2)
        self.assertEqual(pool["primary"]["avg_left_percent"], 70.0)
        self.assertEqual([call[2] for call in calls if call[0] == "quota/cache"], [{"auth_indexes": ["codex-ok-a", "codex-ok-b"]}])
        self.assertNotIn("codex-broken", repr(pool))
        self.assertNotIn("codex-broken", repr(next_cache))

    def test_capacity_recent_complete_needs_reauth_excludes_matched_auth_index(self):
        auth_state = {}
        observation = health.auth_quota_observation_from_payload(inspection_payload_with_total([
            auth_item(name="broken-account", status="needs_reauth", auth_index="codex-needs-reauth"),
            auth_item(name="healthy-account", status="normal", auth_index="codex-ok"),
        ], total=2))
        app.update_auth_inspection_state(auth_state, observation, ts=2_000)

        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [
                    {"auth_index": "codex-needs-reauth", "type": "codex"},
                    {"auth_index": "codex-ok", "type": "codex"},
                ]}, ""
            if path == "quota/cache":
                self.assertEqual(payload, {"auth_indexes": ["codex-ok"]})
                return 200, {"items": [{"auth_index": "codex-ok", "quotas": [
                    {"key": "rate_limit.primary_window", "usedPercent": 25},
                    {"key": "rate_limit.secondary_window", "usedPercent": 50},
                ]}]}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            pool, _ = health.gpt_pool_capacity_snapshot_with_recent_cache(
                cache_now=2_010,
                cache_max_age_seconds=60,
                allow_management_fallback=False,
                auth_inspection_state=auth_state[app.AUTH_INSPECTION_STATE_KEY],
            )

        self.assertEqual(pool["enabled_codex_count"], 1)
        self.assertEqual(pool["total_enabled_codex_count"], 2)
        self.assertEqual(pool["excluded_reauth_count"], 1)
        self.assertEqual(pool["usable_codex_count"], 1)
        self.assertEqual(pool["primary"]["checked_count"], 1)

    def test_capacity_stale_incomplete_unmappable_and_limit_reached_do_not_exclude(self):
        scenarios = [
            ("stale", {
                "raw_current_complete": True,
                "last_complete_at": 1_000,
                "failed_auth_index_keys": [auth_index_key("codex-broken")],
            }, 2_900),
            ("incomplete", {
                "raw_current_complete": False,
                "last_complete_at": 2_000,
                "failed_auth_index_keys": [auth_index_key("codex-broken")],
            }, 2_010),
            ("unmappable", app.update_auth_inspection_state({}, health.auth_quota_observation_from_payload(inspection_payload_with_total([
                {
                    "file_name": "codex-secret@example.com.json",
                    "name": "codex-secret@example.com",
                    "status": "unauthorized_401",
                    "error": "HTTP 401",
                },
                auth_item(name="healthy-account", status="normal", auth_index="codex-ok"),
            ], total=2)), ts=3_000), 3_010),
            ("limit_reached", app.update_auth_inspection_state({}, health.auth_quota_observation_from_payload(inspection_payload_with_total([
                auth_item(name="quota-limited", status="limit_reached", auth_index="codex-broken"),
                auth_item(name="healthy-account", status="normal", auth_index="codex-ok"),
            ], total=2)), ts=4_000), 4_010),
        ]

        for name, auth_state, cache_now in scenarios:
            with self.subTest(name=name):
                def fake_request(path, method="GET", payload=None, cookie=None):
                    if path == "auth/login":
                        return 200, {}, "session=abc; Path=/"
                    if path.startswith("usage/identities/page"):
                        return 200, {"items": [
                            {"auth_index": "codex-broken", "type": "codex"},
                            {"auth_index": "codex-ok", "type": "codex"},
                        ]}, ""
                    if path == "quota/cache":
                        self.assertEqual(payload, {"auth_indexes": ["codex-broken", "codex-ok"]})
                        return 200, {"items": [
                            {"auth_index": "codex-broken", "quotas": [
                                {"key": "rate_limit.primary_window", "usedPercent": 20},
                                {"key": "rate_limit.secondary_window", "usedPercent": 40},
                            ]},
                            {"auth_index": "codex-ok", "quotas": [
                                {"key": "rate_limit.primary_window", "usedPercent": 40},
                                {"key": "rate_limit.secondary_window", "usedPercent": 80},
                            ]},
                        ]}, ""
                    raise AssertionError(f"unexpected request {path}")

                with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
                     mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
                    pool, _ = health.gpt_pool_capacity_snapshot_with_recent_cache(
                        cache_now=cache_now,
                        cache_max_age_seconds=60,
                        allow_management_fallback=False,
                        auth_inspection_state=auth_state,
                    )

                self.assertEqual(pool["enabled_codex_count"], 2)
                self.assertNotIn("excluded_reauth_count", pool)
                self.assertEqual(pool["primary"]["checked_count"], 2)
                if name == "unmappable":
                    self.assertIn("codex-secret@example.com", repr(auth_state))
                else:
                    self.assertNotIn("codex-secret@example.com", repr(auth_state))

    def test_capacity_all_reauth_excluded_does_not_request_empty_quota_cache(self):
        auth_state = {
            "raw_current_complete": True,
            "last_complete_at": 5_000,
            "failed_auth_index_keys": [auth_index_key("codex-a"), auth_index_key("codex-b")],
        }
        calls = []

        def fake_request(path, method="GET", payload=None, cookie=None):
            calls.append((path, method, payload))
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [
                    {"auth_index": "codex-a", "type": "codex"},
                    {"auth_index": "codex-b", "type": "codex"},
                ]}, ""
            if path == "quota/cache":
                self.fail("quota/cache must not be called with an empty usable auth_indexes list")
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.health.management_gpt_pool_capacity_snapshot") as management_fallback:
            pool, next_cache = health.gpt_pool_capacity_snapshot_with_recent_cache(
                cache_now=5_010,
                cache_max_age_seconds=60,
                allow_management_fallback=False,
                auth_inspection_state=auth_state,
            )

        management_fallback.assert_not_called()
        self.assertEqual([call[0] for call in calls], ["auth/login", "usage/identities/page?auth_type=1&active_only=true&page=1&page_size=500"])
        self.assertEqual(pool["enabled_codex_count"], 0)
        self.assertEqual(pool["total_enabled_codex_count"], 2)
        self.assertEqual(pool["excluded_reauth_count"], 2)
        self.assertEqual(pool["usable_codex_count"], 0)
        self.assertEqual(pool["primary"]["checked_count"], 0)
        self.assertEqual(pool["secondary"]["checked_count"], 0)
        self.assertEqual(next_cache["identities"], {})

    def test_gpt_pool_capacity_stale_recent_cache_does_not_fill_missing_weekly_row(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {"items": [
                    {"auth_index": "codex-a", "type": "codex"},
                    {"auth_index": "codex-b", "type": "codex"},
                ]}, ""
            if path == "quota/cache":
                return 200, {"items": [
                    {"auth_index": "codex-a", "quotas": [
                        {"key": "rate_limit.primary_window", "usedPercent": 20},
                        {"key": "rate_limit.secondary_window", "usedPercent": 50},
                    ]},
                    {"auth_index": "codex-b", "quotas": [
                        {"key": "rate_limit.primary_window", "usedPercent": 40},
                    ]},
                ]}, ""
            raise AssertionError(f"unexpected request {path}")

        recent_cache = {
            "created_at": 1_000,
            "identities": {health.gpt_pool_recent_cache_identity_key("codex-b"): {"secondary": 70.0}},
        }

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.health.management_gpt_pool_capacity_snapshot"):
            pool, _ = health.gpt_pool_capacity_snapshot_with_recent_cache(
                recent_cache=recent_cache,
                cache_now=1_061,
                cache_max_age_seconds=60,
                allow_management_fallback=False,
            )

        self.assertEqual(pool["enabled_codex_count"], 2)
        self.assertEqual(pool["primary"]["checked_count"], 2)
        self.assertEqual(pool["secondary"]["checked_count"], 1)
        self.assertEqual(pool["usage_keeper_checked_count"], 1)
        self.assertEqual(pool["missing_rows_count"], 1)

    def test_gpt_pool_capacity_can_skip_management_fallback_for_partial_usage_keeper_cache(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path.startswith("usage/identities/page"):
                return 200, {
                    "identities": [
                        {"identity": "codex-a", "type": "codex", "disabled": False, "is_deleted": False},
                        {"identity": "codex-b", "type": "codex", "disabled": False, "is_deleted": False},
                        {"identity": "codex-c", "type": "codex", "disabled": False, "is_deleted": False},
                    ]
                }, ""
            if path == "quota/cache":
                return 200, {
                    "items": [
                        {
                            "auth_index": "codex-a",
                            "quota": {"quota": [
                                {"key": "rate_limit.primary_window", "usedPercent": 10},
                                {"key": "rate_limit.secondary_window", "usedPercent": 20},
                            ]},
                        },
                        {
                            "auth_index": "codex-b",
                            "quota": {"quota": [
                                {"key": "rate_limit.primary_window", "usedPercent": 30},
                                {"key": "rate_limit.secondary_window", "usedPercent": 40},
                            ]},
                        },
                        {
                            "auth_index": "codex-c",
                            "quota": {"quota": [
                                {"key": "rate_limit.primary_window", "usedPercent": 50},
                            ]},
                        },
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.health.management_gpt_pool_capacity_snapshot") as management_fallback:
            pool = health.gpt_pool_capacity_snapshot(allow_management_fallback=False)

        management_fallback.assert_not_called()
        self.assertEqual(pool["source"], "usage_keeper")
        self.assertEqual(pool["enabled_codex_count"], 3)
        self.assertEqual(pool["primary"]["checked_count"], 3)
        self.assertEqual(pool["secondary"]["checked_count"], 2)
        self.assertEqual(pool["usage_keeper_checked_count"], 2)
        self.assertEqual(pool["missing_rows_count"], 1)

    def test_gpt_pool_5h_observation_marks_complete_low_and_recovered_states(self):
        pool = {
            "enabled_codex_count": 8,
            "primary": {"checked_count": 8, "left_tokens": 70_000_000.0},
            "secondary": {"checked_count": 8, "left_tokens": 900_000_000.0},
            "error": "",
        }

        low = snapshot_module.gpt_pool_5h_observation(
            {"gpt_pool_capacity": pool},
            {"tokens_per_hour": 20_000_000, "error": ""},
        )
        recovered = snapshot_module.gpt_pool_5h_observation(
            {"gpt_pool_capacity": pool},
            {"tokens_per_hour": 10_000_000, "error": ""},
        )

        self.assertTrue(low["complete"])
        self.assertAlmostEqual(low["margin"], 0.7)
        self.assertTrue(low["low"])
        self.assertFalse(low["recovered"])
        self.assertTrue(recovered["complete"])
        self.assertGreaterEqual(recovered["margin"], 1.2)
        self.assertTrue(recovered["recovered"])

    def test_gpt_pool_5h_observation_marks_incomplete_coverage_and_rate_errors(self):
        incomplete_pool = {
            "enabled_codex_count": 8,
            "primary": {"checked_count": 6, "left_tokens": 70_000_000.0},
            "secondary": {"checked_count": 8, "left_tokens": 900_000_000.0},
            "error": "",
        }
        complete_pool = {
            "enabled_codex_count": 8,
            "primary": {"checked_count": 8, "left_tokens": 70_000_000.0},
            "secondary": {"checked_count": 8, "left_tokens": 900_000_000.0},
            "error": "",
        }

        coverage = snapshot_module.gpt_pool_5h_observation(
            {"gpt_pool_capacity": incomplete_pool},
            {"tokens_per_hour": 20_000_000, "error": ""},
        )
        demand = snapshot_module.gpt_pool_5h_observation(
            {"gpt_pool_capacity": complete_pool},
            {"error": "usage unavailable"},
        )

        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["reason"], "incomplete-coverage")
        self.assertFalse(demand["complete"])
        self.assertEqual(demand["reason"], "demand-unavailable")


class AuthReauthAlertTests(unittest.TestCase):
    def test_invalidated_token_evidence_variants_canonicalize_to_same_detail(self):
        first = health.canonical_reauth_evidence_detail(
            "401 Encountered invalidated oauth token for user, failing request"
        )
        second = health.canonical_reauth_evidence_detail(
            "401 Your authentication token has been invalidated. Please try signing in again."
        )
        third = health.canonical_reauth_evidence_detail(
            "HTTP 401: Your authentication token has been invalidated. Please try signing in again."
        )

        self.assertEqual(first, "401 Encountered invalidated oauth token for user, failing request")
        self.assertEqual(second, first)
        self.assertEqual(third, first)

    def test_strong_unauthorized_status_creates_reauth_alert(self):
        payload = inspection_payload(auth_item(name="alice@example.com.json"))
        payload["results"][0].update({
            "token": "sk-secret-token-value",
            "cookie": "session-cookie-secret",
            "api_key": "ck-secret-api-key",
            "management_token": "management-secret-value",
            "raw_auth": "raw auth secret",
        })
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts = check_auth_quota_status(refresh_before_check=True, wait_for_refresh=True)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.alert_id, "auth:quota-inspection-failed")
        self.assertEqual(alert.title, "Proxy accounts need reauth")
        self.assertEqual(alert.severity, "critical")
        self.assertIn("alice@example.com", alert.body)
        self.assertNotIn("Account ending", alert.body)
        self.assertNotIn("alice@example.com.json", alert.body)
        self.assertIn("- alice@example.com:", alert.body)
        self.assertNotIn("- Account ", alert.body)
        self.assertNotIn("unauthorized_401", alert.body)
        self.assertNotIn("sk-secret-token-value", alert.body)
        self.assertNotIn("session-cookie-secret", alert.body)
        self.assertNotIn("ck-secret-api-key", alert.body)
        self.assertNotIn("management-secret-value", alert.body)
        self.assertNotIn("raw auth secret", alert.body)

    def test_token_revoked_status_creates_reauth_alert(self):
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=inspection_payload(auth_item(status="token_revoked", error="token revoked"))):
            alerts = check_auth_quota_status(refresh_before_check=True, wait_for_refresh=True)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_id, "auth:quota-inspection-failed")
        self.assertIn("token revoked", alerts[0].body)
        self.assertNotIn("token_revoked", alerts[0].body)

    def test_disabled_auth_row_with_invalidated_401_error_creates_reauth_observation(self):
        payload = inspection_payload({
            "file_name": "disabled-codex.json",
            "auth_index": "disabled-codex-index",
            "disabled": True,
            "status": "failed",
            "http_status_code": 401,
            "error": "HTTP 401: Your authentication token has been invalidated. Please try signing in again.",
        })

        observation = health.auth_quota_observation_from_payload(payload)

        self.assertTrue(observation["complete"])
        self.assertEqual(len(observation["failed_identity_keys"]), 1)
        self.assertEqual(observation["failed_auth_index_keys"], [auth_index_key("disabled-codex-index")])
        self.assertNotIn("disabled-codex.json", repr(observation))

    def test_auth_quota_status_includes_disabled_quota_cache_401_rows(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path.startswith("usage/identities/page"):
                self.assertIn("active_only=false", path)
                return 200, {
                    "items": [
                        {"auth_index": "enabled-codex", "type": "codex", "disabled": False},
                        {"auth_index": "disabled-codex", "type": "codex", "disabled": True},
                    ]
                }, ""
            if path == "quota/cache":
                self.assertEqual(payload, {"auth_indexes": ["enabled-codex", "disabled-codex"]})
                return 200, {
                    "items": [
                        {
                            "auth_index": "enabled-codex",
                            "status": "completed",
                            "quotas": [
                                {"key": "rate_limit.primary_window", "planType": "plus", "window": {"seconds": 18000}, "usedPercent": 10},
                                {"key": "rate_limit.secondary_window", "planType": "plus", "window": {"seconds": 604800}, "usedPercent": 20},
                            ],
                        },
                        {
                            "auth_index": "disabled-codex",
                            "status": "failed",
                            "http_status_code": 401,
                            "error": "HTTP 401: Your authentication token has been invalidated. Please try signing in again.",
                        },
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=inspection_payload(auth_item(name="enabled", status="normal", error="", auth_index="enabled-codex"))), \
             mock.patch("telegram_alerts.health.usage_keeper_session_cookie", return_value="session=abc"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            alerts, observation = health.check_auth_quota_status_with_observation(refresh_before_check=False, wait_for_refresh=False)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_id, "auth:quota-inspection-failed")
        self.assertIn("401 Encountered invalidated oauth token for user, failing request", alerts[0].body)
        self.assertNotIn("Please try signing in again", alerts[0].body)
        self.assertNotIn("disabled-codex", alerts[0].body)
        self.assertIn(auth_index_key("disabled-codex"), observation["failed_auth_index_keys"])

    def test_disabled_reauth_quota_cache_uses_safe_identity_label(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path.startswith("usage/identities/page"):
                return 200, {
                    "items": [
                        {"auth_index": "enabled-codex", "identity": "codex-healthy@example.com-plus.json", "type": "codex", "disabled": False},
                        {"auth_index": "disabled-codex", "identity": "codex-edu-account@example.com-plus.json", "type": "codex", "disabled": True},
                    ]
                }, ""
            if path == "quota/cache":
                return 200, {
                    "items": [
                        {"auth_index": "enabled-codex", "status": "completed"},
                        {
                            "auth_index": "disabled-codex",
                            "status": "failed",
                            "http_status_code": 401,
                            "error": "HTTP 401: Encountered invalidated oauth token for user, failing request",
                        },
                    ]
                }, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=inspection_payload(auth_item(name="enabled", status="normal", error="", auth_index="enabled-codex"))), \
             mock.patch("telegram_alerts.health.usage_keeper_session_cookie", return_value="session=abc"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            alerts, observation = health.check_auth_quota_status_with_observation(refresh_before_check=False, wait_for_refresh=False)

        self.assertEqual(len(alerts), 1)
        text = build_alert_message(alerts[0])
        self.assertIn("Evidence: 401 Encountered invalidated oauth token for user, failing request", text)
        self.assertIn("- codex-edu-account@example.com", text)
        self.assertNotIn("- codex-edu-account@example.com:", text)
        self.assertNotIn("- Account ", text)
        self.assertNotIn("Account hash", text)
        self.assertIn(auth_index_key("disabled-codex"), observation["failed_auth_index_keys"])

    def test_multiple_reauth_accounts_render_exact_shared_evidence_template(self):
        payload = inspection_payload(
            auth_item(name="codex-account-c@example.com.json", status="unauthorized_401", error="HTTP 401: Encountered invalidated oauth token for user, failing request", auth_index="auth-one"),
            auth_item(name="codex-account-a@example.com.json", status="unauthorized_401", error="HTTP 401: Encountered invalidated oauth token for user, failing request", auth_index="auth-two"),
        )

        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts = check_auth_quota_status(refresh_before_check=False, wait_for_refresh=False)

        text = build_alert_message(alerts[0])
        self.assertEqual(text, "\n".join([
            "[CRITICAL] Proxy accounts need reauth",
            "",
            "Evidence: 401 Encountered invalidated oauth token for user, failing request",
            "- codex-account-a@example.com",
            "- codex-account-c@example.com",
            "",
            "Action:",
            "Reauth the listed account(s), then check Health alerts.",
        ]))
        self.assertNotIn("- Account ", text)

    def test_mixed_invalidated_token_evidence_renders_one_compact_group(self):
        payload = inspection_payload(
            auth_item(name="codex-account-e@example.com.json", status="unauthorized_401", error="HTTP 401: Encountered invalidated oauth token for user, failing request", auth_index="auth-one"),
            auth_item(name="codex-account-c@example.com.json", status="unauthorized_401", error="HTTP 401: Encountered invalidated oauth token for user, failing request", auth_index="auth-two"),
            auth_item(name="codex-account-h@example.com.json", status="unauthorized_401", error="HTTP 401: Encountered invalidated oauth token for user, failing request", auth_index="auth-three"),
            auth_item(name="codex-account-g@example.com.json", status="unauthorized_401", error="HTTP 401: Your authentication token has been invalidated. Please try signing in again.", auth_index="auth-four"),
        )

        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts = check_auth_quota_status(refresh_before_check=False, wait_for_refresh=False)

        text = build_alert_message(alerts[0])
        self.assertEqual(text, "\n".join([
            "[CRITICAL] Proxy accounts need reauth",
            "",
            "Evidence: 401 Encountered invalidated oauth token for user, failing request",
            "- codex-account-c@example.com",
            "- codex-account-e@example.com",
            "- codex-account-g@example.com",
            "- codex-account-h@example.com",
            "",
            "Action:",
            "Reauth the listed account(s), then check Health alerts.",
        ]))
        self.assertEqual(text.count("Evidence:"), 1)
        self.assertNotIn("Please try signing in again", text)

    def test_reordered_reauth_accounts_have_same_fingerprint(self):
        first_payload = inspection_payload(
            auth_item(name="codex-b@example.com.json", status="unauthorized_401", error="HTTP 401: Your authentication token has been invalidated. Please try signing in again.", auth_index="auth-b"),
            auth_item(name="codex-a@example.com.json", status="unauthorized_401", error="HTTP 401: Encountered invalidated oauth token for user, failing request", auth_index="auth-a"),
        )
        second_payload = inspection_payload(
            auth_item(name="codex-a@example.com.json", status="unauthorized_401", error="HTTP 401: Encountered invalidated oauth token for user, failing request", auth_index="auth-a"),
            auth_item(name="codex-b@example.com.json", status="unauthorized_401", error="HTTP 401: Your authentication token has been invalidated. Please try signing in again.", auth_index="auth-b"),
        )

        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=first_payload):
            first = check_auth_quota_status(refresh_before_check=False, wait_for_refresh=False)[0]
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=second_payload):
            second = check_auth_quota_status(refresh_before_check=False, wait_for_refresh=False)[0]

        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_reauth_alert_dedupes_plain_and_codex_labels_for_same_account(self):
        alert = Alert(
            "auth:quota-inspection-failed",
            "critical",
            "Proxy accounts need reauth",
            "\n".join([
                "- account-c@example.com: 401 Encountered invalidated oauth token for user, failing request",
                "- codex-account-c@example.com: 401 Encountered invalidated oauth token for user, failing request",
            ]),
            "joshua",
        )

        text = build_alert_message(alert)

        self.assertEqual(text, "\n".join([
            "[CRITICAL] Proxy accounts need reauth",
            "",
            "Evidence: 401 Encountered invalidated oauth token for user, failing request",
            "- codex-account-c@example.com",
            "",
            "Action:",
            "Reauth the listed account(s), then check Health alerts.",
        ]))
        self.assertNotIn("- account-c@example.com", text)

    def test_reauth_alert_prefers_codex_email_when_plain_and_codex_labels_exist(self):
        item = auth_item(
            name="account-c@example.com",
            status="unauthorized_401",
            error="HTTP 401: Encountered invalidated oauth token for user, failing request",
            auth_index="auth-joshua",
        )
        item["file_name"] = "codex-account-c@example.com.json"
        payload = inspection_payload(item)

        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts = check_auth_quota_status(refresh_before_check=False, wait_for_refresh=False)

        text = build_alert_message(alerts[0])
        self.assertEqual(text, "\n".join([
            "[CRITICAL] Proxy accounts need reauth",
            "",
            "Evidence: 401 Encountered invalidated oauth token for user, failing request",
            "- codex-account-c@example.com",
            "",
            "Action:",
            "Reauth the listed account(s), then check Health alerts.",
        ]))
        self.assertNotIn("- account-c@example.com", text)

    def test_reauth_alert_falls_back_to_short_hash_without_safe_label(self):
        identity_key = auth_index_key("opaque-auth-index")
        alert = Alert(
            "auth:quota-inspection-failed",
            "critical",
            "Proxy accounts need reauth",
            f"- hash {identity_key}: unauthorized_401 Your authentication token has been invalidated. Please try signing in again.",
            identity_key,
        )

        text = build_alert_message(alert)

        self.assertIn("Evidence: 401 Encountered invalidated oauth token for user, failing request", text)
        self.assertIn(f"- hash {identity_key}", text)
        self.assertNotIn(f"- hash {identity_key}:", text)
        self.assertNotIn("- Account ", text)
        self.assertNotIn("Impact:", text)

    def test_disabled_quota_cache_limit_reached_is_not_reauth(self):
        def fake_request(path, method="GET", payload=None, cookie=None):
            if path.startswith("usage/identities/page"):
                return 200, {"items": [{"auth_index": "disabled-limit", "type": "codex", "disabled": True}]}, ""
            if path == "quota/cache":
                return 200, {"items": [{"auth_index": "disabled-limit", "status": "failed", "error": "limit_reached quota exhausted"}]}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=inspection_payload_with_total([], total=0)), \
             mock.patch("telegram_alerts.health.usage_keeper_session_cookie", return_value="session=abc"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            alerts, observation = health.check_auth_quota_status_with_observation(refresh_before_check=False, wait_for_refresh=False)

        self.assertEqual(alerts, [])
        self.assertEqual(observation["failed_identity_keys"], [])
        self.assertIn(auth_index_key("disabled-limit"), observation["healthy_identity_keys"])

    def test_reauth_alert_redacts_token_key_value_error_details(self):
        error = "HTTP 401: compact unauthorized token=token-secret access_token=access-secret refresh_token=refresh-secret"
        payload = inspection_payload(auth_item(error=error))
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts = check_auth_quota_status(refresh_before_check=True, wait_for_refresh=True)

        self.assertEqual(len(alerts), 1)
        body = alerts[0].body
        self.assertIn("401", body)
        self.assertIn("compact unauthorized", body)
        self.assertNotIn("token-secret", body)
        self.assertNotIn("access-secret", body)
        self.assertNotIn("refresh-secret", body)
        self.assertNotIn("token=", body)
        self.assertNotIn("access_token=", body)
        self.assertNotIn("refresh_token=", body)

    def test_reauth_alert_rejects_secret_like_non_email_labels(self):
        item = auth_item(name="opaque-auth-file.json", error="HTTP 401: unauthorized")
        item.update({
            "file_name": "opaque-auth-file.json",
            "alias": "access_token=aliasvalue",
            "label": "refresh_token=refreshvalue",
            "account": "Bearer bearervalue",
            "username": "access_token=alias-secret",
            "email": "",
            "account_email": "",
            "user_email": "",
        })
        payload = inspection_payload(item)
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts = check_auth_quota_status(refresh_before_check=True, wait_for_refresh=True)

        self.assertEqual(len(alerts), 1)
        body = alerts[0].body
        for forbidden in (
            "access_token=aliasvalue",
            "refresh_token=refreshvalue",
            "Bearer bearervalue",
            "access_token=alias-secret",
            "aliasvalue",
            "refreshvalue",
            "bearervalue",
            "alias-secret",
        ):
            self.assertNotIn(forbidden, body)
        self.assertNotIn("account access_token", body)
        self.assertNotIn("account refresh_token", body)
        self.assertNotIn("account Bearer", body)

    def test_reauth_alert_uses_non_email_alias_before_filename_fallback(self):
        item = auth_item(name="opaque-auth-file.json")
        item.update({"alias": "work-account", "email": "", "account_email": "", "user_email": ""})
        payload = inspection_payload(item)
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts = check_auth_quota_status(refresh_before_check=True, wait_for_refresh=True)

        self.assertEqual(len(alerts), 1)
        body = alerts[0].body
        self.assertIn("- work-account:", body)
        self.assertNotIn("- Account ", body)
        self.assertNotIn("Account ending", body)
        self.assertNotIn("opaque-auth-file.json", body)

    def test_reauth_alert_evidence_masks_secret_like_account_labels(self):
        secret_label = "sk-test12345678901234567890"
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=inspection_payload(auth_item(name=secret_label))):
            alerts = check_auth_quota_status()

        self.assertEqual(len(alerts), 1)
        self.assertNotIn(secret_label, alerts[0].body)
        self.assertRegex(alerts[0].body, r"- hash [0-9a-f]{16}:")
        self.assertNotIn("- Account ", alerts[0].body)
        self.assertNotIn("unauthorized_401", alerts[0].body)

    def test_reauth_alert_observation_uses_hashed_failed_identity(self):
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=inspection_payload(auth_item(name="alice", status="unauthorized_401"))):
            alerts, observation = health.check_auth_quota_status_with_observation()

        self.assertEqual(len(alerts), 1)
        self.assertTrue(observation["complete"])
        self.assertEqual(len(observation["failed_identity_keys"]), 1)
        self.assertNotIn("alice", repr(observation["failed_identity_keys"]))
        self.assertEqual(observation["healthy_identity_keys"], [])

    def test_auth_quota_observation_marks_normal_account_healthy(self):
        payload = inspection_payload(auth_item(name="alice", status="normal", auth_index="auth-1"))

        observation = health.auth_quota_observation_from_payload(payload)

        self.assertTrue(observation["complete"])
        self.assertEqual(len(observation["observed_identity_keys"]), 1)
        self.assertEqual(observation["observed_identity_keys"], observation["healthy_identity_keys"])
        self.assertEqual(observation["failed_identity_keys"], [])

    def test_completed_false_full_results_payload_is_complete_and_available(self):
        rows = [
            auth_item(name=f"normal-{idx}", status="normal", auth_index=f"auth-{idx}")
            for idx in range(7)
        ] + [
            auth_item(name=f"limited-{idx}", status="limit_reached", error="quota reached", auth_index=f"limit-{idx}")
            for idx in range(3)
        ]
        payload = inspection_payload_with_total(rows, running=False, completed=False, total=10)

        observation = health.auth_quota_observation_from_payload(payload)
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts, checked_observation = health.check_auth_quota_status_with_observation()

        self.assertTrue(observation["complete"])
        self.assertEqual(observation["reason"], "")
        self.assertEqual(len(observation["observed_identity_keys"]), 10)
        self.assertEqual(observation["observed_identity_keys"], observation["healthy_identity_keys"])
        self.assertEqual(observation["failed_identity_keys"], [])
        self.assertEqual(checked_observation, observation)
        self.assertNotIn("auth:quota-inspection-unavailable", [alert.alert_id for alert in alerts])
        self.assertNotIn("auth:quota-inspection-failed", [alert.alert_id for alert in alerts])

    def test_completed_false_short_results_payload_is_incomplete(self):
        rows = [
            auth_item(name=f"normal-{idx}", status="normal", auth_index=f"auth-{idx}")
            for idx in range(7)
        ]
        payload = inspection_payload_with_total(rows, running=False, completed=False, total=10)

        observation = health.auth_quota_observation_from_payload(payload)
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts, checked_observation = health.check_auth_quota_status_with_observation()

        self.assertFalse(observation["complete"])
        self.assertEqual(observation["reason"], "count-mismatch")
        self.assertEqual(checked_observation, observation)
        self.assertIn("auth:quota-inspection-unavailable", [alert.alert_id for alert in alerts])

    def test_limit_reached_status_does_not_create_reauth_alert(self):
        payload = inspection_payload_with_total([
            auth_item(name="limited", status="limit_reached", error="quota reached", auth_index="auth-limited"),
        ], running=False, completed=False, total=1)

        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts, observation = health.check_auth_quota_status_with_observation()

        self.assertTrue(observation["complete"])
        self.assertEqual(observation["observed_identity_keys"], observation["healthy_identity_keys"])
        self.assertEqual(observation["failed_identity_keys"], [])
        self.assertNotIn("auth:quota-inspection-failed", [alert.alert_id for alert in alerts])
        self.assertEqual(alerts, [])

    def test_auth_quota_observation_marks_malformed_result_row_incomplete(self):
        payload = {
            "running": False,
            "total": 2,
            "results": [auth_item(name="alice", status="normal", auth_index="auth-1"), "not-a-row"],
        }

        observation = health.auth_quota_observation_from_payload(payload)

        self.assertFalse(observation["complete"])
        self.assertEqual(observation["reason"], "malformed-results")
        self.assertEqual(observation["healthy_identity_keys"], [])

    def test_auth_quota_observation_marks_partial_payload_incomplete(self):
        payload = {
            "running": False,
            "partial": True,
            "results": [auth_item(name="alice", status="normal", auth_index="auth-1")],
        }

        observation = health.auth_quota_observation_from_payload(payload)

        self.assertFalse(observation["complete"])
        self.assertEqual(observation["reason"], "partial")
        self.assertEqual(observation["healthy_identity_keys"], [])

    def test_auth_quota_observation_marks_count_mismatch_incomplete(self):
        payload = {
            "running": False,
            "total_count": 2,
            "results": [auth_item(name="alice", status="normal", auth_index="auth-1")],
        }

        observation = health.auth_quota_observation_from_payload(payload)

        self.assertFalse(observation["complete"])
        self.assertEqual(observation["reason"], "count-mismatch")

    def test_auth_quota_observation_does_not_expose_secret_like_identity(self):
        secret_label = "sk-test12345678901234567890"
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=inspection_payload(auth_item(name=secret_label, auth_index=secret_label))):
            alerts, observation = health.check_auth_quota_status_with_observation()

        serialized = repr(observation)
        self.assertNotIn(secret_label, serialized)
        self.assertEqual(len(observation["failed_identity_keys"]), 1)
        self.assertIn("***", list(observation["failed_labels"].values())[0])
        self.assertEqual(alerts[0].alert_id, "auth:quota-inspection-failed")

    def test_quota_disabled_status_does_not_create_reauth_alert(self):
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=inspection_payload(auth_item(status="disabled_by_quota", error="quota limit"))):
            alerts = check_auth_quota_status()

        self.assertEqual(alerts, [])

    def test_transient_inspection_error_does_not_create_reauth_alert(self):
        with mock.patch("telegram_alerts.health.quota_inspection_payload", side_effect=RuntimeError("temporary inspection timeout")):
            alerts = check_auth_quota_status()

        self.assertNotIn("auth:quota-inspection-failed", [alert.alert_id for alert in alerts])

    def test_single_failed_observation_that_clears_sends_no_alert_or_recovery(self):
        state = {}
        alert = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice:unauthorized_401")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state)
            handlers.process_alerts({}, state)

        self.assertEqual(sent, [])
        self.assertEqual(state.get("active"), {})

    def test_two_consecutive_failed_observations_send_reauth_alert(self):
        state = {}
        alert = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice:unauthorized_401")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state)
            handlers.process_alerts({alert.alert_id: alert}, state)

        self.assertEqual(len(sent), 1)
        self.assertIn("Proxy accounts need reauth", sent[0])
        self.assertIn("alice", sent[0])
        self.assertIn("unauthorized_401", sent[0])
        self.assertEqual(state.get("active", {}).get(alert.alert_id, {}).get("last_sent"), 115)

    def test_repeated_identical_reauth_observations_do_not_resend_critical(self):
        state = {}
        alert = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice:unauthorized_401")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130, 145]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))

        self.assertEqual(len(sent), 1)
        self.assertIn("Proxy accounts need reauth", sent[0])

    def test_reauth_delivery_history_suppresses_duplicate_when_active_state_is_missing(self):
        state = {
            "alert_delivery_history": {
                "auth:quota-inspection-failed": {
                    "fingerprint": "alice:unauthorized_401",
                    "last_sent": 100,
                }
            }
        }
        alert = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice:unauthorized_401")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[200, 215]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))

        self.assertEqual(sent, [])
        active = state.get("active", {}).get(alert.alert_id, {})
        self.assertEqual(active.get("last_sent"), 100)
        self.assertEqual(active.get("fingerprint"), "alice:unauthorized_401")

    def test_reauth_delivery_history_suppresses_duplicate_when_identity_hash_changes(self):
        state = {
            "alert_delivery_history": {
                "auth:quota-inspection-failed": {
                    "fingerprint": "old-hash:first",
                    "last_sent": 100,
                    "affected_signature": ["email:account-f@example.com"],
                }
            }
        }
        alert = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- codex-account-f@example.com: token_revoked", "new-hash:changed")
        observation = auth_observation(failed=["new-hash"])
        observation["failed_labels"] = {"new-hash": "codex-account-f@example.com"}
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[200, 215]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=observation)
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=observation)

        self.assertEqual(sent, [])
        active = state.get("active", {}).get(alert.alert_id, {})
        self.assertEqual(active.get("last_sent"), 100)
        self.assertEqual(active.get("affected_signature"), ["email:account-f@example.com"])

    def test_equivalent_reauth_evidence_change_does_not_resend_active_incident(self):
        state = {}
        first_payload = inspection_payload(
            auth_item(name="codex-a@example.com.json", status="unauthorized_401", error="HTTP 401: Encountered invalidated oauth token for user, failing request", auth_index="auth-a"),
            auth_item(name="codex-b@example.com.json", status="unauthorized_401", error="HTTP 401: Your authentication token has been invalidated. Please try signing in again.", auth_index="auth-b"),
        )
        second_payload = inspection_payload(
            auth_item(name="codex-b@example.com.json", status="unauthorized_401", error="HTTP 401: Encountered invalidated oauth token for user, failing request", auth_index="auth-b"),
            auth_item(name="codex-a@example.com.json", status="unauthorized_401", error="HTTP 401: Your authentication token has been invalidated. Please try signing in again.", auth_index="auth-a"),
        )
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=first_payload):
            first = check_auth_quota_status(refresh_before_check=False, wait_for_refresh=False)[0]
            _, first_observation = health.check_auth_quota_status_with_observation(refresh_before_check=False, wait_for_refresh=False)
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=second_payload):
            second = check_auth_quota_status(refresh_before_check=False, wait_for_refresh=False)[0]
            _, second_observation = health.check_auth_quota_status_with_observation(refresh_before_check=False, wait_for_refresh=False)
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({first.alert_id: first}, state, auth_quota_observation=first_observation)
            handlers.process_alerts({first.alert_id: first}, state, auth_quota_observation=first_observation)
            handlers.process_alerts({second.alert_id: second}, state, auth_quota_observation=second_observation)

        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(len(sent), 1)

    def test_reauth_changed_affected_account_set_resends_while_active(self):
        state = {}
        first = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice")
        changed = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401\n- bob: unauthorized_401", "alice-bob")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({first.alert_id: first}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({first.alert_id: first}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({changed.alert_id: changed}, state, auth_quota_observation=auth_observation(failed=["acct-alice", "acct-bob"]))

        self.assertEqual(len(sent), 2)
        self.assertIn("alice", sent[0])
        self.assertIn("bob", sent[1])

    def test_reauth_same_affected_account_set_does_not_resend_when_fingerprint_changes(self):
        state = {}
        first = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice:first")
        changed = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: token_revoked", "alice:changed")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({first.alert_id: first}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({first.alert_id: first}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({changed.alert_id: changed}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))

        self.assertEqual(len(sent), 1)
        active = state.get("active", {}).get(first.alert_id, {})
        self.assertEqual(active.get("fingerprint"), "alice:changed")

    def test_reauth_same_label_does_not_resend_when_identity_hash_changes(self):
        state = {}
        first = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- codex-account-f@example.com: unauthorized_401", "old-hash:first")
        changed = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- codex-account-f@example.com: token_revoked", "new-hash:changed")
        first_observation = auth_observation(failed=["old-hash"])
        first_observation["failed_labels"] = {"old-hash": "codex-account-f@example.com"}
        changed_observation = auth_observation(failed=["new-hash"])
        changed_observation["failed_labels"] = {"new-hash": "codex-account-f@example.com"}
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({first.alert_id: first}, state, auth_quota_observation=first_observation)
            handlers.process_alerts({first.alert_id: first}, state, auth_quota_observation=first_observation)
            handlers.process_alerts({changed.alert_id: changed}, state, auth_quota_observation=changed_observation)

        self.assertEqual(len(sent), 1)
        active = state.get("active", {}).get(first.alert_id, {})
        self.assertEqual(active.get("affected_identity_keys"), ["new-hash"])
        self.assertEqual(active.get("affected_signature"), ["email:account-f@example.com"])

    def test_single_inspection_unavailable_observation_does_not_send_alert(self):
        state = {}
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "temporary timeout", "timeout")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state)
            handlers.process_alerts({}, state)

        self.assertEqual(sent, [])
        self.assertEqual(state.get("active"), {})

    def test_repeated_inspection_unavailable_under_warn_window_does_not_send_warning(self):
        state = {}
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: count-mismatch", "unavailable:malformed-payload")
        sent = []

        with mock.patch.object(handlers, "AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS", 300, create=True), \
             mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 250, 399]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            for _ in range(4):
                handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))

        self.assertEqual(sent, [])
        self.assertNotIn("auth:quota-inspection-unavailable", state.get("active", {}))
        self.assertIn("auth:quota-inspection-unavailable", state.get("alert_candidates", {}))

    def test_inspection_unavailable_sustained_for_warn_window_sends_one_warning(self):
        state = {}
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: count-mismatch", "unavailable:malformed-payload")
        sent = []

        with mock.patch.object(handlers, "AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS", 300, create=True), \
             mock.patch.object(handlers, "now_ts", side_effect=[100, 250, 400, 415]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))

        self.assertEqual(len(sent), 1)
        self.assertIn("Proxy Auth Inspection Unavailable", sent[0])
        self.assertIn("auth:quota-inspection-unavailable", state.get("active", {}))

    def test_repeated_sustained_inspection_unavailable_does_not_duplicate_warning(self):
        state = {}
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: count-mismatch", "unavailable:malformed-payload")
        sent = []

        with mock.patch.object(handlers, "AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS", 300, create=True), \
             mock.patch.object(handlers, "now_ts", side_effect=[100, 400, 415, 430]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))

        self.assertEqual(len(sent), 1)

    def test_active_inspection_unavailable_complete_under_recovery_window_does_not_send_ok(self):
        state = {}
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: count-mismatch", "unavailable:malformed-payload")
        sent = []

        with mock.patch.object(handlers, "AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS", 300, create=True), \
             mock.patch.object(handlers, "AUTH_INSPECTION_UNAVAILABLE_RECOVER_AFTER_SECONDS", 300, create=True), \
             mock.patch.object(handlers, "now_ts", side_effect=[100, 400, 430, 550]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-a"]))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-a"]))

        self.assertEqual(len(sent), 1)
        self.assertNotIn("[OK]", "\n".join(sent))
        self.assertIn("auth:quota-inspection-unavailable", state.get("active", {}))

    def test_active_inspection_unavailable_complete_for_recovery_window_sends_one_ok(self):
        state = {}
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: count-mismatch", "unavailable:malformed-payload")
        sent = []

        with mock.patch.object(handlers, "AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS", 300, create=True), \
             mock.patch.object(handlers, "AUTH_INSPECTION_UNAVAILABLE_RECOVER_AFTER_SECONDS", 300, create=True), \
             mock.patch.object(handlers, "now_ts", side_effect=[100, 400, 430, 730]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-a"]))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-a"]))

        self.assertEqual(len(sent), 2)
        self.assertIn("Proxy Auth Inspection Unavailable", sent[0])
        self.assertIn("[OK]", sent[1])
        self.assertNotIn("auth:quota-inspection-unavailable", state.get("active", {}))

    def test_inspection_unavailable_recurrence_during_recovery_window_resets_ok_timer(self):
        state = {}
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: count-mismatch", "unavailable:malformed-payload")
        sent = []

        with mock.patch.object(handlers, "AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS", 300, create=True), \
             mock.patch.object(handlers, "AUTH_INSPECTION_UNAVAILABLE_RECOVER_AFTER_SECONDS", 300, create=True), \
             mock.patch.object(handlers, "now_ts", side_effect=[100, 400, 430, 500, 800]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-a"]))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="count-mismatch"))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-a"]))

        self.assertEqual(len(sent), 1)
        self.assertNotIn("[OK]", "\n".join(sent))
        self.assertIn("auth:quota-inspection-unavailable", state.get("active", {}))

    def test_reauth_recovery_does_not_send_ok_when_previous_account_is_omitted(self):
        state = {}
        alert = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice:unauthorized_401")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130, 145]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-bob"]))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-bob"]))

        self.assertEqual(len(sent), 1)
        self.assertIn("Proxy accounts need reauth", sent[0])
        self.assertIn("auth:quota-inspection-failed", state.get("active", {}))

    def test_reauth_recovery_does_not_send_ok_when_observation_incomplete(self):
        state = {}
        alert = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice:unauthorized_401")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(complete=False, reason="results-none"))

        self.assertEqual(len(sent), 1)
        self.assertIn("auth:quota-inspection-failed", state.get("active", {}))

    def test_reauth_recovery_does_not_send_ok_when_unavailable_alert_present(self):
        state = {}
        reauth = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice:unauthorized_401")
        unavailable = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection refresh is still running", "unavailable:refresh-running")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130, 145]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({reauth.alert_id: reauth}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({reauth.alert_id: reauth}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({unavailable.alert_id: unavailable}, state, auth_quota_observation=auth_observation(complete=False, reason="refresh-running"))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-alice"]))

        self.assertEqual(len(sent), 1)
        self.assertIn("Proxy accounts need reauth", sent[0])
        self.assertNotIn("Proxy accounts reauth", "\n".join(sent))
        self.assertIn("auth:quota-inspection-failed", state.get("active", {}))

    def test_reauth_recovery_requires_two_complete_healthy_observations(self):
        state = {}
        alert = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice:unauthorized_401")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130, 145]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-alice"]))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-alice"]))

        self.assertEqual(len(sent), 2)
        self.assertIn("Proxy accounts need reauth", sent[0])
        self.assertIn("Proxy accounts reauth", sent[1])
        self.assertNotIn("auth:quota-inspection-failed", state.get("active", {}))

    def test_reauth_recovery_healthy_count_resets_after_incomplete_observation(self):
        state = {}
        alert = Alert("auth:quota-inspection-failed", "critical", "Proxy accounts need reauth", "- alice: unauthorized_401", "alice:unauthorized_401")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130, 145, 160, 175]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(failed=["acct-alice"]))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-alice"]))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(complete=False, reason="refresh-running"))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-alice"]))
            handlers.process_alerts({}, state, auth_quota_observation=auth_observation(healthy=["acct-alice"]))

        self.assertEqual(len(sent), 2)
        self.assertIn("Proxy accounts need reauth", sent[0])
        self.assertIn("Proxy accounts reauth", sent[1])

    def test_auto_alert_message_title_lines_are_standardized(self):
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
        for alert, expected in cases:
            with self.subTest(alert_id=alert.alert_id):
                text = build_alert_message(alert)
                self.assertEqual(text.splitlines()[0], expected)
                if alert.alert_id in {"auth:quota-inspection-failed", "capacity:gpt-pool-5h-low"}:
                    self.assertNotIn("Impact:", text)
                else:
                    self.assertIn("Impact:", text)
                self.assertIn("Evidence:", text)
                self.assertIn("Action:", text)
                self.assertNotIn("---", text)

    def test_resolved_alert_message_title_lines_are_standardized(self):
        self.assertEqual(
            build_resolved_message("capacity:gpt-pool-5h-low", {"title": "GPT pool 5h capacity low", "severity": "warning"}).splitlines()[0],
            "[OK] GPT Pool 5h Capacity",
        )
        self.assertEqual(
            build_resolved_message("auth:quota-inspection-unavailable", {"title": "Proxy auth inspection unavailable", "severity": "warning"}).splitlines()[0],
            "[OK] Proxy Auth Inspection Unavailable",
        )

    def test_gpt_low_capacity_recovery_copy_is_specific(self):
        text = build_resolved_message("capacity:gpt-pool-5h-low", {"title": "GPT pool 5h capacity low", "severity": "warning"})

        self.assertEqual(
            text,
            "[OK] GPT Pool 5h Capacity\n\n"
            "Recovered: 5h GPT pool margin is back above the recovery threshold.",
        )
        self.assertNotIn("---", text)

    def test_reauth_recovery_copy_is_specific(self):
        text = build_resolved_message("auth:quota-inspection-failed", {
            "title": "Proxy accounts need reauth",
            "severity": "critical",
            "affected_labels": {
                "acct-bach": "codex-account-a@example.com",
                "acct-nothing": "codex-account-d@example.com",
            },
        })

        self.assertEqual(
            text,
            "[OK] Proxy accounts reauth\n\n"
            "Recovered:\n"
            "- codex-account-a@example.com\n"
            "- codex-account-d@example.com\n\n"
            "Evidence: latest inspection is healthy.",
        )
        self.assertNotIn("codex-account-a@example.com:", text)
        self.assertNotIn("codex-account-d@example.com:", text)
        self.assertNotIn("---", text)

    def test_incident_lifecycle_without_ack_sends_once_recovers_and_recurs(self):
        state = {}
        alert = Alert("service:cliproxy", "critical", "cliproxy is not reachable", "connect failed", "unreachable")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130, 145, 160]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state)
            handlers.process_alerts({alert.alert_id: alert}, state)
            handlers.process_alerts({}, state)
            handlers.process_alerts({}, state)
            handlers.process_alerts({alert.alert_id: alert}, state)

        self.assertEqual(len(sent), 3)
        self.assertIn("cliproxy is not reachable", sent[0])
        self.assertIn("[OK]", sent[1])
        self.assertIn("cliproxy is not reachable", sent[2])

    def test_incident_changed_fingerprint_notifies_while_active(self):
        state = {}
        first = Alert("service:cliproxy", "critical", "cliproxy is not reachable", "connect failed", "unreachable")
        changed = Alert("service:cliproxy", "critical", "cliproxy is not reachable", "HTTP 500", "http:500")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({first.alert_id: first}, state)
            handlers.process_alerts({changed.alert_id: changed}, state)

        self.assertEqual(len(sent), 2)
        self.assertIn("connect failed", sent[0])
        self.assertIn("HTTP 500", sent[1])

    def test_send_auto_alert_ignores_removed_silence_state(self):
        state = {"silenced_until_by_chat": {"chat-1": 999999, "chat-2": 999999}}
        sent = []

        with mock.patch.object(handlers, "alert_chat_ids", return_value=["chat-1", "chat-2"]), \
             mock.patch.object(handlers, "send_telegram", side_effect=lambda text, dry_run=False, chat_id=None: sent.append(chat_id) or True):
            sent_count, silenced_count = handlers.send_auto_alert("test alert", state)

        self.assertEqual(sent_count, 2)
        self.assertEqual(silenced_count, 0)
        self.assertEqual(sent, ["chat-1", "chat-2"])

    def test_ack_state_no_longer_suppresses_incidents(self):
        state = {"acked": {"service:cliproxy": "unreachable"}}
        alert = Alert("service:cliproxy", "critical", "cliproxy is not reachable", "connect failed", "unreachable")
        sent = []

        with mock.patch.object(handlers, "now_ts", return_value=100), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state)

        self.assertEqual(len(sent), 1)
        self.assertIn("cliproxy is not reachable", sent[0])

    def test_quota_inspection_unavailable_fingerprint_is_normalized_for_equivalent_timeouts(self):
        first = quota_inspection_unavailable_alert(TimeoutError("timed out after 8 seconds"))
        second = quota_inspection_unavailable_alert(TimeoutError("request timed out after 10 seconds"))

        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertIn("timed out after 8 seconds", first.body)

    def test_quota_inspection_unavailable_distinct_categories_have_distinct_fingerprints(self):
        timeout = quota_inspection_unavailable_alert(TimeoutError("timed out"))
        running = quota_inspection_unavailable_alert("quota inspection refresh is still running")
        missing_password = quota_inspection_unavailable_alert(RuntimeError("USAGE_KEEPER_PASSWORD is not configured for quota inspection"))

        self.assertNotEqual(timeout.fingerprint, running.fingerprint)
        self.assertNotEqual(timeout.fingerprint, missing_password.fingerprint)
        self.assertNotEqual(running.fingerprint, missing_password.fingerprint)

    def test_reauth_fingerprint_changes_with_affected_account_or_evidence(self):
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=inspection_payload(auth_item(name="alice", status="unauthorized_401"))):
            first = check_auth_quota_status()[0]
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=inspection_payload(auth_item(name="bob", status="unauthorized_401"))):
            second = check_auth_quota_status()[0]
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=inspection_payload(auth_item(name="alice", status="token_revoked", error="token revoked"))):
            third = check_auth_quota_status()[0]

        self.assertNotEqual(first.fingerprint, second.fingerprint)
        self.assertNotEqual(first.fingerprint, third.fingerprint)

    def test_collect_alerts_treats_none_http_results_as_empty_boundary(self):
        with mock.patch("telegram_alerts.health.check_http_services_detailed", return_value=None), \
             mock.patch("telegram_alerts.health.check_enforcer", return_value=[]), \
             mock.patch("telegram_alerts.health.check_storage", return_value=[]), \
             mock.patch("telegram_alerts.health.check_auth_quota_status", return_value=[]):
            alerts = collect_alerts(None)

        self.assertEqual(alerts, {})

    def test_quota_inspection_payload_refresh_treats_none_results_as_empty_when_fallback_has_no_rows(self):
        calls = []

        def fake_request(path, method="GET", payload=None, cookie=None):
            calls.append((path, method, payload))
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path == "quota/inspection":
                return 200, {"running": False, "results": None}, ""
            if path.startswith("usage/identities/page"):
                return 200, {"items": []}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request):
            payload = quota_inspection_payload(refresh_before_check=True, wait_for_refresh=False)

        self.assertEqual(payload["results"], None)
        self.assertEqual([call[0] for call in calls], [
            "auth/login",
            "quota/inspection",
            "usage/identities/page?auth_type=1&active_only=false&page=1&page_size=500",
        ])
        self.assertNotIn("quota/refresh", [call[0] for call in calls])

    def test_auth_snapshot_options_refreshes_once_per_cooldown(self):
        state = {}

        with mock.patch.object(app, "AUTH_QUOTA_REFRESH_COOLDOWN_SECONDS", 300, create=True), \
             mock.patch.object(app, "AUTH_QUOTA_INSPECTION_WAIT_SECONDS", 60, create=True):
            first = app.auth_snapshot_options(state, ts=100)
            second = app.auth_snapshot_options(state, ts=115)
            third = app.auth_snapshot_options(state, ts=401)

        self.assertTrue(first["auth_refresh_before_check"])
        self.assertTrue(first["auth_wait_for_refresh"])
        self.assertEqual(first["auth_wait_seconds"], 60)
        self.assertEqual(state["auth_quota_inspection"]["next_refresh_at"], 701)
        self.assertFalse(second["auth_refresh_before_check"])
        self.assertFalse(second["auth_wait_for_refresh"])
        self.assertTrue(third["auth_refresh_before_check"])
        self.assertEqual(third["auth_inspection_state"]["next_refresh_at"], 701)

    def test_quota_inspection_payload_waits_until_strictly_complete(self):
        calls = []
        partial = [auth_item(name=f"acct-{index}", status="normal", auth_index=f"auth-{index}") for index in range(6)]
        complete = [auth_item(name=f"acct-{index}", status="normal", auth_index=f"auth-{index}") for index in range(10)]
        inspection_payloads = [
            {"running": False, "total": 10, "results": complete},
            {"running": False, "total": 10, "results": partial},
            {"running": False, "total": 10, "results": complete},
        ]

        def fake_request(path, method="GET", payload=None, cookie=None):
            calls.append((path, method, payload))
            if path == "auth/login":
                return 200, {}, "session=abc; Path=/"
            if path == "quota/inspection":
                return 200, inspection_payloads.pop(0), ""
            if path == "quota/refresh":
                return 200, {"ok": True}, ""
            raise AssertionError(f"unexpected request {path}")

        with mock.patch("telegram_alerts.health.USAGE_KEEPER_PASSWORD", "password"), \
             mock.patch("telegram_alerts.health.usage_keeper_request", side_effect=fake_request), \
             mock.patch("telegram_alerts.health.time.sleep"):
            payload = quota_inspection_payload(refresh_before_check=True, wait_for_refresh=True)

        self.assertEqual(len(payload["results"]), 10)
        self.assertEqual([call[0] for call in calls], ["auth/login", "quota/inspection", "quota/refresh", "quota/inspection", "quota/inspection"])

    def test_check_auth_quota_status_treats_none_results_as_unavailable(self):
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value={"running": False, "results": None}):
            alerts, observation = health.check_auth_quota_status_with_observation()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_id, "auth:quota-inspection-unavailable")
        self.assertEqual(alerts[0].fingerprint, "unavailable:malformed-payload")
        self.assertFalse(observation["complete"])
        self.assertEqual(observation["reason"], "results-none")

    def test_check_auth_quota_status_running_with_none_results_returns_unavailable(self):
        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value={"running": True, "results": None}):
            alerts, observation = health.check_auth_quota_status_with_observation()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_id, "auth:quota-inspection-unavailable")
        self.assertEqual(alerts[0].fingerprint, "unavailable:refresh-running")
        self.assertFalse(observation["complete"])
        self.assertEqual(observation["reason"], "refresh-running")

    def test_incomplete_auth_inspection_does_not_create_reauth_alert(self):
        payload = inspection_payload_with_total(
            [auth_item(name="alice", status="unauthorized_401")],
            total=2,
        )

        with mock.patch("telegram_alerts.health.quota_inspection_payload", return_value=payload):
            alerts, observation = health.check_auth_quota_status_with_observation()

        self.assertFalse(observation["complete"])
        self.assertEqual(observation["reason"], "count-mismatch")
        self.assertIn("auth:quota-inspection-unavailable", {alert.alert_id for alert in alerts})
        self.assertNotIn("auth:quota-inspection-failed", {alert.alert_id for alert in alerts})

    def test_collect_alerts_reports_unavailable_when_auth_results_are_none(self):
        with mock.patch("telegram_alerts.health.check_enforcer", return_value=[]), \
             mock.patch("telegram_alerts.health.check_storage", return_value=[]), \
             mock.patch("telegram_alerts.health.quota_inspection_payload", return_value={"running": False, "results": None}):
            alerts, observation = health.collect_alerts_with_auth_observation([])

        self.assertIn("auth:quota-inspection-unavailable", alerts)
        self.assertFalse(observation["complete"])
        self.assertEqual(observation["reason"], "results-none")

    def test_build_snapshot_includes_auth_quota_observation(self):
        observation = auth_observation(healthy=["acct-alice"])
        quota_context = {
            "tz_name": "Asia/Ho_Chi_Minh",
            "items": [],
            "disabled": set(),
            "config_keys": set(),
            "alias_by_key": {},
            "usage": {},
        }

        with mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({}, observation)), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value=quota_context), \
             mock.patch("telegram_alerts.snapshot.gpt_pool_capacity_snapshot", return_value=health.empty_gpt_pool_capacity()), \
             mock.patch("telegram_alerts.snapshot.usage_rate_estimate", return_value={"tokens_per_hour": 0, "error": ""}):
            built = snapshot_module.build_snapshot()

        self.assertEqual(built["auth_quota_observation"], observation)
        self.assertIn("gpt_pool_5h_observation", built)

    def test_recent_complete_auth_inspection_suppresses_partial_unavailable_alert(self):
        observation = auth_observation(complete=False, reason="count-mismatch")
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: count-mismatch", "unavailable:malformed-payload")
        quota_context = {"tz_name": "Asia/Ho_Chi_Minh", "items": [], "disabled": set(), "config_keys": set(), "alias_by_key": {}, "usage": {}}

        with mock.patch("telegram_alerts.snapshot.now_ts", return_value=1100), \
             mock.patch.object(snapshot_module, "AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS", 900, create=True), \
             mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({alert.alert_id: alert}, observation)), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value=quota_context), \
             mock.patch("telegram_alerts.snapshot.gpt_pool_capacity_snapshot", return_value=health.empty_gpt_pool_capacity()), \
             mock.patch("telegram_alerts.snapshot.usage_rate_estimate", return_value={"tokens_per_hour": 0, "error": ""}):
            built = snapshot_module.build_snapshot(auth_inspection_state={"last_complete_at": 1000})

        self.assertNotIn("auth:quota-inspection-unavailable", built["system_alerts"])
        self.assertFalse(built["auth_quota_observation"]["complete"])
        self.assertEqual(built["auth_quota_observation"]["reason"], "count-mismatch")

    def test_recent_complete_auth_inspection_suppresses_results_none_unavailable_alert(self):
        observation = auth_observation(complete=False, reason="results-none")
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: results-none", "unavailable:malformed-payload")
        quota_context = {"tz_name": "Asia/Ho_Chi_Minh", "items": [], "disabled": set(), "config_keys": set(), "alias_by_key": {}, "usage": {}}

        with mock.patch("telegram_alerts.snapshot.now_ts", return_value=1100), \
             mock.patch.object(snapshot_module, "AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS", 900, create=True), \
             mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({alert.alert_id: alert}, observation)), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value=quota_context), \
             mock.patch("telegram_alerts.snapshot.gpt_pool_capacity_snapshot", return_value=health.empty_gpt_pool_capacity()), \
             mock.patch("telegram_alerts.snapshot.usage_rate_estimate", return_value={"tokens_per_hour": 0, "error": ""}):
            built = snapshot_module.build_snapshot(auth_inspection_state={"last_complete_at": 1000})

        self.assertNotIn("auth:quota-inspection-unavailable", built["system_alerts"])
        self.assertFalse(built["auth_quota_observation"]["complete"])
        self.assertEqual(built["auth_quota_observation"]["reason"], "results-none")

    def test_default_recent_complete_window_covers_restart_warmup_results_none(self):
        observation = auth_observation(complete=False, reason="results-none")
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: results-none", "unavailable:malformed-payload")
        quota_context = {"tz_name": "Asia/Ho_Chi_Minh", "items": [], "disabled": set(), "config_keys": set(), "alias_by_key": {}, "usage": {}}

        with mock.patch("telegram_alerts.snapshot.now_ts", return_value=2200), \
             mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({alert.alert_id: alert}, observation)), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value=quota_context), \
             mock.patch("telegram_alerts.snapshot.gpt_pool_capacity_snapshot", return_value=health.empty_gpt_pool_capacity()), \
             mock.patch("telegram_alerts.snapshot.usage_rate_estimate", return_value={"tokens_per_hour": 0, "error": ""}):
            built = snapshot_module.build_snapshot(auth_inspection_state={"last_complete_at": 1000})

        self.assertNotIn("auth:quota-inspection-unavailable", built["system_alerts"])
        self.assertEqual(built["auth_quota_observation"]["reason"], "results-none")

    def test_process_alerts_single_results_none_observation_does_not_send_or_activate_unavailable(self):
        state = {}
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: results-none", "unavailable:malformed-payload")
        sent = []

        with mock.patch.object(handlers, "now_ts", return_value=100), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="results-none"))

        self.assertEqual(sent, [])
        self.assertNotIn("auth:quota-inspection-unavailable", state.get("active", {}))
        self.assertIn("auth:quota-inspection-unavailable", state.get("alert_candidates", {}))

    def test_process_alerts_sustained_results_none_observations_send_unavailable(self):
        state = {}
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: results-none", "unavailable:malformed-payload")
        sent = []

        with mock.patch.object(handlers, "AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS", 120, create=True), \
             mock.patch.object(handlers, "now_ts", side_effect=[100, 221]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="results-none"))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="results-none"))

        self.assertEqual(len(sent), 1)
        self.assertIn("Proxy Auth Inspection Unavailable", sent[0])
        self.assertIn("auth:quota-inspection-unavailable", state.get("active", {}))

    def test_process_alerts_restart_state_recent_complete_suppresses_results_none_unavailable(self):
        state = {"auth_quota_inspection": {"last_complete_at": 1000}}
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: results-none", "unavailable:malformed-payload")
        sent = []

        with mock.patch.object(handlers, "AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS", 900, create=True), \
             mock.patch.object(handlers, "AUTH_INSPECTION_UNAVAILABLE_WARN_AFTER_SECONDS", 120, create=True), \
             mock.patch.object(handlers, "now_ts", side_effect=[1100, 1250]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="results-none"))
            handlers.process_alerts({alert.alert_id: alert}, state, auth_quota_observation=auth_observation(complete=False, reason="results-none"))

        self.assertEqual(sent, [])
        self.assertNotIn("auth:quota-inspection-unavailable", state.get("active", {}))
        self.assertNotIn("auth:quota-inspection-unavailable", state.get("alert_candidates", {}))

    def test_stale_complete_auth_inspection_allows_unavailable_alert(self):
        observation = auth_observation(complete=False, reason="count-mismatch")
        alert = Alert("auth:quota-inspection-unavailable", "warning", "Proxy auth inspection unavailable", "quota inspection malformed payload: count-mismatch", "unavailable:malformed-payload")
        quota_context = {"tz_name": "Asia/Ho_Chi_Minh", "items": [], "disabled": set(), "config_keys": set(), "alias_by_key": {}, "usage": {}}

        with mock.patch("telegram_alerts.snapshot.now_ts", return_value=2001), \
             mock.patch.object(snapshot_module, "AUTH_QUOTA_INSPECTION_STALE_WARN_SECONDS", 900, create=True), \
             mock.patch("telegram_alerts.snapshot.check_http_services_detailed", return_value=[]), \
             mock.patch("telegram_alerts.snapshot.collect_alerts_with_auth_observation", return_value=({alert.alert_id: alert}, observation)), \
             mock.patch("telegram_alerts.snapshot.load_quota_context", return_value=quota_context), \
             mock.patch("telegram_alerts.snapshot.gpt_pool_capacity_snapshot", return_value=health.empty_gpt_pool_capacity()), \
             mock.patch("telegram_alerts.snapshot.usage_rate_estimate", return_value={"tokens_per_hour": 0, "error": ""}):
            built = snapshot_module.build_snapshot(auth_inspection_state={"last_complete_at": 1000})

        self.assertIn("auth:quota-inspection-unavailable", built["system_alerts"])

    def test_update_auth_inspection_state_stores_only_sanitized_counts_and_keys(self):
        state = {}
        observation = auth_observation(complete=True, healthy=["acct-a"], failed=["acct-b"])
        observation["failed_auth_index_keys"] = ["abcdef1234567890", "raw-auth-secret@example.com", "not-hex"]

        app.update_auth_inspection_state(state, observation, refresh_triggered=True, ts=500)

        stored = state["auth_quota_inspection"]
        self.assertEqual(stored["last_complete_at"], 500)
        self.assertEqual(stored["observed_count"], 2)
        self.assertEqual(stored["healthy_count"], 1)
        self.assertEqual(stored["failed_count"], 1)
        self.assertEqual(stored["failed_identity_keys"], ["acct-b"])
        self.assertEqual(stored["failed_auth_index_keys"], ["abcdef1234567890"])
        self.assertEqual(stored["raw_current_complete"], True)
        self.assertEqual(stored["raw_current_reason"], "")
        self.assertNotIn("sk-", repr(stored))
        self.assertNotIn("Bearer", repr(stored))
        self.assertNotIn("raw-auth-secret@example.com", repr(stored))

    def test_update_auth_inspection_state_records_partial_reason_without_clearing_last_complete(self):
        state = {"auth_quota_inspection": {"last_complete_at": 500, "observed_count": 10}}
        observation = auth_observation(complete=False, reason="results-none")

        app.update_auth_inspection_state(state, observation, refresh_triggered=True, ts=550)

        stored = state["auth_quota_inspection"]
        self.assertEqual(stored["last_complete_at"], 500)
        self.assertEqual(stored["raw_current_complete"], False)
        self.assertEqual(stored["raw_current_reason"], "results-none")

    def test_gpt_low_capacity_single_low_observation_does_not_send_warning(self):
        state = {}
        alert = Alert("capacity:gpt-pool-5h-low", "warning", "GPT pool 5h capacity is low", "- 5h margin: 0.7x", "low-0.5-to-0.8:8")
        sent = []

        with mock.patch.object(handlers, "now_ts", return_value=100), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))

        self.assertEqual(sent, [])
        self.assertNotIn("capacity:gpt-pool-5h-low", state.get("active", {}))

    def test_gpt_low_capacity_two_low_observations_send_one_warning(self):
        state = {}
        alert = Alert("capacity:gpt-pool-5h-low", "warning", "GPT pool 5h capacity is low", "- 5h margin: 0.7x", "low-0.5-to-0.8:8")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))

        self.assertEqual(len(sent), 1)
        self.assertIn("GPT pool 5h capacity low", sent[0])

    def test_gpt_low_capacity_active_margin_below_recovery_threshold_does_not_send_ok(self):
        state = {}
        alert = Alert("capacity:gpt-pool-5h-low", "warning", "GPT pool 5h capacity is low", "- 5h margin: 0.7x", "low-0.5-to-0.8:8")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130, 145]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))
            handlers.process_alerts({}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.85, low=False, recovered=False))
            handlers.process_alerts({}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=1.0, low=False, recovered=False))

        self.assertEqual(len(sent), 1)
        self.assertNotIn("GPT pool 5h capacity OK", "\n".join(sent))
        self.assertIn("capacity:gpt-pool-5h-low", state.get("active", {}))

    def test_gpt_low_capacity_active_incomplete_observation_does_not_send_ok(self):
        state = {}
        alert = Alert("capacity:gpt-pool-5h-low", "warning", "GPT pool 5h capacity is low", "- 5h margin: 0.7x", "low-0.5-to-0.8:8")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))
            handlers.process_alerts({}, state, gpt_pool_5h_observation=gpt_observation(complete=False, reason="incomplete-coverage"))

        self.assertEqual(len(sent), 1)
        self.assertNotIn("GPT pool 5h capacity OK", "\n".join(sent))
        self.assertIn("capacity:gpt-pool-5h-low", state.get("active", {}))

    def test_gpt_low_capacity_recovery_requires_two_complete_recovered_observations(self):
        state = {}
        alert = Alert("capacity:gpt-pool-5h-low", "warning", "GPT pool 5h capacity is low", "- 5h margin: 0.7x", "low-0.5-to-0.8:8")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130, 145]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))
            handlers.process_alerts({}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=1.3, recovered=True))
            handlers.process_alerts({}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=1.3, recovered=True))

        self.assertEqual(len(sent), 2)
        self.assertIn("GPT pool 5h capacity low", sent[0])
        self.assertIn("GPT Pool 5h Capacity", sent[1])
        self.assertNotIn("capacity:gpt-pool-5h-low", state.get("active", {}))

    def test_gpt_low_capacity_recurs_only_after_recovery_and_two_new_lows(self):
        state = {}
        alert = Alert("capacity:gpt-pool-5h-low", "warning", "GPT pool 5h capacity is low", "- 5h margin: 0.7x", "low-0.5-to-0.8:8")
        sent = []

        with mock.patch.object(handlers, "now_ts", side_effect=[100, 115, 130, 145, 160, 175]), \
             mock.patch.object(handlers, "send_auto_alert", side_effect=lambda text, state, dry_run=False: sent.append(text) or (1, 0)), \
             mock.patch.object(handlers, "save_json"):
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))
            handlers.process_alerts({}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=1.3, recovered=True))
            handlers.process_alerts({}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=1.3, recovered=True))
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))
            handlers.process_alerts({alert.alert_id: alert}, state, gpt_pool_5h_observation=gpt_observation(complete=True, margin=0.7, low=True))

        self.assertEqual(len(sent), 3)
        self.assertIn("GPT Pool 5h Capacity", sent[1])
        self.assertIn("GPT pool 5h capacity low", sent[2])

    def test_gpt_low_capacity_small_margin_changes_do_not_change_fingerprint(self):
        pool = {
            "enabled_codex_count": 8,
            "primary": {"checked_count": 8, "left_tokens": 79_000_000.0},
            "secondary": {"checked_count": 8, "left_tokens": 900_000_000.0},
            "error": "",
        }
        first = snapshot_module.gpt_pool_5h_low_capacity_alert(
            {"gpt_pool_capacity": pool},
            {"tokens_per_hour": 20_000_000, "lookback_hours": 3, "error": ""},
        )
        pool["primary"]["left_tokens"] = 78_000_000.0
        second = snapshot_module.gpt_pool_5h_low_capacity_alert(
            {"gpt_pool_capacity": pool},
            {"tokens_per_hour": 20_000_000, "lookback_hours": 3, "error": ""},
        )

        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_alert_snapshot_worker_logs_sanitized_exception_location(self):
        def boom(**kwargs):
            raise TypeError("'NoneType' object is not iterable")

        with app._ALERT_SNAPSHOT_LOCK:
            app._ALERT_SNAPSHOT_JOB["running"] = False
            app._ALERT_SNAPSHOT_JOB["result"] = None

        try:
            with mock.patch("telegram_alerts.app.build_snapshot", side_effect=boom), \
                 mock.patch("telegram_alerts.app.log") as log, \
                 mock.patch("telegram_alerts.app.log_timing"):
                self.assertTrue(app.start_alert_snapshot_job(False, True))
                result = None
                deadline = time.time() + 1
                while time.time() < deadline:
                    result = app.take_alert_snapshot_result()
                    if result is not None:
                        break
                    time.sleep(0.01)

            self.assertIsNotNone(result)
            self.assertIn("not iterable", result["error"])
            log.assert_called()
            logged = "\n".join(str(call.args[0]) for call in log.call_args_list)
            self.assertIn("alert snapshot worker exception TypeError", logged)
            self.assertIn("location=", logged)
            self.assertNotIn("sk-", logged)
        finally:
            with app._ALERT_SNAPSHOT_LOCK:
                app._ALERT_SNAPSHOT_JOB["running"] = False
                app._ALERT_SNAPSHOT_JOB["result"] = None


if __name__ == "__main__":
    unittest.main()
