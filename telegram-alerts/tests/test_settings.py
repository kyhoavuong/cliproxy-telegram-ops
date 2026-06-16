import importlib
import os
import unittest
from unittest import mock

import telegram_alerts.settings as settings_module
import telegram_alerts.utils as utils_module


class SettingsEnvTests(unittest.TestCase):
    def test_capacity_check_fast_cache_seconds_env_override(self):
        original_env = dict(os.environ)
        try:
            with mock.patch.dict(os.environ, {"CAPACITY_CHECK_FAST_CACHE_SECONDS": "7"}, clear=False):
                reloaded = importlib.reload(settings_module)
                self.assertEqual(reloaded.CAPACITY_CHECK_FAST_CACHE_SECONDS, 7)
        finally:
            os.environ.clear()
            os.environ.update(original_env)
            importlib.reload(settings_module)

    def test_allowed_chat_ids_includes_telegram_chat_id(self):
        with mock.patch.object(utils_module, "TELEGRAM_ALLOWED_CHAT_IDS", "100,200"), \
             mock.patch.object(utils_module, "TELEGRAM_CHAT_ID", "300"):
            self.assertEqual(utils_module.allowed_chat_ids(), {"100", "200", "300"})

    def test_is_authorized_requires_chat_and_user_when_both_are_configured(self):
        with mock.patch.object(utils_module, "TELEGRAM_ALLOWED_CHAT_IDS", "chat-1"), \
             mock.patch.object(utils_module, "TELEGRAM_CHAT_ID", ""), \
             mock.patch.object(utils_module, "TELEGRAM_ALLOWED_USER_IDS", "user-1"):
            self.assertTrue(utils_module.is_authorized("chat-1", "user-1"))
            self.assertFalse(utils_module.is_authorized("chat-2", "user-1"))
            self.assertFalse(utils_module.is_authorized("chat-1", "user-2"))

    def test_is_authorized_allows_chat_only_configuration_for_matching_chat(self):
        with mock.patch.object(utils_module, "TELEGRAM_ALLOWED_CHAT_IDS", "chat-1"), \
             mock.patch.object(utils_module, "TELEGRAM_CHAT_ID", ""), \
             mock.patch.object(utils_module, "TELEGRAM_ALLOWED_USER_IDS", ""):
            self.assertTrue(utils_module.is_authorized("chat-1", "any-user"))
            self.assertFalse(utils_module.is_authorized("chat-2", "any-user"))

    def test_is_authorized_denies_user_only_configuration_without_allowed_chat(self):
        with mock.patch.object(utils_module, "TELEGRAM_ALLOWED_CHAT_IDS", ""), \
             mock.patch.object(utils_module, "TELEGRAM_CHAT_ID", ""), \
             mock.patch.object(utils_module, "TELEGRAM_ALLOWED_USER_IDS", "user-1"):
            self.assertFalse(utils_module.is_authorized("chat-1", "user-1"))

    def test_is_authorized_denies_when_no_allowlist_is_configured(self):
        with mock.patch.object(utils_module, "TELEGRAM_ALLOWED_CHAT_IDS", ""), \
             mock.patch.object(utils_module, "TELEGRAM_CHAT_ID", ""), \
             mock.patch.object(utils_module, "TELEGRAM_ALLOWED_USER_IDS", ""):
            self.assertFalse(utils_module.is_authorized("chat-1", "user-1"))

    def test_telegram_chat_id_participates_as_allowed_chat(self):
        with mock.patch.object(utils_module, "TELEGRAM_ALLOWED_CHAT_IDS", ""), \
             mock.patch.object(utils_module, "TELEGRAM_CHAT_ID", "chat-1"), \
             mock.patch.object(utils_module, "TELEGRAM_ALLOWED_USER_IDS", "user-1"):
            self.assertTrue(utils_module.is_authorized("chat-1", "user-1"))
            self.assertFalse(utils_module.is_authorized("chat-2", "user-1"))


if __name__ == "__main__":
    unittest.main()
