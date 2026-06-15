import importlib
import os
import unittest
from unittest import mock

import telegram_alerts.settings as settings_module


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


if __name__ == "__main__":
    unittest.main()
