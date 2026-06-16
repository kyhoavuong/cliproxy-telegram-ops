import asyncio
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "quota-gate" / "quota_gate.py"


def install_aiohttp_stub_if_needed():
    if "aiohttp" in sys.modules:
        return
    try:
        __import__("aiohttp")
        return
    except ModuleNotFoundError:
        pass

    class Response:
        def __init__(self, *, status=200, text="", content_type=None, headers=None):
            self.status = status
            self.text = text
            self.content_type = content_type
            self.headers = headers or {}

    def json_response(data, *, status=200):
        return Response(status=status, text=json.dumps(data), content_type="application/json")

    class Application(dict):
        def __init__(self, *args, **kwargs):
            super().__init__()
            self.cleanup_ctx = []
            self.router = SimpleNamespace(add_route=lambda *args, **kwargs: None)

    class ClientSession:
        def __init__(self, *args, **kwargs):
            pass

        async def close(self):
            pass

    class ClientTimeout:
        def __init__(self, *args, **kwargs):
            pass

    class AiohttpError(Exception):
        pass

    web_stub = SimpleNamespace(
        Response=Response,
        json_response=json_response,
        StreamResponse=FakeStreamResponse if "FakeStreamResponse" in globals() else None,
        Application=Application,
        run_app=lambda *args, **kwargs: None,
    )
    aiohttp_stub = types.ModuleType("aiohttp")
    aiohttp_stub.ClientConnectionError = AiohttpError
    aiohttp_stub.ClientPayloadError = AiohttpError
    aiohttp_stub.ClientSession = ClientSession
    aiohttp_stub.ClientTimeout = ClientTimeout
    aiohttp_stub.ServerDisconnectedError = AiohttpError
    aiohttp_stub.web = web_stub
    sys.modules["aiohttp"] = aiohttp_stub


def load_quota_gate_module():
    install_aiohttp_stub_if_needed()
    spec = importlib.util.spec_from_file_location("quota_gate_for_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeRequest:
    def __init__(self, path, *, headers=None, query_string="", method="GET", body=b"", app=None):
        self.path = path
        self.method = method
        self.headers = headers or {}
        self.query_string = query_string
        self.rel_url = SimpleNamespace(path_qs=path + (("?" + query_string) if query_string else ""))
        self._body = body
        self.app = app or {}

    async def read(self):
        return self._body


class FakeStreamResponse:
    def __init__(self, *, status, reason, headers):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = b""
        self.prepared = False
        self.eof = False

    async def prepare(self, request):
        self.prepared = True

    async def write(self, chunk):
        self.body += chunk

    async def write_eof(self):
        self.eof = True


class FakeUpstreamContent:
    def __init__(self, chunks):
        self._chunks = chunks

    async def iter_chunked(self, size):
        for chunk in self._chunks:
            yield chunk


class FakeUpstreamResponse:
    def __init__(self, status=200, reason="OK", headers=None, chunks=None):
        self.status = status
        self.reason = reason
        self.headers = headers or {"Content-Type": "application/json"}
        self.content = FakeUpstreamContent(chunks or [b"{}"])


class FakeRequestContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class RecordingClient:
    def __init__(self, response=None):
        self.calls = []
        self.response = response or FakeUpstreamResponse()

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return FakeRequestContext(self.response)


class QuotaGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_quota_gate_module()

    def setUp(self):
        self.module._cache.update({
            "loaded_at": 0.0,
            "quotas_mtime": None,
            "state_mtime": None,
            "data": None,
        })

    def patch_runtime(self, tmp_path, *, disabled=()):
        quotas_path = tmp_path / "quotas.json"
        state_path = tmp_path / "state.json"
        db_path = tmp_path / "missing.db"
        quotas_path.write_text(
            json.dumps({
                "timezone": "UTC",
                "keys": [{
                    "name": "alice",
                    "key": "alice-secret-key-1234567890",
                    "daily_token_limit": 100,
                    "weekly_token_limit": 400,
                }],
            }) + "\n",
            encoding="utf-8",
        )
        state_path.write_text(json.dumps({"disabled_by_quota": list(disabled)}) + "\n", encoding="utf-8")
        return mock.patch.multiple(self.module, QUOTAS=quotas_path, STATE=state_path, DB=db_path)

    def response_json(self, response):
        return json.loads(response.text)

    def test_management_dashboard_and_usage_routes_are_blocked_and_not_forwarded(self):
        blocked_paths = [
            "/v0/management/accounts",
            "/management.html",
            "/usage",
            "/usage/reports",
        ]
        for path in blocked_paths:
            with self.subTest(path=path):
                client = RecordingClient()
                request = FakeRequest(path, app={"client": client, "upstream": "http://cliproxy:3000", "upstream_host": "cliproxy:3000"})

                response = asyncio.run(self.module.handler(request))

                self.assertEqual(response.status, 403)
                self.assertEqual(self.response_json(response), {"error": "forbidden"})
                self.assertEqual(client.calls, [])

    def test_v1_chat_completions_request_for_active_key_is_forwarded_normally(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.patch_runtime(Path(tmp), disabled=()):
                client = RecordingClient(FakeUpstreamResponse(status=200, reason="OK", chunks=[b'{"ok":true}']))
                request = FakeRequest(
                    "/v1/chat/completions",
                    headers={"Authorization": "Bearer alice-secret-key-1234567890"},
                    method="POST",
                    body=b'{"messages":[]}',
                    app={"client": client, "upstream": "http://cliproxy:3000", "upstream_host": "cliproxy:3000"},
                )

                with mock.patch.object(self.module.web, "StreamResponse", FakeStreamResponse):
                    response = asyncio.run(self.module.proxy_request(request))

        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, b'{"ok":true}')
        self.assertEqual(len(client.calls), 1)
        method, url, kwargs = client.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "http://cliproxy:3000/v1/chat/completions")
        self.assertEqual(kwargs["data"], b'{"messages":[]}')

    def test_disabled_quota_key_on_v1_returns_429_without_forwarding(self):
        key = "alice-secret-key-1234567890"
        with tempfile.TemporaryDirectory() as tmp:
            with self.patch_runtime(Path(tmp), disabled=(key,)):
                client = RecordingClient()
                request = FakeRequest(
                    "/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}"},
                    app={"client": client, "upstream": "http://cliproxy:3000", "upstream_host": "cliproxy:3000"},
                )

                response = asyncio.run(self.module.proxy_request(request))

        body = self.response_json(response)
        self.assertEqual(response.status, 429)
        self.assertEqual(body["error"], "quota_exceeded")
        self.assertEqual(client.calls, [])

    def test_quota_me_missing_api_key_returns_401(self):
        response = asyncio.run(self.module.quota_me(FakeRequest("/quota/me")))

        self.assertEqual(response.status, 401)
        self.assertEqual(self.response_json(response)["error"], "missing_api_key")

    def test_quota_me_unknown_api_key_returns_generic_401_without_oracle_fields(self):
        unknown_key = "unknown-secret-key-1234567890"
        with tempfile.TemporaryDirectory() as tmp:
            with self.patch_runtime(Path(tmp), disabled=()):
                response = asyncio.run(self.module.quota_me(FakeRequest(
                    "/quota/me",
                    headers={"Authorization": f"Bearer {unknown_key}"},
                )))

        body = self.response_json(response)
        body_text = json.dumps(body, sort_keys=True)
        self.assertEqual(response.status, 401)
        self.assertEqual(body, {"error": "unauthorized", "message": "Invalid API key"})
        for forbidden_field in (
            "known_key",
            "key",
            "today_tokens",
            "daily_token_limit",
            "daily_remaining_tokens",
            "week_tokens",
            "weekly_token_limit",
            "weekly_remaining_tokens",
            "reset_at",
        ):
            self.assertNotIn(forbidden_field, body)
        self.assertNotIn("unknown", body_text)
        self.assertNotIn("1234567890", body_text)

    def test_quota_me_known_api_key_returns_summary_without_full_key(self):
        key = "alice-secret-key-1234567890"
        with tempfile.TemporaryDirectory() as tmp:
            with self.patch_runtime(Path(tmp), disabled=()):
                response = asyncio.run(self.module.quota_me(FakeRequest(
                    "/quota/me",
                    headers={"Authorization": f"Bearer {key}"},
                )))

        body = self.response_json(response)
        body_text = json.dumps(body, sort_keys=True)
        self.assertEqual(response.status, 200)
        self.assertTrue(body["known_key"])
        self.assertEqual(body["name"], "alice")
        self.assertEqual(body["status"], "active")
        self.assertNotEqual(body["key"], key)
        self.assertNotIn(key, body_text)

    def test_quota_me_disabled_known_api_key_returns_disabled_summary(self):
        key = "alice-secret-key-1234567890"
        with tempfile.TemporaryDirectory() as tmp:
            with self.patch_runtime(Path(tmp), disabled=(key,)):
                response = asyncio.run(self.module.quota_me(FakeRequest(
                    "/quota/me",
                    headers={"Authorization": f"Bearer {key}"},
                )))

        body = self.response_json(response)
        self.assertEqual(response.status, 200)
        self.assertTrue(body["known_key"])
        self.assertEqual(body["status"], "disabled_by_quota")
        self.assertIn("state", body["disabled_reasons"])


if __name__ == "__main__":
    unittest.main()
