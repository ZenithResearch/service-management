from __future__ import annotations

import json
import threading
import unittest
from argparse import Namespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from service_management.provider_http import ProviderHttpResponse
from service_management.provider_projection_server import _runtime, make_server
from service_management.runtime_port import UnavailableRuntime


class Application:
    def __init__(self): self.requests = []

    async def handle(self, request):
        self.requests.append(request)
        return ProviderHttpResponse(
            200, (("Content-Type", "application/json"),
                  ("Content-Length", "11"), ("Cache-Control", "no-store")),
            b'{"ok":true}')


class Composition:
    def __init__(self): self.application = Application()
    def readiness(self):
        return {"schema": "service.provider-projection-readiness.v1", "ready": True,
                "checks": {"intake_store": True, "service_store": True,
                           "requester_policy": True, "runtime_authority": True}}


class ProviderProjectionServerTests(unittest.TestCase):
    def setUp(self):
        self.composition = Composition()
        self.server = make_server(self.composition, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)

    def get(self, path, *, method="GET", headers=None):
        request = Request(self.base + path, method=method, headers=headers or {})
        with urlopen(request, timeout=2) as response:
            return response.status, response.headers, response.read()

    def test_liveness_readiness_and_projection_are_separate(self):
        self.assertEqual(json.loads(self.get("/live")[2])["live"], True)
        self.assertEqual(json.loads(self.get("/ready")[2])["ready"], True)
        status, headers, body = self.get(
            "/v1/client/requests/request-1",
            headers={"Origin": "https://anima.example", "Authorization": "Castalia proof"})
        self.assertEqual((status, json.loads(body)), (200, {"ok": True}))
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.composition.application.requests[0].method, "GET")

    def test_query_and_body_are_rejected_before_application(self):
        for request in (
            Request(self.base + "/v1/client/requests/request-1?secret=x"),
            Request(self.base + "/v1/client/requests/request-1", data=b"x", method="POST"),
        ):
            with self.assertRaises(HTTPError) as error:
                urlopen(request, timeout=2)
            self.assertEqual(error.exception.code, 400)
        self.assertEqual(self.composition.application.requests, [])

    def test_listener_is_numeric_loopback_only(self):
        with self.assertRaises(ValueError):
            make_server(self.composition, "0.0.0.0", 8293)

    def test_bootstrap_runtime_is_explicit_and_carries_no_authority(self):
        args = Namespace(runtime_unavailable=True, runtime_endpoint=None,
                         runtime_wallet_command=None,
                         runtime_wallet_command_sha256=None,
                         runtime_wallet_configuration=None,
                         runtime_wallet_configuration_sha256=None,
                         timeout=5)
        authority, runtime = _runtime(args)
        self.assertIsNone(authority)
        self.assertIsInstance(runtime, UnavailableRuntime)

        args.runtime_endpoint = "http://127.0.0.1:8292"
        with self.assertRaisesRegex(ValueError, "cannot receive Runtime authority"):
            _runtime(args)

    def test_active_runtime_requires_complete_authority_tuple(self):
        args = Namespace(runtime_unavailable=False,
                         runtime_endpoint="http://127.0.0.1:8292",
                         runtime_wallet_command=None,
                         runtime_wallet_command_sha256=None,
                         runtime_wallet_configuration=None,
                         runtime_wallet_configuration_sha256=None,
                         timeout=5)
        with self.assertRaisesRegex(ValueError, "complete Runtime authority"):
            _runtime(args)


if __name__ == "__main__": unittest.main()
