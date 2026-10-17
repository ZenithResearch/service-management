import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from service_management import Service
from service_management.authority import LocalDevUntrustedVerifier
from service_management.http_api import make_server
from service_management.ingress import CommandIngress
from service_management.sqlite_store import SQLiteUnitOfWork


class HttpContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = SQLiteUnitOfWork(Path(self.temp.name) / "service.db")

    def start(self, *, local=False):
        service = Service(self.store, verifier=LocalDevUntrustedVerifier() if local else None,
                          environment="test" if local else "production", allow_local_dev_untrusted=local)
        server = make_server(CommandIngress(service))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(2)))
        return server.server_port

    def post(self, port, raw, extra=None, path="/v1/commands"):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        self.addCleanup(connection.close)
        connection.request("POST", path, raw, {"Content-Type": "application/json", **(extra or {})})
        response = connection.getresponse()
        return response.status, json.loads(response.read()), dict(response.getheaders())

    def command(self, **updates):
        return json.dumps({"schema": "service.command.v1", "operation": "request.create", "request_id": "http-create", "resource": {"kind": "ServiceRequest", "id": "http-request"}, "expected_version": None, "payload": {"summary": "HTTP intake"}, **updates}).encode()

    def get(self, port, path):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        self.addCleanup(connection.close)
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, json.loads(response.read())

    def test_readiness_separates_liveness_default_deny_and_explicit_local_authority(self):
        denied = self.start()
        self.assertEqual(self.get(denied, "/live")[0], 200)
        status, body = self.get(denied, "/ready")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"service": "service-management", "ready": False,
                               "checks": {"storage": "available", "authority": "default_deny"}})
        local = self.start(local=True)
        status, body = self.get(local, "/ready")
        self.assertEqual(status, 200)
        self.assertEqual(body["checks"]["authority"], "local_dev_untrusted")
        self.assertEqual(self.store.audit_history("ServiceRequest", "http-request"), [])
        self.assertEqual(Service(self.store, verifier=object()).readiness()["checks"]["authority"], "unqualified")

    def test_readiness_storage_failure_is_bounded_redacted_and_does_not_create_database(self):
        port = self.start(local=True)
        blocker = sqlite3.connect(self.store.database, isolation_level=None)
        try:
            blocker.execute("BEGIN IMMEDIATE")
            status, body = self.get(port, "/ready")
            self.assertEqual(status, 503)
            self.assertEqual(body["checks"]["storage"], "unavailable")
            self.assertNotIn(str(self.store.database), json.dumps(body))
            self.assertEqual(self.get(port, "/live")[0], 200)
        finally:
            blocker.rollback(); blocker.close()
        self.assertEqual(self.get(port, "/ready")[0], 200)
        self.store.database.unlink()
        self.assertEqual(self.get(port, "/ready")[0], 503)
        self.assertFalse(self.store.database.exists())

    def test_real_http_default_deny_and_local_adapter_visibility(self):
        status, body, headers = self.post(self.start(), self.command(), {"X-Service-Authority": "Bearer forged"})
        self.assertEqual(status, 403); self.assertEqual(body["error"]["code"], "forbidden")
        self.assertEqual(headers["Cache-Control"], "no-store")
        port = self.start(local=True)
        status, first, _ = self.post(port, self.command())
        self.assertEqual(status, 200); self.assertEqual(first["authority"]["mode"], "local_dev_untrusted")
        self.assertEqual(self.post(port, self.command())[1], first)
        status, rejected, _ = self.post(port, self.command(actor="matrix-room"))
        self.assertEqual(status, 400); self.assertEqual(rejected["schema"], "service.error.v1")

    def test_real_http_parser_and_lifecycle_errors_are_stable(self):
        port = self.start(local=True)
        self.assertEqual(self.post(port, b'{"schema":"x","schema":"y"}')[1]["error"]["code"], "invalid_json")
        self.assertEqual(self.post(port, self.command())[0], 200)
        raw = self.command(operation="request.accept", request_id="early-http-accept", expected_version=1, payload={"acceptance": "Not qualified"})
        status, body, _ = self.post(port, raw)
        self.assertEqual(status, 409); self.assertEqual(body["error"]["code"], "invalid_transition")
        self.assertEqual(body["request_id"], "early-http-accept")
        self.assertEqual(self.post(port, self.command(), {"Transfer-Encoding": "chunked"})[0], 400)

    def test_http_queries_share_default_deny_and_closed_read_contract(self):
        raw = json.dumps({"schema": "service.query.v1", "request_id": "http-query", "operation": "request.execution", "resource": {"kind": "ServiceRequest", "id": "http-request"}, "payload": {}}).encode()
        self.assertEqual(self.post(self.start(), raw, path="/v1/queries")[0], 403)
        port = self.start(local=True)
        self.post(port, self.command())
        status, result, _ = self.post(port, raw, path="/v1/queries")
        self.assertEqual(status, 200)
        self.assertEqual(result["data"]["execution_state"], "not_accepted")


if __name__ == "__main__":
    unittest.main()
