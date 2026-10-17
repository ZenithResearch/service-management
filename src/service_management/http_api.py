"""Small standard-library HTTP adapter for the closed command contract."""

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .contracts import canonical
from .transport import MAX_TRANSPORT_BODY, decode_http_request
from .errors import ServiceError
from .ingress import CommandIngress


BODY_READ_SECONDS = 5
BODY_READ_CHUNK = 64 * 1024
MAX_INFLIGHT_BODIES = 2


def handler_for(ingress: CommandIngress):
    body_admissions = threading.BoundedSemaphore(MAX_INFLIGHT_BODIES)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ServiceManagement/0.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, format, *args):
            # Headers, authority evidence and intake content are not log data.
            return

        def _reply(self, status: int, value: dict):
            body = canonical(value).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/ready":
                value = ingress.readiness()
                self._reply(200 if value["ready"] else 503, value)
                return
            if self.path != "/live":
                self._reply(404, ServiceError("not_found").envelope())
                return
            self._reply(200, {"service": "service-management", "live": True, "command_schema": "service.command.v1"})

        def _read_body(self, length: int) -> bytes:
            deadline = time.monotonic() + BODY_READ_SECONDS
            chunks = []
            remaining = length
            try:
                while remaining:
                    seconds = deadline - time.monotonic()
                    if seconds <= 0:
                        raise TimeoutError("body deadline")
                    self.connection.settimeout(seconds)
                    chunk = self.rfile.read1(min(remaining, BODY_READ_CHUNK))
                    if not chunk:
                        raise ServiceError("invalid_json")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if time.monotonic() >= deadline:
                    raise TimeoutError("body deadline")
                return b"".join(chunks)
            finally:
                self.connection.settimeout(5)

        def do_POST(self):
            if self.path not in {"/v1/commands", "/v1/queries"}:
                self._reply(404, ServiceError("not_found").envelope())
                return
            admitted = False
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1 or len(lengths[0]) > 20 or not lengths[0].isascii() or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= MAX_TRANSPORT_BODY:
                    raise ServiceError("invalid_json")
                if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding", "identity") != "identity":
                    raise ServiceError("invalid_json")
                if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                    raise ServiceError("invalid_command")
                evidence_values = self.headers.get_all("X-Service-Authority", [])
                if len(evidence_values) > 1 or (evidence_values and len(evidence_values[0]) > 16_384):
                    raise ServiceError("forbidden")
                evidence = evidence_values[0].encode("utf-8") if evidence_values else None
                if not body_admissions.acquire(blocking=False):
                    raise ServiceError("storage_unavailable")
                admitted = True
                raw = self._read_body(int(lengths[0]))
                if len(raw) != int(lengths[0]):
                    raise ServiceError("invalid_json")
                raw, evidence = decode_http_request(raw, evidence)
                action = ingress.submit if self.path == "/v1/commands" else ingress.query
                result = action(raw, authority_evidence=evidence)
                self._reply(200, result)
            except ServiceError as error:
                self._reply(error.status, error.envelope())
            except (TimeoutError, socket.timeout, UnicodeError):
                self._reply(400, ServiceError("invalid_json").envelope())
            except Exception:
                self._reply(500, ServiceError("internal_error").envelope())
            finally:
                if admitted:
                    body_admissions.release()

    return Handler


def make_server(ingress: CommandIngress, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), handler_for(ingress))
    server.daemon_threads = True
    return server
