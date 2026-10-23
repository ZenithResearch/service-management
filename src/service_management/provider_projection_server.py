"""Local GET-only provider projection listener for an explicit HTTPS proxy."""

from __future__ import annotations

import argparse
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .castalia_gateway import CastaliaClientReadPolicy, CastaliaClientReadVerifier
from .castalia_requester import load_requester_policy
from .client_intake import IntakeStore
from .contracts import canonical
from .provider_http import ProviderHttpApplication, ProviderHttpConfig, ProviderHttpRequest
from .provider_projection import LocalProviderProjection
from .runtime_port import UnavailableRuntime
from .sdk_adapter import SDKRuntimeAdapter
from .sqlite_store import SQLiteUnitOfWork
from .wallet_service_authority import CastaliaWalletRuntimeAuthority


MAX_HEADER_VALUE = 32_768


def _existing_database(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("projection databases must already exist as regular files")
    return path


class ProjectionComposition:
    """Pinned local owners behind one browser-authorized read boundary."""

    def __init__(self, args):
        intake_database = _existing_database(args.intake_database)
        service_database = _existing_database(args.service_database)
        requester = load_requester_policy(args.requester_policy)
        caller = ("browser", args.browser_origin)
        policy = CastaliaClientReadPolicy(
            requester.presentation_pins, requester.policy_digest_sha256, caller)
        authority, runtime = _runtime(args)
        self.intakes = IntakeStore(intake_database)
        self.service = SQLiteUnitOfWork(service_database)
        self.authority = authority
        self.requester_policy_path = args.requester_policy
        self.requester_policy = requester
        self.reader = LocalProviderProjection(
            self.intakes, self.service, runtime, public_base_url=args.public_base_url)
        self.application = ProviderHttpApplication(
            ProviderHttpConfig(args.browser_origin), None, None,
            client_reader=self.reader, read_authorizer=CastaliaClientReadVerifier(policy),
            read_only=True)

    def readiness(self) -> dict:
        checks = {"intake_store": self.intakes.health(),
                  "service_store": self.service.health(),
                  "requester_policy": False, "runtime_authority": False}
        try:
            checks["requester_policy"] = (
                load_requester_policy(self.requester_policy_path) == self.requester_policy)
        except (OSError, ValueError, TypeError):
            pass
        try:
            if self.authority is not None:
                self.authority._check_profile()
                checks["runtime_authority"] = True
        except Exception:
            pass
        return {"schema": "service.provider-projection-readiness.v1",
                "service": "service-management-provider-projection",
                "ready": all(checks.values()), "checks": checks}


def handler_for(composition: ProjectionComposition):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ServiceProviderProjection/0.1"

        def log_message(self, _format, *_args):
            # Authorization evidence, request identity and browser origin are not log data.
            return

        def _send(self, status: int, headers: tuple[tuple[str, str], ...], body: bytes):
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _health(self, readiness: bool):
            value = composition.readiness() if readiness else {
                "schema": "service.provider-projection-liveness.v1",
                "service": "service-management-provider-projection", "live": True}
            body = canonical(value).encode("utf-8")
            status = 200 if not readiness or value["ready"] else 503
            self._send(status, (("Content-Type", "application/json"),
                                ("Content-Length", str(len(body))),
                                ("Cache-Control", "no-store")), body)

        def _handle(self, method: str):
            parsed = urlsplit(self.path)
            if parsed.query or parsed.fragment:
                self.send_error(400)
                return
            if method == "GET" and parsed.path in {"/live", "/ready"}:
                self._health(parsed.path == "/ready")
                return
            headers = tuple(self.headers.raw_items())
            if (self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Content-Length") not in {None, "0"}
                    or any(len(value) > MAX_HEADER_VALUE for _, value in headers)):
                self.send_error(400)
                return
            response = asyncio.run(composition.application.handle(
                ProviderHttpRequest(method, parsed.path, headers, b"")))
            self._send(response.status, response.headers, response.body)

        def do_GET(self): self._handle("GET")
        def do_OPTIONS(self): self._handle("OPTIONS")
        def do_POST(self): self._handle("POST")
        def do_PUT(self): self._handle("PUT")
        def do_DELETE(self): self._handle("DELETE")

    return Handler


def make_server(composition: ProjectionComposition, host: str, port: int) -> ThreadingHTTPServer:
    if host != "127.0.0.1" or type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("projection listener requires explicit numeric loopback and port")
    server = ThreadingHTTPServer((host, port), handler_for(composition))
    server.daemon_threads = True
    return server


def _runtime(args):
    values = (args.runtime_endpoint, args.runtime_wallet_command,
              args.runtime_wallet_command_sha256,
              args.runtime_wallet_configuration,
              args.runtime_wallet_configuration_sha256)
    if args.runtime_unavailable:
        if any(value is not None for value in values):
            raise ValueError("bootstrap projection cannot receive Runtime authority")
        return None, UnavailableRuntime()
    if any(value is None for value in values):
        raise ValueError("active projection requires complete Runtime authority")
    authority = CastaliaWalletRuntimeAuthority(
        executable=args.runtime_wallet_command,
        executable_sha256=args.runtime_wallet_command_sha256,
        configuration=args.runtime_wallet_configuration,
        configuration_sha256=args.runtime_wallet_configuration_sha256,
        timeout=args.timeout,
    )
    runtime = SDKRuntimeAdapter.connect(
        args.runtime_endpoint, authority=authority, timeout=args.timeout)
    return authority, runtime


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Serve browser-authorized canonical provider reads on numeric loopback.")
    parser.add_argument("--intake-database", required=True)
    parser.add_argument("--service-database", required=True)
    parser.add_argument("--requester-policy", required=True)
    parser.add_argument("--browser-origin", required=True)
    parser.add_argument("--public-base-url", required=True)
    parser.add_argument("--runtime-unavailable", action="store_true",
                        help="serve authorized pre-Run state without Runtime authority")
    parser.add_argument("--runtime-endpoint")
    parser.add_argument("--runtime-wallet-command")
    parser.add_argument("--runtime-wallet-command-sha256")
    parser.add_argument("--runtime-wallet-configuration")
    parser.add_argument("--runtime-wallet-configuration-sha256")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--timeout", default=5.0, type=float)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.port == 0:
            raise ValueError("production listener requires a fixed port")
        composition = ProjectionComposition(args)
        server = make_server(composition, args.host, args.port)
    except (OSError, ValueError, TypeError):
        raise SystemExit("invalid provider projection configuration") from None
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
