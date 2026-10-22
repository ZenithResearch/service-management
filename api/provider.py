"""Vercel Python entry point for the bounded provider HTTP application."""

from __future__ import annotations

import asyncio
from functools import lru_cache
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit

from service_management.client_gateway import MAX_ENCRYPTED_ENVELOPE
from service_management.provider_http import ProviderHttpRequest
from service_management.provider_vercel import provider_application_from_environment


_ROUTES = {
    "credential": "/v1/request-credential",
    "intake": "/v1/client/requests",
    "reference": "/v1/client/reference-objects",
}


def _route_path(raw_path: str) -> str:
    parsed = urlsplit(raw_path)
    route = parse_qs(parsed.query, strict_parsing=True).get("route", [])
    path = _ROUTES.get(route[0] if len(route) == 1 else "")
    if path is None:
        raise ValueError("unsupported provider route")
    return path


@lru_cache(maxsize=1)
def _application():
    return provider_application_from_environment()


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self._handle("POST")

    def do_OPTIONS(self):
        self._handle("OPTIONS")

    def do_GET(self):
        self._handle("GET")

    def _handle(self, method: str):
        try:
            raw_length = self.headers.get("Content-Length", "0")
            if not raw_length.isascii() or not raw_length.isdigit():
                raise ValueError()
            length = int(raw_length)
            if length < 0 or length > MAX_ENCRYPTED_ENVELOPE:
                raise ValueError()
            body = self.rfile.read(length) if length else b""
            path = _route_path(self.path)
            response = asyncio.run(_application().handle(ProviderHttpRequest(
                method, path, tuple(self.headers.raw_items()), body)))
        except Exception:
            payload = b'{"error":{"code":"internal_error","message":"The provider could not complete the request.","retryable":true},"request_id":null,"schema":"service.client-error.v1"}'
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers(); self.wfile.write(payload); return
        self.send_response(response.status)
        for name, value in response.headers:
            self.send_header(name, value)
        self.end_headers()
        if response.body:
            self.wfile.write(response.body)
