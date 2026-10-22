"""Framework-neutral public HTTP boundary for credential issuance and intake."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Iterable

from .castalia_credential import ReceiverCredentialIssuer
from .client_gateway import (
    EncryptedGatewaySubmission,
    EncryptedIntakeGateway,
    MAX_ENCRYPTED_ENVELOPE,
    UnknownGatewayOutcome,
    parse_intake_envelope_header,
)
from .contracts import canonical, identifier
from .errors import ServiceError

MAX_AUTHORIZATION = 32_768
CLIENT_ERRORS = {
    "invalid_command": (400, "invalid_request", "The request is invalid.", False),
    "forbidden": (403, "forbidden", "The request is not authorized.", False),
    "not_found": (404, "not_found", "The requested resource does not exist.", False),
    "runtime_unavailable": (503, "unavailable", "Authoritative provider state is temporarily unavailable.", True),
    "projection_gap": (503, "unavailable", "Authoritative provider state requires reconciliation.", True),
    "runtime_contract": (500, "internal_error", "The provider could not verify authoritative state.", True),
    "internal_error": (500, "internal_error", "The provider could not complete the request.", True),
}
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)


@dataclass(frozen=True)
class ProviderHttpRequest:
    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True)
class ProviderHttpResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True)
class ProviderHttpConfig:
    browser_origin: str
    credential_path: str = "/v1/request-credential"
    intake_path: str = "/v1/client/requests"
    status_base_url: str | None = None

    def __post_init__(self):
        if (not isinstance(self.browser_origin, str) or not self.browser_origin.startswith("https://")
                or self.browser_origin.endswith("/") or any(c in self.browser_origin for c in "?#")
                or not self.credential_path.startswith("/") or not self.intake_path.startswith("/")
                or self.credential_path == self.intake_path):
            raise ValueError("invalid provider HTTP configuration")
        if self.status_base_url is not None:
            from urllib.parse import urlsplit
            parsed = urlsplit(self.status_base_url)
            segments = parsed.path.split("/")[1:]
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                    or parsed.query or parsed.fragment or self.status_base_url.endswith("/")
                    or any(segment in {"", ".", ".."}
                           or re.fullmatch(r"[A-Za-z0-9._~-]+", segment) is None
                           for segment in segments)):
                raise ValueError("invalid public status base")


class ProviderHttpApplication:
    """Expose bounded browser commands and optional authoritative client reads."""

    def __init__(self, config: ProviderHttpConfig, credential_issuer: ReceiverCredentialIssuer | None,
                 intake_gateway: EncryptedIntakeGateway | None, *, client_reader=None,
                 read_authorizer=None, read_only: bool = False):
        self.config, self.credential_issuer, self.intake_gateway = (
            config, credential_issuer, intake_gateway)
        self.client_reader, self.read_authorizer, self.read_only = client_reader, read_authorizer, read_only
        if read_only and (credential_issuer is not None or intake_gateway is not None
                          or client_reader is None or read_authorizer is None):
            raise ValueError("read-only provider HTTP requires only projection dependencies")

    async def handle(self, request: ProviderHttpRequest) -> ProviderHttpResponse:
        request_id = None
        try:
            headers = self._headers(request.headers)
            origin = headers.get("origin")
            if origin != self.config.browser_origin:
                raise ServiceError("forbidden")
            if request.method == "OPTIONS":
                return self._response(204, b"")
            if request.method == "GET":
                return self._read(request.path, headers)
            if self.read_only:
                return self._error(405, "invalid_request", "The method is not supported.", False, None)
            if request.method != "POST":
                return self._error(405, "invalid_request", "The method is not supported.", False, None)
            request_id = headers.get("x-zenith-request-id")
            if request.path == self.config.credential_path:
                return self._credential(request.body, headers)
            if request.path == self.config.intake_path:
                return await self._intake(request.body, headers)
            return self._error(404, "not_found", "The provider route does not exist.", False, request_id)
        except UnknownGatewayOutcome:
            return self._error(503, "unavailable", "The queue outcome is unknown; retry the exact prepared envelope.", True, request_id)
        except ServiceError as error:
            status, code, message, retryable = CLIENT_ERRORS.get(
                error.code, (500, "internal_error", "The provider could not complete the request.", True))
            return self._error(status, code, message, retryable, request_id)
        except (KeyError, TypeError, ValueError, UnicodeError, OverflowError, json.JSONDecodeError):
            return self._error(400, "invalid_request", "The request is invalid.", False, request_id)

    def _credential(self, body: bytes, headers: dict[str, str]) -> ProviderHttpResponse:
        if self.credential_issuer is None:
            raise ServiceError("runtime_unavailable")
        self._body(headers, body, "application/json", 65_536)
        value = self.credential_issuer.issue(body)
        return self._json(200, value)

    async def _intake(self, body: bytes, headers: dict[str, str]) -> ProviderHttpResponse:
        if self.intake_gateway is None:
            raise ServiceError("runtime_unavailable")
        self._body(headers, body, "application/vnd.zenith.service-intake-envelope-v1",
                   MAX_ENCRYPTED_ENVELOPE)
        required = ("idempotency-key", "x-zenith-request-id", "x-zenith-provider-id",
                    "x-zenith-intake-sha256", "x-zenith-envelope-key-id",
                    "x-zenith-envelope-expires-at", "authorization")
        if any(not headers.get(key) for key in required):
            raise ValueError("missing intake header")
        authorization = headers["authorization"]
        if not authorization.startswith("Castalia "):
            raise ServiceError("forbidden")
        presentation = self._base64url(authorization[9:])
        header = parse_intake_envelope_header(body)
        if (headers["x-zenith-envelope-key-id"] != header.recipient_key_id
                or headers["x-zenith-envelope-expires-at"] != str(header.expires_at_ms)):
            raise ValueError("envelope header mismatch")
        submission = EncryptedGatewaySubmission(
            headers["x-zenith-request-id"], headers["idempotency-key"],
            headers["x-zenith-provider-id"], headers["x-zenith-intake-sha256"])
        result = await self.intake_gateway.submit(
            body, submission=submission, requester_presentation=presentation)
        if self.config.status_base_url is not None:
            result = {**result, "status_url": self.config.status_base_url + result["status_url"]}
        return self._json(202, result)

    def _read(self, path: str, headers: dict[str, str]) -> ProviderHttpResponse:
        if self.client_reader is None or self.read_authorizer is None:
            raise ServiceError("runtime_unavailable")
        authorization = headers.get("authorization", "")
        if not authorization.startswith("Castalia "):
            raise ServiceError("forbidden")
        presentation = self._base64url(authorization[9:])
        status = re.fullmatch(r"/v1/client/requests/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})", path)
        artifact = re.fullmatch(r"/v1/client/requests/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})/artifacts/([a-f0-9]{64})", path)
        receipt = re.fullmatch(r"/v1/client/requests/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})/receipts/(process-runtime|service-management|secs)/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})", path)
        if status:
            request_id = status.group(1)
            subject = self.read_authorizer.verify(
                "request.status", f"requests/{request_id}", presentation)
            return self._json(200, self.client_reader.status(request_id, subject))
        if artifact:
            request_id, content_hash = artifact.groups()
            subject = self.read_authorizer.verify(
                "artifact.get", f"artifacts/{content_hash}", presentation)
            media_type, body = self.client_reader.artifact(request_id, content_hash, subject)
            return self._response(200, body, content_type=media_type)
        if receipt:
            request_id, owner, receipt_id = receipt.groups()
            subject = self.read_authorizer.verify(
                "receipt.get", f"{owner}/receipts/{receipt_id}", presentation)
            return self._response(200, self.client_reader.receipt(
                request_id, owner, receipt_id, subject), content_type="application/json")
        return self._error(404, "not_found", "The provider route does not exist.", False, None)

    @staticmethod
    def _headers(values: Iterable[tuple[str, str]]) -> dict[str, str]:
        result = {}
        for raw_name, raw_value in values:
            if not isinstance(raw_name, str) or not isinstance(raw_value, str):
                raise ValueError("invalid header")
            name = raw_name.lower()
            if (not name or name in result or "\r" in raw_value or "\n" in raw_value
                    or len(raw_value) > MAX_AUTHORIZATION):
                raise ValueError("invalid header")
            result[name] = raw_value
        return result

    @staticmethod
    def _body(headers: dict[str, str], body: bytes, media_type: str, maximum: int) -> None:
        if (headers.get("content-type") != media_type or not isinstance(body, bytes)
                or not 0 < len(body) <= maximum):
            raise ValueError("invalid body")
        length = headers.get("content-length")
        if length is not None and (not length.isascii() or not length.isdigit()
                                   or int(length) != len(body)):
            raise ValueError("invalid content length")

    @staticmethod
    def _base64url(value: str) -> bytes:
        if (not value or len(value) > MAX_AUTHORIZATION or BASE64URL.fullmatch(value) is None
                or "=" in value):
            raise ServiceError("forbidden")
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (ValueError, binascii.Error):
            raise ServiceError("forbidden") from None
        if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
            raise ServiceError("forbidden")
        return decoded

    def _json(self, status: int, value: dict) -> ProviderHttpResponse:
        return self._response(status, canonical(value).encode("utf-8"))

    def _error(self, status: int, code: str, message: str, retryable: bool,
               request_id: str | None) -> ProviderHttpResponse:
        safe_request = request_id if isinstance(request_id, str) and identifier(request_id) else None
        return self._json(status, {"schema": "service.client-error.v1", "request_id": safe_request,
                                   "error": {"code": code, "message": message,
                                             "retryable": retryable}})

    def _response(self, status: int, body: bytes, *, content_type="application/json") -> ProviderHttpResponse:
        headers = [
            ("Access-Control-Allow-Origin", self.config.browser_origin),
            ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
            ("Access-Control-Allow-Headers", "Authorization, Content-Type, Content-Length, Idempotency-Key, X-Zenith-Request-Id, X-Zenith-Provider-Id, X-Zenith-Intake-SHA256, X-Zenith-Envelope-Key-Id, X-Zenith-Envelope-Expires-At"),
            ("Cache-Control", "no-store"), ("Vary", "Origin"),
        ]
        if body:
            headers.extend((("Content-Type", content_type), ("Content-Length", str(len(body)))))
        return ProviderHttpResponse(status, tuple(headers), body)
