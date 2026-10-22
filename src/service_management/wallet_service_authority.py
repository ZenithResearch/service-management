"""Pinned native Castalia Wallet authority for exact Service commands.

This adapter selects only the released ``castalia-wallet-service`` binary and
an owner-private, digest-pinned ``application=service`` configuration. It does
not receive keys, policy, paths, mode, or authority from an intake request.
"""

from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
import re
import stat
import subprocess

from .client_intake import UnknownAdmissionOutcome
from .contracts import canonical, load_json
from .errors import ServiceError
from .runtime_port import RuntimeCallError


MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
MAX_CONFIGURATION_BYTES = 65_536
MAX_AUTHORITY_BYTES = 1_048_576
MAX_PACKET_BYTES = 65_536 + 16_384 + 69
MAX_CONTEXT_BYTES = 65_536
DENIAL = b"castalia wallet service command denied\n"
HEX64 = re.compile(r"^[a-f0-9]{64}$", re.ASCII)


def _read_pinned(path: Path, digest: str, maximum: int, *, executable: bool) -> bytes:
    descriptor = None
    try:
        if path.is_symlink() or not path.is_absolute():
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= maximum
                or before.st_uid not in ({0, os.getuid()} if executable else {os.getuid()})
                or before.st_mode & (0o022 if executable else 0o077)
                or (executable and not before.st_mode & 0o111)):
            raise ValueError
        body = bytearray()
        while block := os.read(descriptor, 65_536):
            body.extend(block)
            if len(body) > maximum:
                raise ValueError
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if (identity(before) != identity(after) or len(body) != before.st_size
                or hashlib.sha256(body).hexdigest() != digest):
            raise ValueError
        return bytes(body)
    except (OSError, ValueError):
        raise ServiceError("forbidden") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _envelope(raw: bytes, *, schema: str, packet_maximum: int) -> bytes:
    try:
        if not 0 < len(raw) <= MAX_AUTHORITY_BYTES:
            raise ValueError
        value = load_json(raw)
        if (set(value) != {"schema", "packet_hex", "signed_context_hex"}
                or value["schema"] != schema):
            raise ValueError
        for name, maximum in (("packet_hex", packet_maximum),
                              ("signed_context_hex", MAX_CONTEXT_BYTES)):
            field = value[name]
            if (not isinstance(field, str) or not 0 < len(field) <= 2 * maximum
                    or len(field) % 2 or re.fullmatch(r"[a-f0-9]+", field, re.ASCII) is None):
                raise ValueError
        return raw
    except (ServiceError, KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        raise UnknownAdmissionOutcome() from None


class CastaliaWalletServiceAuthority:
    """Issue or explicitly resume exact Service authority through Wallet."""

    def __init__(self, *, executable: str | Path, executable_sha256: str,
                 configuration: str | Path, configuration_sha256: str,
                 timeout: float = 5.0):
        self.executable = Path(executable)
        self.configuration = Path(configuration)
        self.executable_sha256 = executable_sha256
        self.configuration_sha256 = configuration_sha256
        self.timeout = timeout
        if (not self.executable.is_absolute() or not self.configuration.is_absolute()
                or HEX64.fullmatch(executable_sha256) is None
                or HEX64.fullmatch(configuration_sha256) is None
                or type(timeout) not in {int, float} or not math.isfinite(timeout)
                or not 0.05 <= timeout <= 30):
            raise ValueError("absolute pinned Wallet authority profile required")
        self._check_profile()

    def _check_profile(self) -> None:
        _read_pinned(self.executable, self.executable_sha256,
                     MAX_EXECUTABLE_BYTES, executable=True)
        raw = _read_pinned(self.configuration, self.configuration_sha256,
                           MAX_CONFIGURATION_BYTES, executable=False)
        try:
            value = load_json(raw)
            required = {"schema", "native_configuration", "native_configuration_sha256",
                        "wallet_root", "application", "store_binding", "expected_state"}
            if (not isinstance(value, dict) or set(value) != required
                    or value["schema"] != "castalia.wallet-service-command.v1"
                    or value["application"] != "service"
                    or not isinstance(value["store_binding"], dict)
                    or value["store_binding"].get("application") != "service"):
                raise ValueError
        except (ServiceError, UnicodeError, ValueError, TypeError):
            raise ServiceError("forbidden") from None

    def issue(self, command: bytes) -> bytes:
        return self._invoke("issue", command)

    def resume(self, command: bytes) -> bytes:
        return self._invoke("resume", command)

    def _invoke(self, mode: str, command: bytes) -> bytes:
        try:
            value = load_json(command)
            if canonical(value).encode("utf-8") != command:
                raise ServiceError("invalid_command")
            self._check_profile()
            result = subprocess.run(
                [str(self.executable), mode, "--config", str(self.configuration),
                 "--config-sha256", self.configuration_sha256],
                input=command, capture_output=True, timeout=self.timeout,
                env={}, cwd=str(self.configuration.parent), check=False,
            )
        except ServiceError:
            raise
        except (OSError, subprocess.SubprocessError):
            raise UnknownAdmissionOutcome() from None
        if result.returncode == 2 and not result.stdout and result.stderr == DENIAL:
            raise ServiceError("forbidden")
        if result.returncode != 0 or result.stderr:
            raise UnknownAdmissionOutcome()
        evidence = _envelope(result.stdout, schema="service.secs-envelope.v1",
                             packet_maximum=MAX_PACKET_BYTES)
        try:
            self._check_profile()
        except ServiceError:
            raise UnknownAdmissionOutcome() from None
        return evidence


class CastaliaWalletRuntimeAuthority(CastaliaWalletServiceAuthority):
    """Pinned Runtime command/query authority with explicit command recovery."""

    def _check_profile(self) -> None:
        _read_pinned(self.executable, self.executable_sha256,
                     MAX_EXECUTABLE_BYTES, executable=True)
        raw = _read_pinned(self.configuration, self.configuration_sha256,
                           MAX_CONFIGURATION_BYTES, executable=False)
        try:
            value = load_json(raw)
            required = {"schema", "native_configuration", "native_configuration_sha256",
                        "wallet_root", "application", "store_binding", "expected_state"}
            if (not isinstance(value, dict) or set(value) != required
                    or value["schema"] != "castalia.wallet-service-command.v1"
                    or value["application"] != "runtime"
                    or not isinstance(value["store_binding"], dict)
                    or value["store_binding"].get("application") != "runtime"):
                raise ValueError
        except (ServiceError, UnicodeError, ValueError, TypeError):
            raise ServiceError("forbidden") from None

    def __call__(self, request: dict) -> bytes:
        try:
            raw = canonical(request).encode("utf-8")
            schema = request.get("schema") if isinstance(request, dict) else None
            mode = "issue" if schema == "runtime.command.v1" else "query" if schema == "runtime.query.v1" else None
            if mode is None:
                raise ServiceError("invalid_command")
            return self._invoke_runtime(mode, raw)
        except ServiceError as error:
            raise RuntimeCallError(error.code, retryable=False, uncertain=False) from None
        except UnknownAdmissionOutcome:
            raise RuntimeCallError("unknown_outcome", retryable=True, uncertain=True) from None

    def resume(self, request: dict) -> bytes:
        try:
            if not isinstance(request, dict) or request.get("schema") != "runtime.command.v1":
                raise ServiceError("invalid_command")
            return self._invoke_runtime("resume", canonical(request).encode("utf-8"))
        except ServiceError as error:
            raise RuntimeCallError(error.code, retryable=False, uncertain=False) from None
        except UnknownAdmissionOutcome:
            raise RuntimeCallError("unknown_outcome", retryable=True, uncertain=True) from None

    def _invoke_runtime(self, mode: str, raw: bytes) -> bytes:
        # Reuse the pinned process transport, then enforce Runtime's larger
        # packet ceiling and application-specific envelope schema.
        try:
            value = load_json(raw)
            if canonical(value).encode("utf-8") != raw:
                raise ServiceError("invalid_command")
            self._check_profile()
            result = subprocess.run(
                [str(self.executable), mode, "--config", str(self.configuration),
                 "--config-sha256", self.configuration_sha256],
                input=raw, capture_output=True, timeout=self.timeout,
                env={}, cwd=str(self.configuration.parent), check=False,
            )
        except ServiceError:
            raise
        except (OSError, subprocess.SubprocessError):
            raise UnknownAdmissionOutcome() from None
        if result.returncode == 2 and not result.stdout and result.stderr == DENIAL:
            raise ServiceError("forbidden")
        if result.returncode != 0 or result.stderr:
            raise UnknownAdmissionOutcome()
        evidence = _envelope(result.stdout, schema="runtime.secs-envelope.v1",
                             packet_maximum=2_097_152 + 16_384 + 69)
        try:
            self._check_profile()
        except ServiceError:
            raise UnknownAdmissionOutcome() from None
        return evidence
