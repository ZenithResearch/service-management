"""Adapter for the public process_runtime_client distribution only."""

from functools import lru_cache
from importlib.resources import files
import json

from .contracts import canonical
from .runtime_port import RuntimeCallError


@lru_cache(maxsize=1)
def _query_validator():
    # The public SDK exports exact_retry for commands; queries use its packaged
    # versioned schema with the same strict JSON integer semantics.
    from jsonschema import Draft202012Validator, validators

    schema = json.loads(
        files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text()
    )
    strict = validators.extend(
        Draft202012Validator,
        type_checker=Draft202012Validator.TYPE_CHECKER.redefine(
            "integer", lambda checker, value: type(value) is int
        ),
    )
    return strict({**schema, "$ref": "#/$defs/query"})


class SDKRuntimeAdapter:
    def __init__(self, client, *, cancelled=None):
        from process_runtime_client import RuntimeClient, LocalDevAuthority

        if not isinstance(client, RuntimeClient):
            raise TypeError("expected the public wire-only RuntimeClient")
        self._client, self.cancelled = client, cancelled
        self.authority_mode = (
            "local_dev_untrusted"
            if isinstance(client.authority, LocalDevAuthority)
            else "adapter_supplied"
            if client.authority
            else "default_deny"
        )

    @classmethod
    def connect(
        cls,
        endpoint,
        *,
        authority=None,
        timeout=10,
        environment="production",
        local_dev_untrusted=False,
        cancelled=None,
    ):
        from process_runtime_client import LocalDevAuthority, RuntimeClient

        if environment not in {"production", "development", "test"}:
            raise ValueError("unknown environment")
        if environment == "production" and isinstance(authority, LocalDevAuthority):
            raise ValueError("local_dev_untrusted is prohibited in production")
        if local_dev_untrusted:
            if environment == "production" or authority is not None:
                raise ValueError(
                    "local_dev_untrusted is prohibited in production and cannot replace an authority adapter"
                )
            authority = LocalDevAuthority(environment=environment)
        # Missing authority remains the SDK's explicit unauthenticated denial.
        return cls(
            RuntimeClient(endpoint, authority=authority, timeout=timeout),
            cancelled=cancelled,
        )

    def _call(self, envelope, *, command):
        if self.cancelled is not None and self.cancelled():
            raise RuntimeCallError("runtime_unavailable", retryable=True)
        from process_runtime_client import RuntimeClientError, exact_retry

        try:
            request = json.loads(canonical(envelope))
            if command:
                request = exact_retry(request)
            elif not _query_validator().is_valid(request):
                raise RuntimeClientError("incompatible_version")
            authority = self._client.authority
            if authority is None:
                raise RuntimeClientError("unauthenticated")
            # Acquisition may block or mutate its input. Retain the validated
            # request separately and never reuse the provider's mutable copy.
            evidence = authority(json.loads(canonical(request)))
            if type(evidence) is not bytes:
                raise RuntimeClientError("unauthenticated")
            if self.cancelled is not None and self.cancelled():
                raise RuntimeCallError("runtime_unavailable", retryable=True)
            action = self._client.execute if command else self._client.query
            return json.loads(canonical(action(request, evidence=evidence)))
        except RuntimeClientError as error:
            # Conservatively preserve uncertainty if an older SDK could not
            # distinguish request validation from post-commit response mismatch.
            uncertain = error.uncertain or (
                command and error.code == "incompatible_version"
            )
            raise RuntimeCallError(
                error.code, retryable=error.retryable, uncertain=uncertain
            ) from None
        except (ValueError, TypeError, UnicodeError):
            raise RuntimeCallError("incompatible_version", uncertain=command) from None

    def command(self, envelope):
        return self._call(envelope, command=True)

    def query(self, envelope):
        return self._call(envelope, command=False)

    def new_command(self, operation, *, request_id, expected_version, payload):
        from process_runtime_client import command_envelope, RuntimeClientError

        try:
            return command_envelope(
                operation,
                request_id=request_id,
                expected_version=expected_version,
                payload=json.loads(canonical(payload)),
            )
        except RuntimeClientError as error:
            raise RuntimeCallError(
                error.code, retryable=False, uncertain=False
            ) from None
