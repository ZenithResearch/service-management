"""Public SDK admission tests; loopback fixture accepts inert test evidence only."""

import base64
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
from unittest.mock import patch

from process_runtime_client import (
    LocalDevAuthority,
    RuntimeClientError,
    command_envelope,
)
from service_management.runtime_port import RuntimeCallError
from service_management.sdk_adapter import SDKRuntimeAdapter


EVIDENCE = b"inert-sdk-adapter-test-evidence"


def requests():
    return (
        (
            "command",
            command_envelope(
                "handoff.consume",
                request_id="handoff-event-1",
                expected_version=None,
                payload={
                    "schema": "service.runtime-handoff.v1",
                    "event_id": "event-1",
                    "source": "service-management",
                    "request_id": "request-1",
                    "case_id": "case-1",
                    "plan_revision_id": "revision-1",
                    "pin": {
                        "process_id": "process-1",
                        "process_version": "version-1",
                        "compilation_hash": "a" * 64,
                    },
                    "inputs": {"message": "retained intent"},
                    "idempotency_key": "event-1",
                },
            ),
        ),
        (
            "query",
            {
                "schema": "runtime.query.v1",
                "operation": "events.list",
                "payload": {"after": 0, "limit": 1},
            },
        ),
    )


class SDKAdapterAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.received = []
        received = self.received

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                transport = json.loads(
                    self.rfile.read(int(self.headers["Content-Length"]))
                )
                received.append(transport)
                body = transport["request"]
                if self.path == "/v1/commands":
                    response = {
                        "schema": "runtime.result.v1",
                        "request_id": body["request_id"],
                        "operation": body["operation"],
                        "resource": body["resource"],
                        "duplicate": False,
                        "version": 1,
                        "result": {},
                    }
                else:
                    response = {
                        "schema": "runtime.query-result.v1",
                        "operation": body["operation"],
                        "data": {"events": [], "next_cursor": 0, "high_watermark": 0},
                    }
                raw = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        self.thread.start()
        self.addCleanup(self.close)
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.assertFalse(self.thread.is_alive())

    def test_cancellation_during_blocked_authority_denies_command_and_query_dispatch(
        self,
    ):
        for kind, envelope in requests():
            with self.subTest(kind=kind):
                entered, release, cancelled = (
                    threading.Event(),
                    threading.Event(),
                    threading.Event(),
                )
                calls = []

                def authority(value):
                    calls.append(deepcopy(value))
                    entered.set()
                    if not release.wait(3):
                        raise AssertionError("authority wait timed out")
                    return EVIDENCE

                adapter = SDKRuntimeAdapter.connect(
                    self.endpoint, authority=authority, cancelled=cancelled.is_set
                )
                method = "execute" if kind == "command" else "query"
                with patch.object(
                    adapter._client, method, wraps=getattr(adapter._client, method)
                ) as dispatch:
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(getattr(adapter, kind), envelope)
                        try:
                            self.assertTrue(entered.wait(3))
                            cancelled.set()
                        finally:
                            release.set()
                        with self.assertRaises(RuntimeCallError) as error:
                            future.result(timeout=5)
                    self.assertEqual(
                        (
                            error.exception.code,
                            error.exception.retryable,
                            error.exception.uncertain,
                        ),
                        ("runtime_unavailable", True, False),
                    )
                    dispatch.assert_not_called()
                self.assertEqual(calls, [envelope])
                self.assertEqual(self.received, [])

    def test_authority_mutation_cannot_change_retained_or_dispatched_intent(self):
        for kind, envelope in requests():
            with self.subTest(kind=kind):
                original = deepcopy(envelope)
                calls = []

                def authority(value):
                    calls.append(deepcopy(value))
                    if kind == "command":
                        value["payload"]["inputs"]["message"] = "provider mutation"
                    else:
                        value["payload"]["after"] = 9
                    return EVIDENCE

                adapter = SDKRuntimeAdapter.connect(self.endpoint, authority=authority)
                original_authority = adapter._client.authority
                getattr(adapter, kind)(envelope)
                self.assertEqual(calls, [original])
                self.assertEqual(envelope, original)
                self.assertEqual(self.received[-1]["request"], original)
                self.assertEqual(
                    base64.b64decode(self.received[-1]["authority_base64"]), EVIDENCE
                )
                self.assertIs(adapter._client.authority, original_authority)

    def test_resume_command_selects_only_explicit_authority_recovery(self):
        command = requests()[0][1]
        calls = []

        class Authority:
            def __call__(inner, value):
                calls.append(("issue", deepcopy(value))); return EVIDENCE
            def resume(inner, value):
                calls.append(("resume", deepcopy(value))); return EVIDENCE

        adapter = SDKRuntimeAdapter.connect(self.endpoint, authority=Authority())
        adapter.command(command)
        adapter.resume_command(command)
        self.assertEqual([mode for mode, _ in calls], ["issue", "resume"])
        self.assertEqual(calls[0][1], calls[1][1])

    def test_invalid_envelopes_deny_before_authority(self):
        for kind, envelope in requests():
            mutations = [
                lambda value: value.update(extra=True),
                lambda value: value.update(schema="unknown"),
                lambda value: value["payload"].update(extra=True),
            ]
            if kind == "query":
                mutations += [
                    lambda value: value["payload"].update(after=True),
                    lambda value: value["payload"].update(limit=1.0),
                ]
            else:
                mutations += [lambda value: value.update(expected_version=True)]
            for mutate in mutations:
                with self.subTest(kind=kind, mutation=mutate):
                    bad = deepcopy(envelope)
                    mutate(bad)
                    calls = []
                    adapter = SDKRuntimeAdapter.connect(
                        self.endpoint,
                        authority=lambda value: calls.append(value) or EVIDENCE,
                    )
                    with self.assertRaises(RuntimeCallError) as error:
                        getattr(adapter, kind)(bad)
                    self.assertEqual(error.exception.code, "incompatible_version")
                    self.assertEqual(error.exception.uncertain, kind == "command")
                    self.assertEqual(calls, [])
                    self.assertEqual(self.received, [])

    def test_default_deny_and_invalid_authority_bytes_never_dispatch(self):
        for kind, envelope in requests():
            for evidence in (None, "not bytes", bytearray(b"bytes")):
                with self.subTest(kind=kind, evidence=evidence):
                    calls = []
                    adapter = SDKRuntimeAdapter.connect(
                        self.endpoint,
                        authority=lambda value: calls.append(value) or evidence,
                    )
                    with self.assertRaises(RuntimeCallError) as error:
                        getattr(adapter, kind)(envelope)
                    self.assertEqual(
                        (
                            error.exception.code,
                            error.exception.retryable,
                            error.exception.uncertain,
                        ),
                        ("unauthenticated", False, False),
                    )
                    self.assertEqual(calls, [envelope])
            adapter = SDKRuntimeAdapter.connect(self.endpoint)
            with self.assertRaises(RuntimeCallError) as error:
                getattr(adapter, kind)(envelope)
            self.assertEqual(error.exception.code, "unauthenticated")
        self.assertEqual(self.received, [])

    def test_already_cancelled_never_calls_authority_or_dispatch(self):
        calls = []
        adapter = SDKRuntimeAdapter.connect(
            self.endpoint,
            authority=lambda value: calls.append(value) or EVIDENCE,
            cancelled=lambda: True,
        )
        for kind, envelope in requests():
            with self.assertRaises(RuntimeCallError) as error:
                getattr(adapter, kind)(envelope)
            self.assertEqual(
                (
                    error.exception.code,
                    error.exception.retryable,
                    error.exception.uncertain,
                ),
                ("runtime_unavailable", True, False),
            )
        self.assertEqual(calls, [])
        self.assertEqual(self.received, [])

    def test_provider_error_classification_is_preserved(self):
        cases = [
            (RuntimeClientError("forbidden"), "forbidden", False, False),
            (
                RuntimeClientError("storage_unavailable", retryable=True),
                "storage_unavailable",
                True,
                False,
            ),
            (
                RuntimeCallError("unknown_outcome", retryable=True, uncertain=True),
                "unknown_outcome",
                True,
                True,
            ),
        ]
        for kind, envelope in requests():
            for failure, code, retryable, uncertain in cases:
                with self.subTest(kind=kind, code=code):
                    calls = []

                    def authority(value):
                        calls.append(value)
                        raise failure

                    adapter = SDKRuntimeAdapter.connect(
                        self.endpoint, authority=authority
                    )
                    with self.assertRaises(RuntimeCallError) as error:
                        getattr(adapter, kind)(envelope)
                    self.assertEqual(
                        (
                            error.exception.code,
                            error.exception.retryable,
                            error.exception.uncertain,
                        ),
                        (code, retryable, uncertain),
                    )
                    self.assertEqual(calls, [envelope])
        self.assertEqual(self.received, [])

    def test_post_dispatch_sdk_error_uncertainty_is_preserved(self):
        for kind, envelope in requests():
            for code, retryable, uncertain in [
                ("transport_unavailable", True, kind == "command"),
                ("incompatible_version", False, False),
            ]:
                with self.subTest(kind=kind, code=code):
                    adapter = SDKRuntimeAdapter.connect(
                        self.endpoint, authority=lambda value: EVIDENCE
                    )
                    method = "execute" if kind == "command" else "query"
                    with patch.object(
                        adapter._client,
                        method,
                        side_effect=RuntimeClientError(
                            code, retryable=retryable, uncertain=uncertain
                        ),
                    ):
                        with self.assertRaises(RuntimeCallError) as error:
                            getattr(adapter, kind)(envelope)
                    self.assertEqual(
                        (
                            error.exception.code,
                            error.exception.retryable,
                            error.exception.uncertain,
                        ),
                        (
                            code,
                            retryable,
                            uncertain
                            or (kind == "command" and code == "incompatible_version"),
                        ),
                    )

    def test_local_dev_uses_one_explicit_proof_and_remains_prohibited_in_production(
        self,
    ):
        for kind, envelope in requests():
            adapter = SDKRuntimeAdapter.connect(
                self.endpoint, environment="test", local_dev_untrusted=True
            )
            with patch.object(
                LocalDevAuthority,
                "__call__",
                autospec=True,
                side_effect=LocalDevAuthority.__call__,
            ) as authority:
                original = adapter._client.authority
                getattr(adapter, kind)(envelope)
                self.assertIs(adapter._client.authority, original)
                authority.assert_called_once()
            proof = json.loads(base64.b64decode(self.received[-1]["authority_base64"]))
            self.assertEqual(proof["schema"], "runtime.local-dev-envelope.v1")
            self.assertEqual(adapter.authority_mode, "local_dev_untrusted")
        with self.assertRaises(ValueError):
            SDKRuntimeAdapter.connect(self.endpoint, local_dev_untrusted=True)
