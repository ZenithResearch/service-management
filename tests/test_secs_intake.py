import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from service_management.errors import ServiceError
from service_management.secs_intake import (
    MAX_ENCRYPTED_ENVELOPE,
    NativeSecSIntakeOpener,
    OPENED_FRAME_MAGIC,
    OPENED_REFERENCE_FRAME_MAGIC,
)


def frame(intake=b'{"schema":"service.intake.v1"}', evidence=b"exact-requester-evidence"):
    return (OPENED_FRAME_MAGIC + len(intake).to_bytes(4, "big")
            + len(evidence).to_bytes(4, "big") + intake + evidence)


def reference_frame(content=b"original-reference", evidence=b"exact-requester-evidence"):
    values = [b"anima-brand-request-01", b"anima-brand-submit-01", b"reference-1"]
    return (OPENED_REFERENCE_FRAME_MAGIC + bytes(map(len, values))
            + hashlib.sha256(content).digest() + len(content).to_bytes(4, "big")
            + len(evidence).to_bytes(4, "big") + b"".join(values) + content + evidence)


class NativeSecSIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.executable = Path(self.temp.name) / "secs-provider-intake-v1"
        self.executable.write_bytes(b"pinned-test-binary")
        self.digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.opener = NativeSecSIntakeOpener(self.executable, self.digest)

    @patch("service_management.secs_intake.subprocess.run")
    def test_closed_native_frame_returns_exact_intake_and_evidence(self, invoke):
        invoke.return_value = subprocess.CompletedProcess([], 0, frame(), b"")
        opened = self.opener.open(b"encrypted-envelope")
        self.assertEqual(opened.intake, b'{"schema":"service.intake.v1"}')
        self.assertEqual(opened.requester_evidence, b"exact-requester-evidence")
        self.assertEqual(invoke.call_args.args[0], [str(self.executable), "open"])
        self.assertEqual(invoke.call_args.kwargs["input"], b"encrypted-envelope")
        self.assertEqual(invoke.call_args.kwargs["env"], {})
        self.assertEqual(invoke.call_args.kwargs["timeout"], 5.0)

    @patch("service_management.secs_intake.subprocess.run")
    def test_distinct_reference_frame_returns_bound_ids_digest_bytes_and_evidence(self, invoke):
        invoke.return_value = subprocess.CompletedProcess([], 0, reference_frame(), b"")
        opened = self.opener.open_reference(b"encrypted-reference-envelope")
        self.assertEqual(opened.request_id, "anima-brand-request-01")
        self.assertEqual(opened.idempotency_key, "anima-brand-submit-01")
        self.assertEqual(opened.artifact_id, "reference-1")
        self.assertEqual(opened.content, b"original-reference")
        self.assertEqual(opened.content_hash, hashlib.sha256(opened.content).hexdigest())
        self.assertEqual(opened.requester_evidence, b"exact-requester-evidence")
        self.assertEqual(invoke.call_args.args[0],
                         [str(self.executable), "open-reference-object"])

    @patch("service_management.secs_intake.subprocess.run")
    def test_envelope_rejection_is_request_failure_and_config_failure_is_unavailable(self, invoke):
        for reason, expected in (("envelope_rejected", "invalid_command"),
                                 ("missing_recipient_key", "storage_unavailable"),
                                 ("unknown", "storage_unavailable")):
            invoke.return_value = subprocess.CompletedProcess(
                [], 1, b"", f'{{"error":"{reason}","ok":false}}\n'.encode())
            with self.subTest(reason=reason), self.assertRaises(ServiceError) as raised:
                self.opener.open(b"encrypted-envelope")
            self.assertEqual(raised.exception.code, expected)

    @patch("service_management.secs_intake.subprocess.run")
    def test_wrong_or_unbounded_frames_fail_closed(self, invoke):
        bad = [b"", b"WRONG001" + frame()[8:], frame() + b"trailing",
               OPENED_FRAME_MAGIC + (0).to_bytes(4, "big") + (1).to_bytes(4, "big") + b"x"]
        for output in bad:
            invoke.return_value = subprocess.CompletedProcess([], 0, output, b"")
            with self.subTest(output=output[:16]), self.assertRaises(ServiceError) as raised:
                self.opener.open(b"encrypted-envelope")
            self.assertEqual(raised.exception.code, "storage_unavailable")
        with self.assertRaises(ServiceError) as raised:
            self.opener.open(bytes(MAX_ENCRYPTED_ENVELOPE + 1))
        self.assertEqual(raised.exception.code, "invalid_command")

    @patch("service_management.secs_intake.subprocess.run")
    def test_executable_hash_and_symlink_are_rechecked_before_every_open(self, invoke):
        invoke.return_value = subprocess.CompletedProcess([], 0, frame(), b"")
        self.opener.open(b"encrypted-envelope")
        self.executable.write_bytes(b"replaced")
        with self.assertRaises(ServiceError) as raised:
            self.opener.open(b"encrypted-envelope")
        self.assertEqual(raised.exception.code, "storage_unavailable")
        link = Path(self.temp.name) / "link"; link.symlink_to(self.executable)
        linked = NativeSecSIntakeOpener(link, hashlib.sha256(self.executable.read_bytes()).hexdigest())
        with self.assertRaises(ServiceError):
            linked.open(b"encrypted-envelope")


if __name__ == "__main__":
    unittest.main()
