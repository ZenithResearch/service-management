import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from service_management.client_intake import UnknownAdmissionOutcome
from service_management.provider_worker import _oidc_token, main


def admission_args(command):
    return [command, "--intake-database", "/private/intake.db",
            "--service-database", "/private/service.db",
            "--requester-policy", "/private/requester.json",
            "--native-verifier", "/private/process-runtime-secs-check",
            "--native-verifier-sha256", "1" * 64,
            "--receiver-policy", "/private/service-receiver.json",
            "--wallet-command", "/private/castalia-wallet-service",
            "--wallet-command-sha256", "2" * 64,
            "--wallet-configuration", "/private/wallet-command.json",
            "--wallet-configuration-sha256", "3" * 64]


def lifecycle_args(command):
    return [command, "--intake-database", "/private/intake.db",
            "--service-database", "/private/service.db",
            "--native-verifier", "/private/process-runtime-secs-check",
            "--native-verifier-sha256", "1" * 64,
            "--receiver-policy", "/private/service-receiver.json",
            "--wallet-command", "/private/castalia-wallet-service",
            "--wallet-command-sha256", "2" * 64,
            "--wallet-configuration", "/private/service-wallet.json",
            "--wallet-configuration-sha256", "3" * 64,
            "--runtime-endpoint", "http://127.0.0.1:8092",
            "--runtime-wallet-command", "/private/castalia-wallet-service",
            "--runtime-wallet-command-sha256", "2" * 64,
            "--runtime-wallet-configuration", "/private/runtime-wallet.json",
            "--runtime-wallet-configuration-sha256", "4" * 64,
            "--process-id", "zenith.anima.brand-package",
            "--process-version", "zenith.anima.brand-package-v1",
            "--compilation-hash", "5" * 64]


def pull_args(token_file):
    return ["pull-once", "--intake-database", "/private/intake.db",
            "--region", "sfo1", "--topic", "zenith-intake-v1",
            "--consumer-group", "zenith-provider-mac", "--limit", "1",
            "--lease-seconds", "300", "--intake-opener", "/private/secs-provider-intake-v1",
            "--intake-opener-sha256", "4" * 64, "--oidc-token-file", str(token_file)]


class ProviderWorkerTests(unittest.TestCase):
    def run_worker(self, command, worker):
        output = io.StringIO()
        with patch("service_management.provider_worker._admission", return_value=worker), \
                contextlib.redirect_stdout(output):
            code = main(admission_args(command))
        return code, json.loads(output.getvalue())

    def test_fresh_and_recovery_commands_select_distinct_worker_operations(self):
        class Worker:
            def __init__(self): self.calls = []
            def admit_once(self, *, limit): self.calls.append(("issue", limit)); return []
            def resume_once(self, *, limit): self.calls.append(("resume", limit)); return []

        worker = Worker()
        code, result = self.run_worker("admit-once", worker)
        self.assertEqual((code, result["processed"], worker.calls), (0, 0, [("issue", 16)]))
        code, result = self.run_worker("resume-admission-once", worker)
        self.assertEqual((code, result["processed"], worker.calls[-1]), (0, 0, ("resume", 16)))

    def test_unknown_outcome_is_redacted_and_names_explicit_recovery(self):
        class Worker:
            def admit_once(self, *, limit): raise UnknownAdmissionOutcome()

        code, result = self.run_worker("admit-once", Worker())
        self.assertEqual(code, 4)
        self.assertEqual(result["error"], "unknown_outcome")
        self.assertIn("resume-admission-once", result["recovery"])
        self.assertNotIn("/private", json.dumps(result))

    def test_brand_package_commands_select_fresh_and_resume_operations(self):
        class Worker:
            def __init__(self): self.calls = []
            def advance_once(self, *, limit): self.calls.append(("issue", limit)); return []
            def resume_once(self, *, limit): self.calls.append(("resume", limit)); return []

        worker, output = Worker(), io.StringIO()
        with patch("service_management.provider_worker._lifecycle", return_value=worker), \
                contextlib.redirect_stdout(output):
            self.assertEqual(main(lifecycle_args("advance-brand-package-once")), 0)
        with patch("service_management.provider_worker._lifecycle", return_value=worker), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(lifecycle_args("resume-brand-package-once")), 0)
        self.assertEqual(worker.calls, [("issue", 16), ("resume", 16)])

    def test_pull_reads_owner_private_token_and_passes_it_only_to_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "oidc-token"
            token_file.write_text("header.payload.signature\n")
            token_file.chmod(0o600)
            worker = type("Worker", (), {"ingest_once": staticmethod(lambda: _async([]))})()
            output = io.StringIO()
            with patch("service_management.provider_worker.IntakeStore"), \
                    patch("service_management.provider_worker.NativeSecSIntakeOpener"), \
                    patch("service_management.provider_worker.VercelPollIntake.from_sdk", return_value=worker) as factory, \
                    contextlib.redirect_stdout(output):
                self.assertEqual(main(pull_args(token_file)), 0)
            self.assertEqual(factory.call_args.kwargs["token"], "header.payload.signature")
            self.assertNotIn("header.payload.signature", output.getvalue())

    def test_oidc_token_file_rejects_symlink_and_permissive_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "oidc-token"
            token_file.write_text("header.payload.signature\n")
            token_file.chmod(0o644)
            with self.assertRaises(ValueError):
                _oidc_token(str(token_file))
            token_file.chmod(0o600)
            link = Path(directory) / "token-link"
            link.symlink_to(token_file)
            with self.assertRaises(ValueError):
                _oidc_token(str(link))


async def _async(value):
    return value


if __name__ == "__main__":
    unittest.main()
