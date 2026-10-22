import contextlib
import io
import json
import unittest
from unittest.mock import patch

from service_management.client_intake import UnknownAdmissionOutcome
from service_management.provider_worker import main


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


if __name__ == "__main__":
    unittest.main()
