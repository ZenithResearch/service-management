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


def pull_args(token_file=None):
    result = ["pull-once", "--intake-database", "/private/intake.db",
            "--region", "sfo1", "--topic", "zenith-intake-v1",
            "--consumer-group", "zenith-provider-mac", "--limit", "1",
            "--lease-seconds", "300", "--intake-opener", "/private/secs-provider-intake-v1",
            "--intake-opener-sha256", "4" * 64]
    if token_file is not None:
        result.extend(["--oidc-token-file", str(token_file)])
    return result


def delivery_args(handoff_id):
    return ["deliver-handoff-once", "--service-database", "/private/service.db",
            "--runtime-endpoint", "http://127.0.0.1:8092",
            "--runtime-wallet-command", "/private/castalia-wallet-service",
            "--runtime-wallet-command-sha256", "2" * 64,
            "--runtime-wallet-configuration", "/private/runtime-wallet.json",
            "--runtime-wallet-configuration-sha256", "4" * 64,
            "--handoff-id", handoff_id]


def activation_args():
    return ["activation-brand-package-once", "--intake-database", "/private/intake.db"]


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

    def test_activation_preview_is_read_only_and_returns_the_exact_future_identity(self):
        store = type("Store", (), {"activation_pending": staticmethod(
            lambda **kwargs: [{"request_id": "request-1", "stage": "request_admitted",
                               "intake_json": "{}"}])})()
        expected = {"handoff_id": "a" * 64, "run_id": "handoff-" + "a" * 48}
        output = io.StringIO()
        with patch("service_management.provider_worker.IntakeStore", return_value=store), \
                patch("service_management.provider_worker.Intake.parse", return_value=object()), \
                patch("service_management.provider_worker.brand_package_activation",
                      return_value=expected), contextlib.redirect_stdout(output):
            self.assertEqual(main(activation_args()), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["results"], [{"request_id": "request-1",
                                              "stage": "request_admitted",
                                              "activation": expected}])

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

    def test_pull_without_token_file_delegates_environment_resolution_to_sdk(self):
        worker = type("Worker", (), {"ingest_once": staticmethod(lambda: _async([]))})()
        output = io.StringIO()
        with patch("service_management.provider_worker.IntakeStore"), \
                patch("service_management.provider_worker.NativeSecSIntakeOpener"), \
                patch("service_management.provider_worker.VercelPollIntake.from_sdk",
                      return_value=worker) as factory, contextlib.redirect_stdout(output):
            self.assertEqual(main(pull_args()), 0)
        self.assertIsNone(factory.call_args.kwargs["token"])
        self.assertNotIn("VERCEL_OIDC_TOKEN", output.getvalue())

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

    def test_delivery_selects_only_the_exact_handoff_and_reconciles_it(self):
        from service_management.runtime_port import content_digest
        event_id = "service-event-1"
        handoff_id = content_digest({"source": "service-management", "event_id": event_id})

        class Worker:
            def __init__(self): self.reconciled = []
            def pending(self, *, after, limit):
                return [{"event_id": "other-event"}, {"event_id": event_id}]
            def reconcile(self, selected):
                self.reconciled.append(selected)
                return {"event_id": selected, "state": "started"}

        worker, output = Worker(), io.StringIO()
        with patch("service_management.provider_worker._delivery", return_value=worker), \
                contextlib.redirect_stdout(output):
            self.assertEqual(main(delivery_args(handoff_id)), 0)
        result = json.loads(output.getvalue())
        self.assertEqual((result["processed"], worker.reconciled), (1, [event_id]))

    def test_delivery_does_not_consume_a_different_pending_handoff(self):
        worker = type("Worker", (), {
            "pending": staticmethod(lambda **kwargs: [{"event_id": "other-event"}]),
            "reconcile": staticmethod(lambda selected: self.fail("wrong handoff consumed")),
        })()
        output = io.StringIO()
        with patch("service_management.provider_worker._delivery", return_value=worker), \
                contextlib.redirect_stdout(output):
            self.assertEqual(main(delivery_args("a" * 64)), 0)
        self.assertEqual(json.loads(output.getvalue())["processed"], 0)


async def _async(value):
    return value


if __name__ == "__main__":
    unittest.main()
