import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from service_management.client_intake import UnknownAdmissionOutcome
from service_management.contracts import canonical
from service_management.errors import ServiceError
from service_management.runtime_port import RuntimeCallError
from service_management.wallet_service_authority import (CastaliaWalletRuntimeAuthority,
    CastaliaWalletServiceAuthority, DENIAL)


class WalletServiceAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.executable = self.root / "castalia-wallet-service"
        self.executable.write_bytes(b"reviewed-wallet-binary")
        self.executable.chmod(0o700)
        self.configuration = self.root / "service-command.json"
        self.configuration.write_text(canonical({
            "schema": "castalia.wallet-service-command.v1",
            "native_configuration": "/private/native.json",
            "native_configuration_sha256": "1" * 64,
            "wallet_root": "/private/wallet",
            "application": "service",
            "store_binding": {"store_id": "2" * 32, "subject_id": "service.provider",
                              "application": "service", "purpose": "secs-service-holder-proof.v1",
                              "minimum_revision": 1},
            "expected_state": {"state_revision": 1, "state_sha256": "3" * 64},
        }))
        self.configuration.chmod(0o600)
        self.executable_sha = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.configuration_sha = hashlib.sha256(self.configuration.read_bytes()).hexdigest()
        self.command = canonical({"schema": "service.command.v1", "operation": "request.create",
            "request_id": "admit-1", "resource": {"kind": "ServiceRequest", "id": "request-1"},
            "expected_version": None, "payload": {"summary": "Brand", "details": ""}}).encode()
        self.evidence = canonical({"schema": "service.secs-envelope.v1",
            "packet_hex": "00", "signed_context_hex": "00"}).encode()

    def authority(self):
        return CastaliaWalletServiceAuthority(executable=self.executable,
            executable_sha256=self.executable_sha, configuration=self.configuration,
            configuration_sha256=self.configuration_sha, timeout=1)

    def test_issue_and_resume_are_distinct_pinned_exact_invocations(self):
        authority = self.authority()
        with patch("service_management.wallet_service_authority.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, self.evidence, b"")) as invoke:
            self.assertEqual(authority.issue(self.command), self.evidence)
            self.assertEqual(authority.resume(self.command), self.evidence)
        self.assertEqual([call.args[0][1] for call in invoke.call_args_list], ["issue", "resume"])
        for call in invoke.call_args_list:
            self.assertEqual(call.kwargs["input"], self.command)
            self.assertEqual(call.kwargs["env"], {})
            self.assertEqual(call.args[0][2:], ["--config", str(self.configuration),
                                               "--config-sha256", self.configuration_sha])

    def test_denial_does_not_fallback_and_uncertain_output_requires_caller_recovery(self):
        authority = self.authority()
        with patch("service_management.wallet_service_authority.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 2, b"", DENIAL)) as invoke:
            with self.assertRaises(ServiceError) as denied:
                authority.issue(self.command)
            self.assertEqual(denied.exception.code, "forbidden")
            self.assertEqual(invoke.call_count, 1)
            self.assertEqual(invoke.call_args.args[0][1], "issue")
        for result in [subprocess.CompletedProcess([], 0, b"{}", b""),
                       subprocess.CompletedProcess([], 1, b"", b"fault"),
                       subprocess.CompletedProcess([], 0, self.evidence, b"unexpected")]:
            with self.subTest(result=result), patch(
                    "service_management.wallet_service_authority.subprocess.run", return_value=result):
                with self.assertRaises(UnknownAdmissionOutcome):
                    authority.issue(self.command)

    def test_wrong_application_pin_or_changed_artifact_denies_before_launch(self):
        value = json.loads(self.configuration.read_text())
        value["application"] = "runtime"
        self.configuration.write_text(canonical(value)); self.configuration.chmod(0o600)
        changed_sha = hashlib.sha256(self.configuration.read_bytes()).hexdigest()
        with self.assertRaises(ServiceError):
            CastaliaWalletServiceAuthority(executable=self.executable,
                executable_sha256=self.executable_sha, configuration=self.configuration,
                configuration_sha256=changed_sha)
        self.configuration.write_text(canonical({**value, "application": "service"})); self.configuration.chmod(0o600)
        authority = CastaliaWalletServiceAuthority(executable=self.executable,
            executable_sha256=self.executable_sha, configuration=self.configuration,
            configuration_sha256=hashlib.sha256(self.configuration.read_bytes()).hexdigest())
        self.executable.write_bytes(b"substituted"); self.executable.chmod(0o700)
        with patch("service_management.wallet_service_authority.subprocess.run") as invoke:
            with self.assertRaises(ServiceError): authority.issue(self.command)
            invoke.assert_not_called()

    def test_runtime_commands_queries_and_resume_use_only_the_selected_modes(self):
        value = json.loads(self.configuration.read_text())
        value["application"] = "runtime"; value["store_binding"]["application"] = "runtime"
        self.configuration.write_text(canonical(value)); self.configuration.chmod(0o600)
        authority = CastaliaWalletRuntimeAuthority(executable=self.executable,
            executable_sha256=self.executable_sha, configuration=self.configuration,
            configuration_sha256=hashlib.sha256(self.configuration.read_bytes()).hexdigest())
        evidence = canonical({"schema": "runtime.secs-envelope.v1",
                              "packet_hex": "00", "signed_context_hex": "00"}).encode()
        command = json.loads(self.command); command["schema"] = "runtime.command.v1"
        query = {"schema": "runtime.query.v1", "operation": "events.list",
                 "payload": {"after": 0, "limit": 1}}
        with patch("service_management.wallet_service_authority.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, evidence, b"")) as invoke:
            self.assertEqual(authority(command), evidence)
            self.assertEqual(authority(query), evidence)
            self.assertEqual(authority.resume(command), evidence)
        self.assertEqual([call.args[0][1] for call in invoke.call_args_list],
                         ["issue", "query", "resume"])
        with patch("service_management.wallet_service_authority.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 2, b"", DENIAL)):
            with self.assertRaises(RuntimeCallError) as denied: authority(command)
            self.assertEqual((denied.exception.code, denied.exception.uncertain),
                             ("forbidden", False))


if __name__ == "__main__":
    unittest.main()
