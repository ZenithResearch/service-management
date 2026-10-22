"""One-shot local provider intake and admission worker commands."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
import stat

from .application import Service
from .castalia_requester import CastaliaRequesterVerifier, load_requester_policy
from .client_intake import (AdmissionWorker, IntakeStore, NativeAuthorizedServicePort,
                            UnknownAdmissionOutcome)
from .contracts import canonical
from .errors import ServiceError
from .ingress import CommandIngress
from .native_authority import FileReceiverPolicy, NativeSecSHelper, SecSServiceAuthorityVerifier
from .provider_lifecycle import BrandPackageLifecycleWorker
from .secs_intake import NativeSecSIntakeOpener
from .sdk_adapter import SDKRuntimeAdapter
from .sqlite_store import SQLiteUnitOfWork
from .vercel_intake import VercelPollConfig, VercelPollIntake
from .wallet_service_authority import CastaliaWalletRuntimeAuthority, CastaliaWalletServiceAuthority


def _oidc_token(path: str) -> str:
    """Read one owner-private OIDC token without putting it in argv or env."""
    source = Path(path)
    descriptor = None
    try:
        if not source.is_absolute() or source.is_symlink():
            raise ValueError
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_mode & 0o077
                or not 5 <= before.st_size <= 16_385):
            raise ValueError
        body = bytearray()
        while block := os.read(descriptor, 16_386):
            body.extend(block)
            if len(body) > 16_385:
                raise ValueError
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or len(body) != before.st_size:
            raise ValueError
        raw = bytes(body)
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        token = raw.decode("ascii")
        if (not token or len(token) > 16_384 or token.count(".") != 2
                or any(character.isspace() for character in token)):
            raise ValueError
        return token
    except (OSError, UnicodeError, ValueError):
        raise ValueError("invalid owner-private Vercel OIDC token file") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _admission(args) -> AdmissionWorker:
    receiver_policy = FileReceiverPolicy(args.receiver_policy)
    receiver_policy()
    inbound = SecSServiceAuthorityVerifier(
        NativeSecSHelper(args.native_verifier, args.native_verifier_sha256),
        receiver_policy,
    )
    service = Service(SQLiteUnitOfWork(args.service_database), verifier=inbound,
                      environment="production")
    wallet = CastaliaWalletServiceAuthority(
        executable=args.wallet_command,
        executable_sha256=args.wallet_command_sha256,
        configuration=args.wallet_configuration,
        configuration_sha256=args.wallet_configuration_sha256,
        timeout=args.timeout,
    )
    requester = CastaliaRequesterVerifier(load_requester_policy(args.requester_policy))
    port = NativeAuthorizedServicePort(CommandIngress(service), wallet)
    return AdmissionWorker(IntakeStore(args.intake_database), requester, port)


def _lifecycle(args) -> BrandPackageLifecycleWorker:
    receiver_policy = FileReceiverPolicy(args.receiver_policy)
    receiver_policy()
    inbound = SecSServiceAuthorityVerifier(
        NativeSecSHelper(args.native_verifier, args.native_verifier_sha256),
        receiver_policy,
    )
    runtime_authority = CastaliaWalletRuntimeAuthority(
        executable=args.runtime_wallet_command,
        executable_sha256=args.runtime_wallet_command_sha256,
        configuration=args.runtime_wallet_configuration,
        configuration_sha256=args.runtime_wallet_configuration_sha256,
        timeout=args.timeout,
    )
    runtime = SDKRuntimeAdapter.connect(
        args.runtime_endpoint, authority=runtime_authority, timeout=args.timeout)
    service = Service(SQLiteUnitOfWork(args.service_database), verifier=inbound,
                      environment="production", runtime=runtime)
    service_authority = CastaliaWalletServiceAuthority(
        executable=args.wallet_command,
        executable_sha256=args.wallet_command_sha256,
        configuration=args.wallet_configuration,
        configuration_sha256=args.wallet_configuration_sha256,
        timeout=args.timeout,
    )
    port = NativeAuthorizedServicePort(CommandIngress(service), service_authority)
    process_pin = {"process_id": args.process_id,
                   "process_version": args.process_version,
                   "compilation_hash": args.compilation_hash}
    return BrandPackageLifecycleWorker(IntakeStore(args.intake_database), port,
                                       runtime, process_pin)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Pull encrypted provider requests or admit retained requests through native authority.")
    commands = parser.add_subparsers(dest="command", required=True)
    pull = commands.add_parser("pull-once", help="poll one bounded Vercel Queue batch")
    pull.add_argument("--intake-database", required=True)
    pull.add_argument("--region", required=True)
    pull.add_argument("--topic", required=True)
    pull.add_argument("--consumer-group", required=True)
    pull.add_argument("--limit", type=int, default=10)
    pull.add_argument("--lease-seconds", type=int, default=300)
    pull.add_argument("--intake-opener", required=True)
    pull.add_argument("--intake-opener-sha256", required=True)
    pull.add_argument("--oidc-token-file", required=True)

    for name, help_text in (
        ("admit-once", "verify and admit only fresh retained requests"),
        ("resume-admission-once", "explicitly resume only held native authority attempts"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--intake-database", required=True)
        command.add_argument("--service-database", required=True)
        command.add_argument("--requester-policy", required=True)
        command.add_argument("--native-verifier", required=True)
        command.add_argument("--native-verifier-sha256", required=True)
        command.add_argument("--receiver-policy", required=True)
        command.add_argument("--wallet-command", required=True)
        command.add_argument("--wallet-command-sha256", required=True)
        command.add_argument("--wallet-configuration", required=True)
        command.add_argument("--wallet-configuration-sha256", required=True)
        command.add_argument("--limit", type=int, default=16)
        command.add_argument("--timeout", type=float, default=5)
    for name, help_text in (
        ("advance-brand-package-once", "advance one fresh command for each retained brand-package request"),
        ("resume-brand-package-once", "resume only held brand-package authority attempts"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--intake-database", required=True)
        command.add_argument("--service-database", required=True)
        command.add_argument("--native-verifier", required=True)
        command.add_argument("--native-verifier-sha256", required=True)
        command.add_argument("--receiver-policy", required=True)
        command.add_argument("--wallet-command", required=True)
        command.add_argument("--wallet-command-sha256", required=True)
        command.add_argument("--wallet-configuration", required=True)
        command.add_argument("--wallet-configuration-sha256", required=True)
        command.add_argument("--runtime-endpoint", required=True)
        command.add_argument("--runtime-wallet-command", required=True)
        command.add_argument("--runtime-wallet-command-sha256", required=True)
        command.add_argument("--runtime-wallet-configuration", required=True)
        command.add_argument("--runtime-wallet-configuration-sha256", required=True)
        command.add_argument("--process-id", required=True)
        command.add_argument("--process-version", required=True)
        command.add_argument("--compilation-hash", required=True)
        command.add_argument("--limit", type=int, default=16)
        command.add_argument("--timeout", type=float, default=5)
    return parser


def main(argv=None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "pull-once":
            store = IntakeStore(args.intake_database)
            opener = NativeSecSIntakeOpener(args.intake_opener, args.intake_opener_sha256)
            config = VercelPollConfig(args.topic, args.consumer_group, args.limit,
                                      args.lease_seconds)
            worker = VercelPollIntake.from_sdk(region=args.region, token=_oidc_token(args.oidc_token_file),
                                               config=config, opener=opener, store=store)
            results = asyncio.run(worker.ingest_once())
        elif args.command in {"admit-once", "resume-admission-once"}:
            worker = _admission(args)
            action = worker.resume_once if args.command == "resume-admission-once" else worker.admit_once
            results = action(limit=args.limit)
        else:
            worker = _lifecycle(args)
            action = worker.resume_once if args.command == "resume-brand-package-once" else worker.advance_once
            results = action(limit=args.limit)
        print(canonical({"schema": "service.provider-worker-result.v1",
                         "command": args.command, "processed": len(results),
                         "results": results}), flush=True)
        return 0
    except UnknownAdmissionOutcome:
        recovery = ("run resume-brand-package-once for the retained command"
                    if "brand-package" in args.command else
                    "run resume-admission-once for the retained command")
        print(canonical({"schema": "service.provider-worker-result.v1",
                         "command": args.command, "processed": 0, "results": [],
                         "error": "unknown_outcome",
                         "recovery": recovery}), flush=True)
        return 4
    except ServiceError as error:
        code = error.code if error.code in {"forbidden", "storage_unavailable",
                                            "idempotency_conflict", "invalid_command"} else "worker_unavailable"
        print(canonical({"schema": "service.provider-worker-result.v1",
                         "command": args.command, "processed": 0, "results": [],
                         "error": code, "recovery": "inspect retained local worker state"}), flush=True)
        return 3
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.error("invalid provider worker configuration")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
