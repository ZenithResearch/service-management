"""One-shot local provider intake and admission worker commands."""

from __future__ import annotations

import argparse
import asyncio

from .application import Service
from .castalia_requester import CastaliaRequesterVerifier, load_requester_policy
from .client_intake import (AdmissionWorker, IntakeStore, NativeAuthorizedServicePort,
                            UnknownAdmissionOutcome)
from .contracts import canonical
from .errors import ServiceError
from .ingress import CommandIngress
from .native_authority import FileReceiverPolicy, NativeSecSHelper, SecSServiceAuthorityVerifier
from .secs_intake import NativeSecSIntakeOpener
from .sqlite_store import SQLiteUnitOfWork
from .vercel_intake import VercelPollConfig, VercelPollIntake
from .wallet_service_authority import CastaliaWalletServiceAuthority


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
            worker = VercelPollIntake.from_sdk(region=args.region, token=None,
                                               config=config, opener=opener, store=store)
            results = asyncio.run(worker.ingest_once())
        else:
            worker = _admission(args)
            action = worker.resume_once if args.command == "resume-admission-once" else worker.admit_once
            results = action(limit=args.limit)
        print(canonical({"schema": "service.provider-worker-result.v1",
                         "command": args.command, "processed": len(results),
                         "results": results}), flush=True)
        return 0
    except UnknownAdmissionOutcome:
        print(canonical({"schema": "service.provider-worker-result.v1",
                         "command": args.command, "processed": 0, "results": [],
                         "error": "unknown_outcome",
                         "recovery": "run resume-admission-once for retained commands"}), flush=True)
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
