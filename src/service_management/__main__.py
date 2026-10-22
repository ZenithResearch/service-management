import argparse
import signal

from .composition import CompositionConfig, build_application
from .native_authority import FileReceiverPolicy, NativeSecSHelper, SecSServiceAuthorityVerifier
from .http_api import make_server
from .errors import ServiceError
from .wallet_service_authority import CastaliaWalletRuntimeAuthority


def main():
    parser = argparse.ArgumentParser(description="Canonical service command API; production authority defaults to deny.")
    parser.add_argument("--database", required=True)
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--environment", choices=["production", "development", "test"], default="production")
    parser.add_argument("--local-dev-untrusted", action="store_true")
    parser.add_argument("--native-verifier", help="absolute operator-pinned verification-only helper path")
    parser.add_argument("--native-verifier-sha256", help="reviewed SHA-256 of helper bytes")
    parser.add_argument("--receiver-policy", help="absolute receiver-owned service.receiver-policy.v1 file")
    parser.add_argument("--runtime-endpoint", help="explicit credential-free public runtime origin")
    parser.add_argument("--projection-database", help="separate disposable service progress store")
    parser.add_argument("--poll-runtime", action="store_true", help="start bounded durable outbox and projection workers")
    parser.add_argument("--rebuild-projection", action="store_true", help="explicitly rebuild derived progress from retained cursor zero")
    parser.add_argument("--poll-interval", type=float, default=1)
    parser.add_argument("--max-backoff", type=float, default=30)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--projection-pages", type=int, default=4)
    parser.add_argument("--runtime-timeout", type=float, default=5)
    parser.add_argument("--runtime-wallet-command", help="absolute operator-pinned Castalia Wallet command path")
    parser.add_argument("--runtime-wallet-command-sha256", help="reviewed SHA-256 of Wallet command bytes")
    parser.add_argument("--runtime-wallet-configuration", help="absolute owner-private application=runtime configuration")
    parser.add_argument("--runtime-wallet-configuration-sha256", help="reviewed SHA-256 of Runtime Wallet configuration")
    args = parser.parse_args()
    native = (args.native_verifier, args.native_verifier_sha256, args.receiver_policy)
    if any(native) and (not all(native) or args.local_dev_untrusted):
        parser.error("native verifier, digest and receiver policy must be supplied together without local development authority")
    runtime_native = (args.runtime_wallet_command, args.runtime_wallet_command_sha256,
                      args.runtime_wallet_configuration, args.runtime_wallet_configuration_sha256)
    if any(runtime_native) and (not all(runtime_native) or not args.runtime_endpoint
                                or args.local_dev_untrusted):
        parser.error("runtime Wallet command, digests and configuration require a runtime endpoint and production authority")
    inbound = None
    try:
        if all(native):
            policy = FileReceiverPolicy(args.receiver_policy)
            policy()
            inbound = SecSServiceAuthorityVerifier(NativeSecSHelper(args.native_verifier, args.native_verifier_sha256), policy)
        runtime_authority = CastaliaWalletRuntimeAuthority(
            executable=args.runtime_wallet_command,
            executable_sha256=args.runtime_wallet_command_sha256,
            configuration=args.runtime_wallet_configuration,
            configuration_sha256=args.runtime_wallet_configuration_sha256,
            timeout=args.runtime_timeout,
        ) if all(runtime_native) else None
        config = CompositionConfig(args.database, environment=args.environment, local_dev_untrusted=args.local_dev_untrusted,
            runtime_endpoint=args.runtime_endpoint, projection_database=args.projection_database, poll_runtime=args.poll_runtime,
            rebuild_projection=args.rebuild_projection, poll_interval=args.poll_interval, max_backoff=args.max_backoff,
            batch_size=args.batch_size, projection_pages=args.projection_pages, runtime_timeout=args.runtime_timeout)
        application = build_application(config, inbound_verifier=inbound,
                                        runtime_authority=runtime_authority)
    except (OSError, ValueError, TypeError, KeyError, ServiceError):
        parser.error("invalid service-owned composition or authority configuration")
    server = make_server(application.ingress, port=args.port)
    server.timeout = .2
    server.daemon_threads = False  # Drain accepted HTTP requests on clean exit.
    def stop(signum, frame):
        application.stopped.set()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, stop)
    authority_mode = "local_dev_untrusted" if args.local_dev_untrusted else "native_receiver_unqualified" if all(native) else "default_deny"
    print(f"service-management on 127.0.0.1:{server.server_port}; authority={authority_mode}", flush=True)
    application.start()
    try:
        while not application.stopped.is_set():
            server.handle_request()
    finally:
        try:
            application.stop()
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
