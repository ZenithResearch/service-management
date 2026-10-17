"""Trusted component startup factory and bounded source-owned runtime workers."""
from dataclasses import dataclass
import math
from pathlib import Path
import threading
from typing import Protocol

from .application import Service
from .authority import LocalDevUntrustedVerifier
from .delivery import OutboxDelivery
from .errors import ServiceError
from .ingress import CommandIngress
from .projection import RuntimeProjection
from .runtime_port import RuntimeCallError, UnavailableRuntime
from .sdk_adapter import SDKRuntimeAdapter
from .sqlite_store import SQLiteUnitOfWork


class RuntimeAuthority(Protocol):
    def __call__(self, exact_request: dict) -> bytes:
        """Provide approved bounded native evidence for the exact SDK request.

        This trusted startup port has no implementation or credential custody in
        service-management. The runtime receiver independently verifies every
        result; a mode label or transport identity cannot grant authority.
        """
        ...


@dataclass(frozen=True)
class CompositionConfig:
    database: str | Path
    environment: str = "production"
    local_dev_untrusted: bool = False
    runtime_endpoint: str | None = None
    projection_database: str | Path | None = None
    poll_runtime: bool = False
    rebuild_projection: bool = False
    poll_interval: float = 1.0
    max_backoff: float = 30.0
    batch_size: int = 100
    projection_pages: int = 4
    runtime_timeout: float = 5.0

    def __post_init__(self):
        if self.environment not in {"production", "development", "test"}:
            raise ValueError("unknown environment")
        if any(type(value) is not bool for value in (self.local_dev_untrusted, self.poll_runtime, self.rebuild_projection)):
            raise ValueError("explicit composition flags required")
        if self.environment == "production" and self.local_dev_untrusted:
            raise ValueError("local_dev_untrusted is prohibited in production")
        if self.projection_database is not None and Path(self.projection_database).resolve() == Path(self.database).resolve():
            raise ValueError("projection must use separate disposable storage")
        if self.poll_runtime and (not self.runtime_endpoint or self.projection_database is None):
            raise ValueError("runtime polling requires an endpoint and separate projection storage")
        if self.rebuild_projection and not self.poll_runtime:
            raise ValueError("projection rebuild requires explicit polling")
        for value, low, high in ((self.poll_interval, .05, 60), (self.max_backoff, .05, 300), (self.runtime_timeout, .05, 10)):
            if type(value) not in {int, float} or not math.isfinite(value) or not low <= value <= high:
                raise ValueError("invalid bounded worker timing")
        if self.max_backoff < self.poll_interval or type(self.batch_size) is not int or not 1 <= self.batch_size <= 100 or type(self.projection_pages) is not int or not 1 <= self.projection_pages <= 100:
            raise ValueError("invalid worker bounds")


ERRORS = {"not_ready", "forbidden", "unauthenticated", "runtime_unavailable", "runtime_rejected",
          "runtime_contract", "projection_gap", "storage_unavailable", "unknown_outcome", "incompatible_version"}


def _diagnosis(code, owner):
    if code == "not_ready":
        return "process-runtime", "review_and_reopen_runtime_admission"
    if code in {"forbidden", "unauthenticated", "runtime_rejected"}:
        return "native-service-authority", "qualify_or_restore_exact_outbound_permission"
    if code == "projection_gap":
        return "service-management", "inspect_retained_runtime_history_and_rebuild_projection"
    if code in {"runtime_unavailable", "unknown_outcome"}:
        return "process-runtime", "restore_runtime_then_reconcile_exact_retained_intent"
    if code in {"runtime_contract", "incompatible_version"}:
        return "component-contracts", "review_pinned_provider_consumer_artifacts"
    return owner, "restore_owner_then_retry_retained_state"


class BoundedWorker:
    def __init__(self, name, callback, *, interval, max_backoff, stopped):
        self.name, self.callback = name, callback
        self.interval, self.max_backoff, self.stopped = interval, max_backoff, stopped
        self._lock, self._thread = threading.Lock(), None
        self._health = {"state": "starting", "owner": "service-management", "last_error": None,
                        "recovery": "wait_for_first_poll", "cycles": 0, "next_delay_seconds": interval}

    def start(self):
        if self._thread is not None:
            raise RuntimeError("worker already started")
        self._thread = threading.Thread(target=self._run, name="service-"+self.name, daemon=False)
        self._thread.start()

    def health(self):
        with self._lock:
            return dict(self._health)

    def _run(self):
        failures = 0
        while not self.stopped.is_set():
            try:
                diagnostic = self.callback()
            except (ServiceError, RuntimeCallError) as error:
                code = error.code if error.code in ERRORS else "worker_unavailable"
                diagnostic = {"state": "retrying", "last_error": code}
            except Exception:
                # Exceptions, endpoints, event bodies, inputs and authority are
                # never diagnostics. Canonical uncertain attempts remain durable.
                diagnostic = {"state": "retrying", "last_error": "worker_unavailable"}
            healthy = diagnostic["state"] in {"healthy", "catching_up"}
            failures = 0 if healthy else min(failures + 1, 20)
            delay = self.interval if healthy else min(self.max_backoff, self.interval * 2**failures)
            owner, recovery = _diagnosis(diagnostic.get("last_error"), "process-runtime" if diagnostic.get("failure_origin") == "runtime" else "service-management")
            with self._lock:
                self._health = {**diagnostic, "owner": owner, "recovery": "none" if healthy else recovery,
                                "cycles": self._health["cycles"]+1, "next_delay_seconds": delay}
            if self.stopped.wait(delay):
                break
        with self._lock:
            self._health = {**self._health, "state": "stopped"}

    def join(self, timeout):
        if self._thread is not None:
            self._thread.join(timeout)
            if self._thread.is_alive():
                raise RuntimeError("bounded worker failed to stop")


class ApplicationComposition:
    def __init__(self, config, *, inbound_verifier=None, runtime_authority: RuntimeAuthority | None = None):
        if not isinstance(config, CompositionConfig):
            raise TypeError("validated CompositionConfig required")
        self.config, self.stopped = config, threading.Event()
        if runtime_authority is not None and not config.runtime_endpoint:
            raise ValueError("outbound authority requires an explicit runtime endpoint")
        if config.local_dev_untrusted and inbound_verifier is not None:
            raise ValueError("local development authority cannot replace an inbound verifier")
        self.storage = SQLiteUnitOfWork(config.database)
        self.runtime = SDKRuntimeAdapter.connect(config.runtime_endpoint, authority=runtime_authority,
            environment=config.environment, local_dev_untrusted=config.local_dev_untrusted,
            timeout=config.runtime_timeout, cancelled=self.stopped.is_set) if config.runtime_endpoint else UnavailableRuntime()
        self.outbound_enabled = bool(config.runtime_endpoint and (config.local_dev_untrusted or runtime_authority is not None))
        self.projection = RuntimeProjection(config.projection_database) if config.projection_database is not None else None
        verifier = LocalDevUntrustedVerifier() if config.local_dev_untrusted else inbound_verifier
        self.service = Service(self.storage, verifier=verifier, environment=config.environment,
            allow_local_dev_untrusted=config.local_dev_untrusted, runtime=self.runtime, projection=self.projection)
        self.delivery = OutboxDelivery(self.storage, self.runtime)
        self._cursor, self._rebuild = "", None
        self._started, self.workers = False, {}
        if config.poll_runtime and self.outbound_enabled:
            if config.rebuild_projection:
                self._rebuild = self.projection.begin_rebuild()
            for name, action in (("outbox_delivery", self._deliver), ("runtime_projection", self._sync)):
                self.workers[name] = BoundedWorker(name, action, interval=config.poll_interval,
                    max_backoff=config.max_backoff, stopped=self.stopped)
        composition = self
        class ManagedIngress(CommandIngress):
            def readiness(self):
                return composition.readiness()
        self.ingress = ManagedIngress(self.service)

    def start(self):
        if self._started or self.stopped.is_set():
            raise RuntimeError("composition cannot be started twice")
        self._started = True
        for worker in self.workers.values():
            worker.start()

    def stop(self):
        self.stopped.set()
        # A worker checks stop between operations/pages; each SDK call is bounded
        # and storage admission waits no more than five seconds.
        for worker in self.workers.values():
            worker.join(self.config.runtime_timeout + 25)

    def _deliver(self):
        pending = self.delivery.pending(after=self._cursor, limit=self.config.batch_size)
        code = None
        for row in pending:
            if self.stopped.is_set():
                break
            result = self.delivery.reconcile(row["event_id"])
            self._cursor = row["event_id"]
            if result["state"] != "started":
                candidate = result["last_error"]
                code = candidate if candidate in ERRORS else "unknown_outcome"
        if not pending:
            self._cursor = ""  # Fairly revisit retryable lower IDs next cycle.
        counts = self.storage.transact(lambda tx: tx.handoff_counts())
        durable_error = counts.pop("pending_error")
        code = code or (durable_error if durable_error in ERRORS else "unknown_outcome" if durable_error else None)
        state = "blocked" if counts["failed"] else "retrying" if code else "healthy"
        return {"state": state, "last_error": code or ("runtime_rejected" if counts["failed"] else None), "failure_origin": "runtime" if code or counts["failed"] else None, **counts}

    def _sync(self):
        health = self.projection.health()
        if health["freshness"] == "gap" and self._rebuild is None:
            raise ServiceError("projection_gap")
        for _ in range(self.config.projection_pages):
            if self.stopped.is_set():
                break
            health = self.projection.sync(self.runtime, limit=self.config.batch_size)
            if health["freshness"] == "current":
                if self._rebuild is not None:
                    health = self.projection.finish_rebuild(self._rebuild)
                    self._rebuild = None
                break
        return {"state": "healthy" if health["freshness"] == "current" else "catching_up",
                "last_error": None, "cursor": health["cursor"], "freshness": health["freshness"]}

    def readiness(self):
        base = self.service.readiness()
        checks = dict(base["checks"])
        if self.config.runtime_endpoint:
            checks["runtime_authority"] = {"state": "local_dev_untrusted" if self.config.local_dev_untrusted else "injected_unqualified" if self.outbound_enabled else "unavailable",
                "owner": "native-service-authority", "recovery": "none" if self.outbound_enabled else "inject_qualified_bounded_native_outbound_authority"}
        if self.config.poll_runtime:
            for name in ("outbox_delivery", "runtime_projection"):
                worker = self.workers.get(name)
                checks[name] = worker.health() if worker else {"state": "disabled", "last_error": "unauthenticated",
                    "owner": "native-service-authority", "recovery": "inject_qualified_bounded_native_outbound_authority"}
        ready = base["ready"] and (not self.config.runtime_endpoint or self.outbound_enabled)
        if self.config.poll_runtime:
            ready = ready and all(checks[name]["state"] == "healthy" for name in ("outbox_delivery", "runtime_projection"))
        return {"service": "service-management", "ready": bool(ready and not self.stopped.is_set()), "checks": checks}


def build_application(config: CompositionConfig, *, inbound_verifier=None, runtime_authority: RuntimeAuthority | None = None) -> ApplicationComposition:
    """Trusted factory; the CLI cannot invent or select an outbound native signer."""
    return ApplicationComposition(config, inbound_verifier=inbound_verifier, runtime_authority=runtime_authority)
