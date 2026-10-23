"""Vercel Queues poll-mode adapter for the durable intake worker.

The Vercel SDK owns its OIDC token and lease.  This adapter never exposes that
credential to a browser.  Exiting a delivery context cleanly acknowledges it;
therefore the local SQLite commit is completed before acknowledgement.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .client_intake import EnvelopeOpener, IntakeStore, ReferenceObjectOpener, TransportReceipt


QUEUE_NAME = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)


def _time(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValueError("queue timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class VercelPollConfig:
    topic: str
    consumer_group: str
    limit: int = 10
    lease_seconds: int = 300

    def __post_init__(self):
        if (QUEUE_NAME.fullmatch(self.topic) is None or QUEUE_NAME.fullmatch(self.consumer_group) is None
                or type(self.limit) is not int or not 1 <= self.limit <= 10
                or type(self.lease_seconds) is not int or not 30 <= self.lease_seconds <= 3600):
            raise ValueError("invalid Vercel queue configuration")


class VercelPollIntake:
    """Thin async adapter around an official ``vercel.queue.QueueClient``."""

    def __init__(self, queue: Any, topic: Any, config: VercelPollConfig,
                 opener: EnvelopeOpener, store: IntakeStore):
        self.queue, self.topic, self.config = queue, topic, config
        self.opener, self.store = opener, store

    async def ingest_once(self) -> list[dict]:
        results = []
        deliveries = self.queue.poll(self.topic, self.config.consumer_group,
                                     limit=self.config.limit, lease_duration=self.config.lease_seconds)
        async for delivery in deliveries:
            # The official SDK acknowledges only after this context exits cleanly.
            async with delivery as message:
                if not isinstance(message.payload, bytes):
                    raise ValueError("intake queue topic must use the bytes transport")
                opened = self.opener.open(message.payload)
                metadata = message.metadata
                message_id = str(metadata.message_id)
                receipt = TransportReceipt(
                    "vercel-queue",
                    "vqs." + hashlib.sha256(message_id.encode("utf-8")).hexdigest(),
                    _time(metadata.created_at) or "",
                    _time(metadata.expires_at),
                )
                results.append(self.store.ingest(opened, receipt))
        return results

    @classmethod
    def from_sdk(cls, *, region: str, token: str | None, config: VercelPollConfig,
                 opener: EnvelopeOpener, store: IntakeStore) -> "VercelPollIntake":
        """Create the optional official SDK adapter.

        Pass ``token=None`` to let the SDK resolve its Vercel OIDC token.  Static
        access tokens and browser credentials are intentionally unsupported.
        Deploymentless polling is selected because the Mac must consume across
        frontend deployments; envelope versioning remains explicit.
        """
        if not isinstance(region, str) or re.fullmatch(r"^[a-z0-9]+$", region, re.ASCII) is None:
            raise ValueError("invalid Vercel queue region")
        if token is not None and (not isinstance(token, str) or token.count(".") != 2 or len(token) > 16_384):
            raise ValueError("invalid Vercel OIDC token")
        try:
            from vercel.queue import ALL_DEPLOYMENTS, ByteBufferTransport, QueueClient, Topic
        except ImportError as error:
            raise RuntimeError("the required vercel-queue dependency is unavailable") from error
        queue = QueueClient(region=region, token=token, deployment=ALL_DEPLOYMENTS)
        topic = Topic[bytes](config.topic, transport=ByteBufferTransport())
        return cls(queue, topic, config, opener, store)


class VercelPollReferenceObjects:
    """Poll the distinct encrypted-reference topic into the same durable inbox."""

    def __init__(self, queue: Any, topic: Any, config: VercelPollConfig,
                 opener: ReferenceObjectOpener, store: IntakeStore):
        self.queue, self.topic, self.config = queue, topic, config
        self.opener, self.store = opener, store

    async def ingest_once(self) -> list[dict]:
        results = []
        deliveries = self.queue.poll(self.topic, self.config.consumer_group,
                                     limit=self.config.limit,
                                     lease_duration=self.config.lease_seconds)
        async for delivery in deliveries:
            async with delivery as message:
                if not isinstance(message.payload, bytes):
                    raise ValueError("reference queue topic must use the bytes transport")
                opened = self.opener.open_reference(message.payload)
                metadata = message.metadata
                receipt = TransportReceipt(
                    "vercel-queue",
                    "vqs." + hashlib.sha256(
                        str(metadata.message_id).encode("utf-8")).hexdigest(),
                    _time(metadata.created_at) or "", _time(metadata.expires_at))
                results.append(self.store.ingest_reference(opened, receipt))
        return results

    @classmethod
    def from_sdk(cls, *, region: str, token: str | None, config: VercelPollConfig,
                 opener: ReferenceObjectOpener,
                 store: IntakeStore) -> "VercelPollReferenceObjects":
        if not isinstance(region, str) or re.fullmatch(r"^[a-z0-9]+$", region, re.ASCII) is None:
            raise ValueError("invalid Vercel queue region")
        if token is not None and (not isinstance(token, str) or token.count(".") != 2
                                  or len(token) > 16_384):
            raise ValueError("invalid Vercel OIDC token")
        try:
            from vercel.queue import ALL_DEPLOYMENTS, ByteBufferTransport, QueueClient, Topic
        except ImportError as error:
            raise RuntimeError("the required vercel-queue dependency is unavailable") from error
        queue = QueueClient(region=region, token=token, deployment=ALL_DEPLOYMENTS)
        topic = Topic[bytes](config.topic, transport=ByteBufferTransport())
        return cls(queue, topic, config, opener, store)
