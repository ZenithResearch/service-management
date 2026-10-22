import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from service_management.client_intake import OpenedEnvelope
from service_management.vercel_intake import VercelPollConfig, VercelPollIntake
from tests.test_client_intake import intake


class Message:
    def __init__(self):
        self.payload = b"encrypted-envelope"
        self.metadata = type("Metadata", (), {
            "message_id": "opaque/message/id",
            "created_at": datetime(2026, 10, 21, 18, tzinfo=UTC),
            "expires_at": datetime(2026, 10, 28, 18, tzinfo=UTC),
        })()


class Delivery:
    def __init__(self, message): self.message = message; self.acknowledged = False
    async def __aenter__(self): return self.message
    async def __aexit__(self, kind, value, traceback):
        if kind is None: self.acknowledged = True


class Queue:
    def __init__(self, deliveries): self.deliveries = deliveries; self.calls = []
    async def _iterate(self):
        for delivery in self.deliveries: yield delivery
    def poll(self, topic, group, **options):
        self.calls.append((topic, group, options)); return self._iterate()


class Opener:
    def open(self, payload):
        if payload != b"encrypted-envelope": raise ValueError("not the expected encrypted payload")
        return OpenedEnvelope(intake(), b"verified-membership-proof")


class FailingStore:
    def ingest(self, opened, receipt): raise RuntimeError("disk full")


class VercelIntakeTests(unittest.IsolatedAsyncioTestCase):
    async def test_sdk_delivery_is_acknowledged_only_after_local_commit(self):
        from service_management.client_intake import IntakeStore
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        store = IntakeStore(Path(temp.name) / "intake.db")
        delivery = Delivery(Message()); queue = Queue([delivery])
        config = VercelPollConfig("zenith-intake-v1", "zenith-provider-mac")
        result = await VercelPollIntake(queue, "topic", config, Opener(), store).ingest_once()
        self.assertTrue(delivery.acknowledged)
        self.assertEqual(result[0]["state"], "pending")
        self.assertRegex(result[0]["transport_receipt"]["receipt_id"], r"^vqs\.[a-f0-9]{64}$")
        self.assertEqual(queue.calls, [("topic", "zenith-provider-mac", {"limit": 10, "lease_duration": 300})])

    async def test_failed_local_commit_leaves_queue_delivery_unacknowledged(self):
        delivery = Delivery(Message()); queue = Queue([delivery])
        adapter = VercelPollIntake(queue, "topic", VercelPollConfig("zenith-intake-v1", "zenith-provider-mac"), Opener(), FailingStore())
        with self.assertRaisesRegex(RuntimeError, "disk full"):
            await adapter.ingest_once()
        self.assertFalse(delivery.acknowledged)

    def test_config_is_bounded(self):
        for values in [('', 'group', 1, 300), ('topic', 'bad group', 1, 300),
                       ('topic', 'group', 11, 300), ('topic', 'group', 1, 29),
                       ('topic', 'group', 1, 3601)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                VercelPollConfig(values[0], values[1], values[2], values[3])

    def test_factory_rejects_non_oidc_bearer_shape_before_import(self):
        with self.assertRaises(ValueError):
            VercelPollIntake.from_sdk(region="sfo1", token="static-access-token",
                config=VercelPollConfig("topic", "group"), opener=Opener(), store=FailingStore())


if __name__ == "__main__":
    unittest.main()
