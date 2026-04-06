"""Unit tests for the Kafka-backed ingestion pipeline.

Kafka is fully mocked — no broker required.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from shieldops.ingestion.kafka_consumer import KafkaEventConsumer
from shieldops.ingestion.kafka_producer import TOPIC_DLQ, TOPIC_RAW, KafkaEventProducer

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.fail = False

    async def exists(self, key: str) -> int:
        if self.fail:
            raise RuntimeError("redis down")
        return 1 if key in self.store else 0

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value


class FakeAIOKafkaProducer:
    """Drop-in replacement for ``aiokafka.AIOKafkaProducer``."""

    def __init__(self) -> None:
        self.started = False
        self.stopped = False
        self.sent: list[dict[str, Any]] = []

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def send_and_wait(
        self,
        topic: str,
        value: bytes,
        key: bytes | None = None,
        headers: list[tuple[str, bytes]] | None = None,
    ) -> None:
        self.sent.append({"topic": topic, "value": value, "key": key, "headers": headers})


class FakeStore:
    def __init__(self) -> None:
        self.batches: list[list[dict[str, Any]]] = []

    async def insert_events(self, records: list[dict[str, Any]]) -> None:
        self.batches.append(list(records))


class FakeMessage:
    def __init__(self, key: bytes, value: bytes) -> None:
        self.key = key
        self.value = value


# ---------------------------------------------------------------------------
# Producer fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def fake_producer(monkeypatch: pytest.MonkeyPatch) -> KafkaEventProducer:
    """A KafkaEventProducer wired to a FakeAIOKafkaProducer (no broker)."""
    fake_internal = FakeAIOKafkaProducer()

    class _FakeModule:
        AIOKafkaProducer = lambda *a, **kw: fake_internal  # noqa: E731

    # Patch the lazy import site: ``from aiokafka import AIOKafkaProducer``.
    import sys
    import types

    module = types.ModuleType("aiokafka")
    module.AIOKafkaProducer = lambda *a, **kw: fake_internal  # type: ignore[attr-defined]
    module.AIOKafkaConsumer = object  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aiokafka", module)

    prod = KafkaEventProducer(
        bootstrap_servers="localhost:9092",
        redis_client=FakeRedis(),
    )
    await prod.start()
    # Expose the fake for assertion access.
    prod._fake = fake_internal  # type: ignore[attr-defined]
    yield prod
    await prod.stop()


# ---------------------------------------------------------------------------
# Producer tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_producer_publishes_with_org_id_partition_key(
    fake_producer: KafkaEventProducer,
) -> None:
    ok = await fake_producer.publish(
        org_id="acme",
        event_id="evt-1",
        event={"foo": "bar", "source_provider": "cloudtrail"},
    )
    assert ok is True

    fake_internal: FakeAIOKafkaProducer = fake_producer._fake  # type: ignore[attr-defined]
    assert len(fake_internal.sent) == 1

    sent = fake_internal.sent[0]
    assert sent["topic"] == TOPIC_RAW
    # Partition key is the org_id so events from the same tenant stay ordered.
    assert sent["key"] == b"acme"
    # Value is JSON-encoded for schema-evolution-friendly lazy parse.
    decoded = json.loads(sent["value"].decode("utf-8"))
    assert decoded == {"foo": "bar", "source_provider": "cloudtrail"}


@pytest.mark.asyncio
async def test_producer_deduplicates_repeat_event_ids(
    fake_producer: KafkaEventProducer,
) -> None:
    event = {"foo": "bar"}
    first = await fake_producer.publish(org_id="acme", event_id="dup-1", event=event)
    second = await fake_producer.publish(org_id="acme", event_id="dup-1", event=event)

    assert first is True
    assert second is False  # dedup rejected the repeat

    fake_internal: FakeAIOKafkaProducer = fake_producer._fake  # type: ignore[attr-defined]
    assert len(fake_internal.sent) == 1


@pytest.mark.asyncio
async def test_producer_publish_dlq(fake_producer: KafkaEventProducer) -> None:
    ok = await fake_producer.publish_dlq(
        org_id="acme",
        raw_value=b"not-json",
        reason="bad_json",
    )
    assert ok is True

    fake_internal: FakeAIOKafkaProducer = fake_producer._fake  # type: ignore[attr-defined]
    assert fake_internal.sent[-1]["topic"] == TOPIC_DLQ
    assert fake_internal.sent[-1]["headers"] == [("reason", b"bad_json")]


# ---------------------------------------------------------------------------
# Consumer tests
# ---------------------------------------------------------------------------


class FakeConsumerInternal:
    """Stand-in for ``aiokafka.AIOKafkaConsumer``."""

    def __init__(self, batches: list[dict[Any, list[FakeMessage]]]) -> None:
        self._batches = batches
        self._idx = 0
        self.commits = 0
        self.stopped = False

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        self.stopped = True

    def assignment(self) -> set[Any]:
        return set()

    async def getmany(
        self, timeout_ms: int = 0, max_records: int = 0
    ) -> dict[Any, list[FakeMessage]]:
        if self._idx >= len(self._batches):
            return {}
        batch = self._batches[self._idx]
        self._idx += 1
        return batch

    async def commit(self) -> None:
        self.commits += 1


async def _make_consumer(
    monkeypatch: pytest.MonkeyPatch,
    batches: list[dict[Any, list[FakeMessage]]],
) -> tuple[KafkaEventConsumer, FakeConsumerInternal, FakeStore, FakeAIOKafkaProducer]:
    fake_internal = FakeConsumerInternal(batches)

    import sys
    import types

    module = types.ModuleType("aiokafka")
    module.AIOKafkaConsumer = lambda *a, **kw: fake_internal  # type: ignore[attr-defined]
    module.AIOKafkaProducer = object  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aiokafka", module)

    store = FakeStore()
    dlq_internal = FakeAIOKafkaProducer()
    dlq_producer = KafkaEventProducer()
    dlq_producer._producer = dlq_internal  # type: ignore[attr-defined]
    dlq_producer._available = True  # type: ignore[attr-defined]

    consumer = KafkaEventConsumer(
        bootstrap_servers="localhost:9092",
        dlq_producer=dlq_producer,
        store=store,
        batch_size=10,
        batch_timeout_ms=1,
    )
    await consumer.start()
    return consumer, fake_internal, store, dlq_internal


@pytest.mark.asyncio
async def test_consumer_processes_batch_and_commits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = {
        "source_provider": "cloudtrail",
        "event_type": "AccessDenied",
        "severity": "HIGH",
        "account": "123",
    }
    messages = [FakeMessage(key=b"acme", value=json.dumps(raw).encode("utf-8"))]
    batches = [{"tp": messages}]
    consumer, fake_internal, store, _dlq = await _make_consumer(monkeypatch, batches)

    # Stop after first empty poll.
    async def _single_run() -> None:
        # Drain one batch, then one empty poll, then signal stop.
        await consumer._consumer.getmany()  # prime, will be consumed by run()
        # We override run's loop by manually calling and stopping.

    # Trigger the loop; stop after the scripted batches drain.
    async def _stop_soon() -> None:
        import asyncio

        await asyncio.sleep(0.05)
        await consumer.stop()

    import asyncio

    await asyncio.gather(consumer.run(), _stop_soon())

    assert len(store.batches) == 1
    assert len(store.batches[0]) == 1
    assert store.batches[0][0]["source_provider"] == "cloudtrail"
    assert store.batches[0][0]["org_id"] == "acme"
    assert fake_internal.commits >= 1


@pytest.mark.asyncio
async def test_consumer_routes_malformed_events_to_dlq(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad = FakeMessage(key=b"acme", value=b"{not-json")
    batches = [{"tp": [bad]}]
    consumer, _fake_internal, store, dlq_internal = await _make_consumer(monkeypatch, batches)

    import asyncio

    async def _stop_soon() -> None:
        await asyncio.sleep(0.05)
        await consumer.stop()

    await asyncio.gather(consumer.run(), _stop_soon())

    # Nothing persisted to the store.
    assert store.batches == []
    # Bad message was routed to the DLQ topic.
    assert any(s["topic"] == TOPIC_DLQ for s in dlq_internal.sent)
    dlq_send = next(s for s in dlq_internal.sent if s["topic"] == TOPIC_DLQ)
    assert dlq_send["value"] == b"{not-json"
    assert any(h[0] == "reason" for h in (dlq_send["headers"] or []))
