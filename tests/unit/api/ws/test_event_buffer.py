"""Per-org WebSocket event buffer with replay — TDD tests (#5 Round 3)."""

from __future__ import annotations

import pytest

from shieldops.api.ws.event_buffer import EventBuffer


@pytest.fixture()
def buffer() -> EventBuffer:
    return EventBuffer(max_per_org=10)


class TestEventBuffer:
    def test_append_returns_monotonic_id(self, buffer: EventBuffer) -> None:
        id1 = buffer.append("org-a", {"type": "x"})
        id2 = buffer.append("org-a", {"type": "y"})
        assert id2 > id1

    def test_replay_since_returns_events_after_id(self, buffer: EventBuffer) -> None:
        id1 = buffer.append("org-a", {"n": 1})
        buffer.append("org-a", {"n": 2})
        buffer.append("org-a", {"n": 3})
        replayed = buffer.replay_since("org-a", since_id=id1)
        # since_id is exclusive — must NOT include id1.
        assert [r["data"]["n"] for r in replayed] == [2, 3]

    def test_replay_since_none_returns_full_buffer(self, buffer: EventBuffer) -> None:
        buffer.append("org-a", {"n": 1})
        buffer.append("org-a", {"n": 2})
        replayed = buffer.replay_since("org-a", since_id=None)
        assert [r["data"]["n"] for r in replayed] == [1, 2]

    def test_replay_since_unknown_org_returns_empty(self, buffer: EventBuffer) -> None:
        buffer.append("org-a", {"n": 1})
        assert buffer.replay_since("org-b", since_id=None) == []

    def test_tenant_isolation_in_buffer(self, buffer: EventBuffer) -> None:
        buffer.append("org-a", {"n": 1})
        buffer.append("org-b", {"n": 2})
        a = buffer.replay_since("org-a", since_id=None)
        b = buffer.replay_since("org-b", since_id=None)
        assert [r["data"]["n"] for r in a] == [1]
        assert [r["data"]["n"] for r in b] == [2]

    def test_buffer_evicts_oldest_past_max(self) -> None:
        buf = EventBuffer(max_per_org=3)
        for i in range(5):
            buf.append("org-a", {"n": i})
        all_events = buf.replay_since("org-a", since_id=None)
        assert [r["data"]["n"] for r in all_events] == [2, 3, 4]

    def test_replay_since_id_older_than_buffer_returns_all_remaining(
        self,
    ) -> None:
        buf = EventBuffer(max_per_org=3)
        for i in range(5):
            buf.append("org-a", {"n": i})
        # Caller asks for events after a long-evicted ID — should still
        # return the entire current window rather than failing.
        replayed = buf.replay_since("org-a", since_id=0)
        assert [r["data"]["n"] for r in replayed] == [2, 3, 4]

    def test_event_envelope_carries_id_and_data(self, buffer: EventBuffer) -> None:
        buffer.append("org-a", {"hello": "world"})
        events = buffer.replay_since("org-a", since_id=None)
        assert "id" in events[0]
        assert events[0]["data"] == {"hello": "world"}
