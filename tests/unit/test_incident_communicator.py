"""Unit tests for incident_communicator agent."""

from __future__ import annotations

import pytest

from shieldops.agents.incident_communicator.models import (
    ChannelType,
    CommStage,
    IncidentCommunicatorState,
    MessagePriority,
    Notification,
)
from shieldops.agents.incident_communicator.tools import (
    STAKEHOLDER_TEMPLATES,
    IncidentCommunicatorToolkit,
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class TestEnums:
    def test_comm_stage_values(self):
        assert CommStage.IDENTIFY_STAKEHOLDERS == "identify_stakeholders"
        assert CommStage.REPORT == "report"

    def test_channel_type_values(self):
        assert ChannelType.SLACK == "slack"
        assert ChannelType.VOICE == "voice"

    def test_message_priority_values(self):
        assert MessagePriority.CRITICAL == "critical"
        assert MessagePriority.INFORMATIONAL == "informational"


class TestState:
    def test_defaults(self):
        state = IncidentCommunicatorState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == CommStage.IDENTIFY_STAKEHOLDERS
        assert state.incident_id == ""
        assert state.notifications == []
        assert state.channels_used == []
        assert state.ack_count == 0
        assert state.reasoning_chain == []
        assert state.session_start == 0.0

    def test_with_values(self):
        state = IncidentCommunicatorState(
            request_id="req-1",
            tenant_id="t-1",
            incident_id="inc-99",
            ack_count=5,
        )
        assert state.request_id == "req-1"
        assert state.incident_id == "inc-99"
        assert state.ack_count == 5


class TestModels:
    def test_notification_defaults(self):
        n = Notification()
        assert n.id == ""
        assert n.channel == ChannelType.SLACK
        assert n.priority == MessagePriority.MEDIUM
        assert n.sent is False
        assert n.acknowledged is False


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        return IncidentCommunicatorToolkit()

    @pytest.mark.asyncio
    async def test_identify_stakeholders_critical(self, toolkit):
        result = await toolkit.identify_stakeholders(
            incident_id="inc-1",
            severity="critical",
        )
        assert len(result) == len(STAKEHOLDER_TEMPLATES["critical"])
        assert all("name" in s for s in result)

    @pytest.mark.asyncio
    async def test_identify_stakeholders_low(self, toolkit):
        result = await toolkit.identify_stakeholders(
            incident_id="inc-2",
            severity="low",
        )
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_identify_stakeholders_unknown_severity(self, toolkit):
        result = await toolkit.identify_stakeholders(
            incident_id="inc-3",
            severity="unknown",
        )
        # Falls back to medium
        assert len(result) == len(STAKEHOLDER_TEMPLATES["medium"])

    @pytest.mark.asyncio
    async def test_draft_message_critical(self, toolkit):
        msg = await toolkit.draft_message(
            incident_id="inc-1",
            severity="critical",
            recipient="CISO",
        )
        assert "CISO" in msg
        assert "[CRITICAL]" in msg
        assert "inc-1" in msg

    @pytest.mark.asyncio
    async def test_draft_message_fallback_severity(self, toolkit):
        msg = await toolkit.draft_message(
            incident_id="inc-2",
            severity="bogus",
            recipient="SRE",
        )
        assert "[MEDIUM]" in msg

    @pytest.mark.asyncio
    async def test_send_notification_simulated(self, toolkit):
        notif = Notification(
            id="ntf-001",
            recipient="SRE",
            channel=ChannelType.SLACK,
            priority=MessagePriority.HIGH,
            message="Test message",
        )
        result = await toolkit.send_notification(notif)
        assert result is True
        assert toolkit._sent_log["ntf-001"] is True

    @pytest.mark.asyncio
    async def test_check_acknowledgment_sent(self, toolkit):
        notif = Notification(id="ntf-002", message="Test")
        await toolkit.send_notification(notif)
        acked = await toolkit.check_acknowledgment("ntf-002")
        assert acked is True

    @pytest.mark.asyncio
    async def test_check_acknowledgment_not_sent(self, toolkit):
        acked = await toolkit.check_acknowledgment("ntf-never")
        assert acked is False


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_identify_stakeholders_node(self):
        from shieldops.agents.incident_communicator.nodes import (
            identify_stakeholders,
            set_toolkit,
        )

        set_toolkit(IncidentCommunicatorToolkit())
        state = IncidentCommunicatorState(incident_id="inc-1")
        result = await identify_stakeholders(state)
        assert "notifications" in result
        assert len(result["notifications"]) > 0
        assert result["stage"] == CommStage.DRAFT_MESSAGES

    @pytest.mark.asyncio
    async def test_draft_messages_node(self):
        from shieldops.agents.incident_communicator.nodes import (
            draft_messages,
            set_toolkit,
        )

        set_toolkit(IncidentCommunicatorToolkit())
        state = IncidentCommunicatorState(
            incident_id="inc-1",
            notifications=[
                Notification(
                    id="ntf-1",
                    recipient="SRE",
                    priority=MessagePriority.HIGH,
                ),
            ],
        )
        result = await draft_messages(state)
        assert len(result["notifications"]) == 1
        assert result["notifications"][0].message != ""
        assert result["stage"] == CommStage.SELECT_CHANNELS

    @pytest.mark.asyncio
    async def test_select_channels_node(self):
        from shieldops.agents.incident_communicator.nodes import (
            select_channels,
            set_toolkit,
        )

        set_toolkit(IncidentCommunicatorToolkit())
        state = IncidentCommunicatorState(
            incident_id="inc-1",
            notifications=[
                Notification(
                    id="ntf-1",
                    recipient="SRE",
                    priority=MessagePriority.CRITICAL,
                    message="Alert!",
                ),
            ],
        )
        result = await select_channels(state)
        assert len(result["channels_used"]) > 0
        assert result["stage"] == CommStage.SEND_NOTIFICATIONS

    @pytest.mark.asyncio
    async def test_send_notifications_node(self):
        from shieldops.agents.incident_communicator.nodes import (
            send_notifications,
            set_toolkit,
        )

        set_toolkit(IncidentCommunicatorToolkit())
        state = IncidentCommunicatorState(
            incident_id="inc-1",
            notifications=[
                Notification(
                    id="ntf-1",
                    recipient="SRE",
                    channel=ChannelType.SLACK,
                    message="Test",
                ),
            ],
        )
        result = await send_notifications(state)
        assert result["notifications"][0].sent is True
        assert result["stage"] == CommStage.TRACK_ACKS

    @pytest.mark.asyncio
    async def test_track_acks_node(self):
        from shieldops.agents.incident_communicator.nodes import (
            set_toolkit,
            track_acks,
        )

        tk = IncidentCommunicatorToolkit()
        tk._sent_log["ntf-1"] = True
        set_toolkit(tk)
        state = IncidentCommunicatorState(
            incident_id="inc-1",
            notifications=[
                Notification(
                    id="ntf-1",
                    recipient="SRE",
                    sent=True,
                    message="Test",
                ),
            ],
        )
        result = await track_acks(state)
        assert result["ack_count"] >= 1
        assert result["stage"] == CommStage.REPORT

    @pytest.mark.asyncio
    async def test_report_node(self):
        import time

        from shieldops.agents.incident_communicator.nodes import (
            report,
            set_toolkit,
        )

        set_toolkit(IncidentCommunicatorToolkit())
        state = IncidentCommunicatorState(
            incident_id="inc-1",
            session_start=time.time(),
            notifications=[
                Notification(
                    id="ntf-1",
                    sent=True,
                    acknowledged=True,
                    message="Done",
                ),
            ],
        )
        result = await report(state)
        assert result["stage"] == CommStage.REPORT


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.incident_communicator.runner import (
            IncidentCommunicatorRunner,
        )

        runner = IncidentCommunicatorRunner()
        assert runner is not None
