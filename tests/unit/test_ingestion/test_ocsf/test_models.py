"""Tests for OCSF base and category-specific models."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from shieldops.ingestion.ocsf.models import (
    OCSFAPIActivity,
    OCSFAuthenticationEvent,
    OCSFBaseEvent,
    OCSFNetworkActivity,
    OCSFSecurityFinding,
)


class TestOCSFBaseEvent:
    def test_defaults(self) -> None:
        event = OCSFBaseEvent()
        assert isinstance(event.event_id, UUID)
        assert isinstance(event.timestamp, datetime)
        assert event.event_type == "base_event"
        assert event.severity == "informational"
        assert event.source_provider == "unknown"
        assert event.raw_event == {}
        assert event.normalized == {}
        assert event.enrichments == {}

    def test_custom_fields(self) -> None:
        raw = {"key": "value"}
        event = OCSFBaseEvent(
            source_provider="test",
            source_type="unit",
            raw_event=raw,
            severity="high",
        )
        assert event.source_provider == "test"
        assert event.severity == "high"
        assert event.raw_event == raw


class TestOCSFAuthenticationEvent:
    def test_defaults(self) -> None:
        event = OCSFAuthenticationEvent()
        assert event.event_type == "authentication"
        assert event.user == ""
        assert event.action == "login"
        assert event.status == "unknown"

    def test_login_event(self) -> None:
        event = OCSFAuthenticationEvent(
            user="admin@example.com",
            src_ip="10.0.0.1",
            action="login",
            status="success",
        )
        assert event.user == "admin@example.com"
        assert event.src_ip == "10.0.0.1"
        assert event.status == "success"


class TestOCSFSecurityFinding:
    def test_defaults(self) -> None:
        event = OCSFSecurityFinding()
        assert event.event_type == "security_finding"
        assert event.finding_id == ""
        assert event.confidence == 0.0
        assert event.resources == []
        assert event.first_seen is None
        assert event.last_seen is None

    def test_with_resources(self) -> None:
        event = OCSFSecurityFinding(
            finding_id="FINDING-001",
            title="Suspicious activity",
            severity="high",
            confidence=85.0,
            resources=[{"type": "ec2", "uid": "i-12345"}],
        )
        assert event.finding_id == "FINDING-001"
        assert event.confidence == 85.0
        assert len(event.resources) == 1


class TestOCSFNetworkActivity:
    def test_defaults(self) -> None:
        event = OCSFNetworkActivity()
        assert event.event_type == "network_activity"
        assert event.src_port == 0
        assert event.dst_port == 0
        assert event.bytes_in == 0
        assert event.action == "allow"

    def test_flow(self) -> None:
        event = OCSFNetworkActivity(
            src_ip="10.0.0.1",
            src_port=54321,
            dst_ip="10.0.0.2",
            dst_port=443,
            protocol="tcp",
            bytes_in=1024,
            bytes_out=2048,
            action="allow",
        )
        assert event.protocol == "tcp"
        assert event.bytes_in == 1024


class TestOCSFAPIActivity:
    def test_defaults(self) -> None:
        event = OCSFAPIActivity()
        assert event.event_type == "api_activity"
        assert event.api_name == ""
        assert event.request_params == {}
        assert event.response_code == 0

    def test_api_call(self) -> None:
        event = OCSFAPIActivity(
            api_name="DescribeInstances",
            service="ec2.amazonaws.com",
            actor="arn:aws:iam::123456:user/admin",
            response_code=200,
        )
        assert event.api_name == "DescribeInstances"
        assert event.response_code == 200
