"""Tests for OCSF mapper registry and normalize entry point."""

from __future__ import annotations

from typing import Any

from shieldops.ingestion.ocsf.mapper import MapperRegistry, normalize
from shieldops.ingestion.ocsf.models import OCSFBaseEvent, OCSFSecurityFinding


class _DummyMapper:
    """Test mapper that wraps raw event into a SecurityFinding."""

    def map(self, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        return OCSFSecurityFinding(
            source_provider="dummy",
            source_type="test",
            raw_event=raw_event,
            finding_id="DUMMY-001",
            title="dummy finding",
        )


class _CrashingMapper:
    def map(self, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        raise RuntimeError("mapper crashed")


class TestMapperRegistry:
    def test_register_and_lookup(self) -> None:
        registry = MapperRegistry()
        mapper = _DummyMapper()
        registry.register("dummy", mapper)

        assert registry.get("dummy") is mapper
        assert "dummy" in registry.providers()

    def test_lookup_missing(self) -> None:
        registry = MapperRegistry()
        assert registry.get("nonexistent") is None

    def test_normalize_with_registered_mapper(self) -> None:
        registry = MapperRegistry()
        registry.register("dummy", _DummyMapper())

        result = registry.normalize("dummy", {"key": "val"})
        assert isinstance(result, OCSFSecurityFinding)
        assert result.finding_id == "DUMMY-001"
        assert result.raw_event == {"key": "val"}

    def test_normalize_unknown_provider(self) -> None:
        registry = MapperRegistry()
        raw = {"some": "data"}
        result = registry.normalize("unknown_vendor", raw)

        assert isinstance(result, OCSFBaseEvent)
        assert result.source_provider == "unknown_vendor"
        assert result.normalized == {}
        assert result.raw_event == raw

    def test_normalize_mapper_crash_returns_base_event(self) -> None:
        registry = MapperRegistry()
        registry.register("crasher", _CrashingMapper())

        result = registry.normalize("crasher", {"input": 1})
        assert isinstance(result, OCSFBaseEvent)
        assert result.source_type == "mapper_error"
        assert result.raw_event == {"input": 1}


class TestNormalizeEntryPoint:
    def test_cloudtrail_via_global(self) -> None:
        """The global normalize() function should find the cloudtrail mapper."""
        raw = {
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "userIdentity": {"arn": "arn:aws:iam::123:user/admin"},
            "eventTime": "2026-01-15T10:00:00Z",
        }
        result = normalize("cloudtrail", raw)
        assert result.source_provider == "cloudtrail"
        assert result.event_type == "api_activity"

    def test_unknown_via_global(self) -> None:
        result = normalize("some_unknown_source", {"data": 1})
        assert isinstance(result, OCSFBaseEvent)
        assert result.normalized == {}
