"""Tests for the connector health check framework.

Covers:
- ConnectorHealthStatus model
- ConnectorHealthCheck protocol compliance
- HealthCheckRegistry singleton, register/unregister, check, check_all
- Cache TTL behavior (second call within TTL returns cached result)
- Pre-execution hook with mixed healthy/unavailable connectors
- AllConnectorsUnavailableError when all connectors are down
- Individual health check wrapper classes
- API endpoint response shape
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.connectors.health import (
    AllConnectorsUnavailableError,
    AWSHealthCheck,
    ConnectorHealthCheck,
    ConnectorHealthStatus,
    ConnectorStatus,
    CrowdStrikeHealthCheck,
    HealthCheckRegistry,
    PagerDutyHealthCheck,
    ServiceNowHealthCheck,
    SlackHealthCheck,
    SplunkHealthCheck,
    check_agent_connectors,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class HealthyConnector:
    """A connector that always reports healthy."""

    async def check_health(self) -> ConnectorHealthStatus:
        return ConnectorHealthStatus(
            status=ConnectorStatus.HEALTHY,
            latency_ms=5.0,
            last_checked=datetime.now(UTC),
            message="all good",
        )


class DegradedConnector:
    """A connector that always reports degraded."""

    async def check_health(self) -> ConnectorHealthStatus:
        return ConnectorHealthStatus(
            status=ConnectorStatus.DEGRADED,
            latency_ms=250.0,
            last_checked=datetime.now(UTC),
            message="high latency",
        )


class UnavailableConnector:
    """A connector that always reports unavailable."""

    async def check_health(self) -> ConnectorHealthStatus:
        return ConnectorHealthStatus(
            status=ConnectorStatus.UNAVAILABLE,
            latency_ms=0.0,
            last_checked=datetime.now(UTC),
            message="connection refused",
        )


class ExplodingConnector:
    """A connector whose health check raises an exception."""

    async def check_health(self) -> ConnectorHealthStatus:
        raise ConnectionError("network unreachable")


@pytest.fixture(autouse=True)
def _reset_registry() -> None:
    """Reset the singleton registry before each test."""
    HealthCheckRegistry.reset()


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestConnectorHealthStatus:
    def test_defaults(self) -> None:
        s = ConnectorHealthStatus(status=ConnectorStatus.HEALTHY)
        assert s.status == ConnectorStatus.HEALTHY
        assert s.latency_ms == 0.0
        assert s.message == ""
        assert s.last_checked is not None

    def test_full_construction(self) -> None:
        now = datetime.now(UTC)
        s = ConnectorHealthStatus(
            status=ConnectorStatus.DEGRADED,
            latency_ms=123.45,
            last_checked=now,
            message="slow response",
        )
        assert s.status == ConnectorStatus.DEGRADED
        assert s.latency_ms == 123.45
        assert s.message == "slow response"


class TestConnectorStatusEnum:
    def test_values(self) -> None:
        assert ConnectorStatus.HEALTHY == "healthy"
        assert ConnectorStatus.DEGRADED == "degraded"
        assert ConnectorStatus.UNAVAILABLE == "unavailable"


# ---------------------------------------------------------------------------
# Protocol tests
# ---------------------------------------------------------------------------


class TestProtocol:
    def test_healthy_connector_implements_protocol(self) -> None:
        assert isinstance(HealthyConnector(), ConnectorHealthCheck)

    def test_object_without_method_does_not_implement(self) -> None:
        assert not isinstance(object(), ConnectorHealthCheck)


# ---------------------------------------------------------------------------
# Registry tests
# ---------------------------------------------------------------------------


class TestHealthCheckRegistry:
    def test_singleton(self) -> None:
        r1 = HealthCheckRegistry()
        r2 = HealthCheckRegistry()
        assert r1 is r2

    def test_register_and_list(self) -> None:
        reg = HealthCheckRegistry()
        reg.register("aws", HealthyConnector())
        reg.register("splunk", HealthyConnector())
        assert sorted(reg.registered_connectors) == ["aws", "splunk"]

    def test_unregister(self) -> None:
        reg = HealthCheckRegistry()
        reg.register("aws", HealthyConnector())
        reg.unregister("aws")
        assert reg.registered_connectors == []

    @pytest.mark.asyncio
    async def test_check_healthy(self) -> None:
        reg = HealthCheckRegistry()
        reg.register("test", HealthyConnector())
        result = await reg.check("test")
        assert result.status == ConnectorStatus.HEALTHY
        assert result.latency_ms == 5.0

    @pytest.mark.asyncio
    async def test_check_unregistered_raises(self) -> None:
        reg = HealthCheckRegistry()
        with pytest.raises(KeyError, match="not registered"):
            await reg.check("nonexistent")

    @pytest.mark.asyncio
    async def test_check_exception_returns_unavailable(self) -> None:
        reg = HealthCheckRegistry()
        reg.register("broken", ExplodingConnector())
        result = await reg.check("broken")
        assert result.status == ConnectorStatus.UNAVAILABLE
        assert "network unreachable" in result.message

    @pytest.mark.asyncio
    async def test_check_all_parallel(self) -> None:
        reg = HealthCheckRegistry()
        reg.register("a", HealthyConnector())
        reg.register("b", DegradedConnector())
        reg.register("c", UnavailableConnector())
        results = await reg.check_all()
        assert results["a"].status == ConnectorStatus.HEALTHY
        assert results["b"].status == ConnectorStatus.DEGRADED
        assert results["c"].status == ConnectorStatus.UNAVAILABLE

    @pytest.mark.asyncio
    async def test_check_all_empty(self) -> None:
        reg = HealthCheckRegistry()
        results = await reg.check_all()
        assert results == {}


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------


class TestCaching:
    @pytest.mark.asyncio
    async def test_cached_result_returned_within_ttl(self) -> None:
        """Second call within TTL should return cached result (same object)."""
        reg = HealthCheckRegistry()
        reg.cache_ttl = 30.0
        reg.register("test", HealthyConnector())

        result1 = await reg.check("test")
        result2 = await reg.check("test")
        # Should be the exact same object from cache
        assert result1 is result2

    @pytest.mark.asyncio
    async def test_cache_expired_gives_fresh_result(self) -> None:
        """After TTL expiry, a new health check should run."""
        reg = HealthCheckRegistry()
        reg.cache_ttl = 0.0  # immediate expiry
        reg.register("test", HealthyConnector())

        result1 = await reg.check("test")
        result2 = await reg.check("test")
        # With 0 TTL, each call should produce a new object
        assert result1 is not result2

    @pytest.mark.asyncio
    async def test_invalidate_clears_cache(self) -> None:
        reg = HealthCheckRegistry()
        reg.cache_ttl = 300.0  # long TTL
        reg.register("test", HealthyConnector())

        result1 = await reg.check("test")
        reg.invalidate("test")
        result2 = await reg.check("test")
        assert result1 is not result2

    @pytest.mark.asyncio
    async def test_invalidate_all(self) -> None:
        reg = HealthCheckRegistry()
        reg.cache_ttl = 300.0
        reg.register("a", HealthyConnector())
        reg.register("b", HealthyConnector())

        await reg.check("a")
        await reg.check("b")
        reg.invalidate_all()

        # Cache should be empty
        assert reg._cache == {}


# ---------------------------------------------------------------------------
# Pre-execution hook tests
# ---------------------------------------------------------------------------


class TestCheckAgentConnectors:
    @pytest.mark.asyncio
    async def test_all_healthy(self) -> None:
        reg = HealthCheckRegistry()
        reg.register("aws", HealthyConnector())
        reg.register("splunk", HealthyConnector())

        result = await check_agent_connectors("test_agent", ["aws", "splunk"])
        assert result["aws"].status == ConnectorStatus.HEALTHY
        assert result["splunk"].status == ConnectorStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_mixed_status_returns_partial(self) -> None:
        reg = HealthCheckRegistry()
        reg.register("aws", HealthyConnector())
        reg.register("splunk", UnavailableConnector())

        result = await check_agent_connectors("test_agent", ["aws", "splunk"])
        assert result["aws"].status == ConnectorStatus.HEALTHY
        assert result["splunk"].status == ConnectorStatus.UNAVAILABLE

    @pytest.mark.asyncio
    async def test_all_unavailable_raises(self) -> None:
        reg = HealthCheckRegistry()
        reg.register("aws", UnavailableConnector())
        reg.register("splunk", UnavailableConnector())

        with pytest.raises(AllConnectorsUnavailableError) as exc_info:
            await check_agent_connectors("test_agent", ["aws", "splunk"])
        assert "aws" in exc_info.value.connector_names
        assert "splunk" in exc_info.value.connector_names

    @pytest.mark.asyncio
    async def test_unregistered_connector_treated_as_unavailable(self) -> None:
        reg = HealthCheckRegistry()
        reg.register("aws", HealthyConnector())

        # "splunk" is not registered -> unavailable, but "aws" is healthy
        result = await check_agent_connectors("test_agent", ["aws", "splunk"])
        assert result["aws"].status == ConnectorStatus.HEALTHY
        assert result["splunk"].status == ConnectorStatus.UNAVAILABLE

    @pytest.mark.asyncio
    async def test_all_unregistered_raises(self) -> None:
        _reg = HealthCheckRegistry()
        with pytest.raises(AllConnectorsUnavailableError):
            await check_agent_connectors("test_agent", ["x", "y"])

    @pytest.mark.asyncio
    async def test_empty_connectors_returns_empty(self) -> None:
        result = await check_agent_connectors("test_agent", [])
        assert result == {}


# ---------------------------------------------------------------------------
# Health check implementation tests
# ---------------------------------------------------------------------------


class TestAWSHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy(self) -> None:
        mock_connector = MagicMock()
        mock_connector._region = "us-east-1"
        mock_connector._ensure_clients = MagicMock()

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456"}

        with patch("boto3.client", return_value=mock_sts):
            hc = AWSHealthCheck(mock_connector)
            result = await hc.check_health()

        assert result.status == ConnectorStatus.HEALTHY
        assert result.latency_ms > 0
        assert "STS" in result.message

    @pytest.mark.asyncio
    async def test_unavailable(self) -> None:
        mock_connector = MagicMock()
        mock_connector._region = "us-east-1"
        mock_connector._ensure_clients = MagicMock()

        with patch("boto3.client", side_effect=Exception("no credentials")):
            hc = AWSHealthCheck(mock_connector)
            result = await hc.check_health()

        assert result.status == ConnectorStatus.UNAVAILABLE
        assert "no credentials" in result.message


class TestCrowdStrikeHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy(self) -> None:
        mock_connector = MagicMock()
        mock_connector._ensure_auth = AsyncMock()
        hc = CrowdStrikeHealthCheck(mock_connector)
        result = await hc.check_health()
        assert result.status == ConnectorStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_unavailable(self) -> None:
        mock_connector = MagicMock()
        mock_connector._ensure_auth = AsyncMock(side_effect=Exception("auth failed"))
        hc = CrowdStrikeHealthCheck(mock_connector)
        result = await hc.check_health()
        assert result.status == ConnectorStatus.UNAVAILABLE


class TestSplunkHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy(self) -> None:
        mock_connector = MagicMock()
        mock_connector._api_request = AsyncMock(
            return_value={
                "entry": [{"content": {"version": "9.1.2"}}],
            }
        )
        hc = SplunkHealthCheck(mock_connector)
        result = await hc.check_health()
        assert result.status == ConnectorStatus.HEALTHY
        assert "9.1.2" in result.message

    @pytest.mark.asyncio
    async def test_unavailable(self) -> None:
        mock_connector = MagicMock()
        mock_connector._api_request = AsyncMock(side_effect=Exception("timeout"))
        hc = SplunkHealthCheck(mock_connector)
        result = await hc.check_health()
        assert result.status == ConnectorStatus.UNAVAILABLE


class TestPagerDutyHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy(self) -> None:
        mock_connector = MagicMock()
        mock_connector._api_request = AsyncMock(return_value={"abilities": ["sso", "teams"]})
        hc = PagerDutyHealthCheck(mock_connector)
        result = await hc.check_health()
        assert result.status == ConnectorStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_unavailable(self) -> None:
        mock_connector = MagicMock()
        mock_connector._api_request = AsyncMock(side_effect=Exception("401"))
        hc = PagerDutyHealthCheck(mock_connector)
        result = await hc.check_health()
        assert result.status == ConnectorStatus.UNAVAILABLE


class TestSlackHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy(self) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"ok": True, "user": "shieldops-bot"}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            hc = SlackHealthCheck("xoxb-test-token")
            result = await hc.check_health()

        assert result.status == ConnectorStatus.HEALTHY
        assert "shieldops-bot" in result.message

    @pytest.mark.asyncio
    async def test_auth_failed(self) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"ok": False, "error": "invalid_auth"}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            hc = SlackHealthCheck("xoxb-bad-token")
            result = await hc.check_health()

        assert result.status == ConnectorStatus.UNAVAILABLE
        assert "invalid_auth" in result.message


class TestServiceNowHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy(self) -> None:
        mock_connector = MagicMock()
        mock_connector._api_request = AsyncMock(return_value={"result": [{"sys_id": "abc"}]})
        hc = ServiceNowHealthCheck(mock_connector)
        result = await hc.check_health()
        assert result.status == ConnectorStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_unavailable(self) -> None:
        mock_connector = MagicMock()
        mock_connector._api_request = AsyncMock(side_effect=Exception("connection refused"))
        hc = ServiceNowHealthCheck(mock_connector)
        result = await hc.check_health()
        assert result.status == ConnectorStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# API endpoint test
# ---------------------------------------------------------------------------


class TestConnectorHealthAPI:
    @pytest.mark.asyncio
    async def test_endpoint_response_shape(self) -> None:
        """Verify the API route handler returns the expected response shape."""
        reg = HealthCheckRegistry()
        reg.register("aws", HealthyConnector())
        reg.register("splunk", UnavailableConnector())

        # Import and call the route handler directly
        from shieldops.api.routes.connector_health import get_connector_health

        mock_user = MagicMock()
        result = await get_connector_health(_user=mock_user)

        assert result["total"] == 2
        assert result["healthy"] == 1
        assert result["unavailable"] == 1
        assert result["degraded"] == 0
        assert len(result["connectors"]) == 2

        # Check connector entries have required fields
        for entry in result["connectors"]:
            assert "connector_name" in entry
            assert "status" in entry
            assert "latency_ms" in entry
            assert "last_checked" in entry


# ---------------------------------------------------------------------------
# AllConnectorsUnavailableError tests
# ---------------------------------------------------------------------------


class TestAllConnectorsUnavailableError:
    def test_message(self) -> None:
        err = AllConnectorsUnavailableError(["aws", "splunk"])
        assert "aws" in str(err)
        assert "splunk" in str(err)
        assert err.connector_names == ["aws", "splunk"]
