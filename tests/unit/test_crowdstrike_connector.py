"""Comprehensive behavioral tests for the CrowdStrike Falcon connector.

Tests cover:
- Health checks (healthy device, not found, API error, various statuses)
- list_resources for hosts and detections (success, error, filtering)
- get_events (detection events within time range, empty, error)
- execute_action: rtr_command, update_prevention_policy, contain_host,
  unsupported action, API error
- create_snapshot (captures policies + host groups)
- rollback (valid snapshot, missing snapshot, API error during restore)
- validate_health polling (immediate success, timeout, polls-until-healthy)
- OAuth2 token lifecycle (initial auth, token refresh on expiry)
- Domain methods: get_detections, get_incidents, contain_host,
  lift_containment, get_threat_graph, query_iocs, close
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.connectors.crowdstrike.connector import CrowdStrikeConnector
from shieldops.models.base import (
    Environment,
    ExecutionStatus,
    RemediationAction,
    RiskLevel,
    TimeRange,
)

# ---------------------------------------------------------------------------
# Helpers & Fixtures
# ---------------------------------------------------------------------------


def _mock_response(json_data: dict[str, Any], status_code: int = 200) -> MagicMock:
    """Create a mock httpx.Response with json() and raise_for_status()."""
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.raise_for_status.return_value = None
    return resp


def _make_action(
    action_type: str,
    target: str = "device-abc123",
    parameters: dict[str, Any] | None = None,
) -> RemediationAction:
    return RemediationAction(
        id="action-001",
        action_type=action_type,
        target_resource=target,
        environment=Environment.PRODUCTION,
        risk_level=RiskLevel.HIGH,
        parameters=parameters or {},
        description=f"Test {action_type}",
    )


@pytest.fixture
def mock_http_client() -> AsyncMock:
    """Create a mock httpx.AsyncClient."""
    client = AsyncMock()
    # Default: return a valid OAuth2 token for any POST to /oauth2/token
    token_resp = _mock_response(
        {
            "access_token": "test-token-abc",
            "expires_in": 1799,
        }
    )
    client.post.return_value = token_resp
    client.request.return_value = _mock_response({})
    client.aclose.return_value = None
    return client


@pytest.fixture
def connector(mock_http_client: AsyncMock) -> CrowdStrikeConnector:
    """Create a CrowdStrikeConnector with a mock HTTP client injected."""
    conn = CrowdStrikeConnector(
        client_id="test-client-id",
        client_secret="test-client-secret",
        base_url="https://api.crowdstrike.com",
    )
    conn._http_client = mock_http_client
    return conn


@pytest.fixture
def time_range() -> TimeRange:
    now = datetime.now(UTC)
    return TimeRange(start=now - timedelta(hours=1), end=now)


def _setup_request_router(
    mock_client: AsyncMock,
    routes: dict[str, Any],
) -> None:
    """Configure mock_client.request to return different responses based on URL path.

    routes maps path substrings to response dicts. The first matching route wins.
    If a route value is an Exception, it will be raised.
    """

    async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
        for pattern, response in routes.items():
            if pattern in path:
                if isinstance(response, Exception):
                    raise response
                if isinstance(response, list):
                    # Pop the first response for sequential calls
                    resp = response.pop(0)
                    if isinstance(resp, Exception):
                        raise resp
                    return _mock_response(resp)
                return _mock_response(response)
        return _mock_response({})

    mock_client.request.side_effect = _route


# ============================================================================
# Health Checks
# ============================================================================


class TestHealth:
    @pytest.mark.asyncio
    async def test_healthy_device_normal_status(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Device with status 'normal' returns HealthStatus(healthy=True)."""
        _setup_request_router(
            mock_http_client,
            {
                "/devices/entities/devices/v2": {
                    "resources": [
                        {
                            "device_id": "dev-001",
                            "status": "normal",
                            "last_seen": "2026-04-01T12:00:00Z",
                            "prevention_policy_applied": True,
                        }
                    ]
                }
            },
        )

        health = await connector.get_health("dev-001")

        assert health.healthy is True
        assert health.status == "normal"
        assert health.resource_id == "dev-001"
        assert health.metrics["prevention_policy_applied"] == 1.0
        assert health.last_checked is not None

    @pytest.mark.asyncio
    async def test_healthy_device_online_status(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Device with status 'online' is also healthy."""
        _setup_request_router(
            mock_http_client,
            {
                "/devices/entities/devices/v2": {
                    "resources": [{"device_id": "dev-002", "status": "online"}]
                }
            },
        )

        health = await connector.get_health("dev-002")

        assert health.healthy is True
        assert health.status == "online"

    @pytest.mark.asyncio
    async def test_healthy_device_contained_status(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Device with status 'contained' is considered healthy."""
        _setup_request_router(
            mock_http_client,
            {
                "/devices/entities/devices/v2": {
                    "resources": [{"device_id": "dev-003", "status": "contained"}]
                }
            },
        )

        health = await connector.get_health("dev-003")

        assert health.healthy is True
        assert health.status == "contained"

    @pytest.mark.asyncio
    async def test_unhealthy_device_offline_status(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Device with non-healthy status returns healthy=False."""
        _setup_request_router(
            mock_http_client,
            {
                "/devices/entities/devices/v2": {
                    "resources": [{"device_id": "dev-004", "status": "offline"}]
                }
            },
        )

        health = await connector.get_health("dev-004")

        assert health.healthy is False
        assert health.status == "offline"

    @pytest.mark.asyncio
    async def test_device_not_found_empty_resources(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Empty resources array returns healthy=False, status='not_found'."""
        _setup_request_router(mock_http_client, {"/devices/entities/devices/v2": {"resources": []}})

        health = await connector.get_health("dev-missing")

        assert health.healthy is False
        assert health.status == "not_found"
        assert health.resource_id == "dev-missing"
        assert "not found" in (health.message or "").lower()

    @pytest.mark.asyncio
    async def test_api_error_returns_unhealthy(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """API exception returns healthy=False, status='error'."""
        _setup_request_router(
            mock_http_client, {"/devices/entities/devices/v2": Exception("ConnectionTimeout")}
        )

        health = await connector.get_health("dev-001")

        assert health.healthy is False
        assert health.status == "error"
        assert "ConnectionTimeout" in (health.message or "")

    @pytest.mark.asyncio
    async def test_health_unknown_status_is_unhealthy(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Device with unknown status string is unhealthy."""
        _setup_request_router(
            mock_http_client,
            {
                "/devices/entities/devices/v2": {
                    "resources": [{"device_id": "dev-005", "status": "unknown"}]
                }
            },
        )

        health = await connector.get_health("dev-005")

        assert health.healthy is False

    @pytest.mark.asyncio
    async def test_health_missing_status_field(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Device dict without 'status' key defaults to 'unknown' and is unhealthy."""
        _setup_request_router(
            mock_http_client,
            {"/devices/entities/devices/v2": {"resources": [{"device_id": "dev-006"}]}},
        )

        health = await connector.get_health("dev-006")

        assert health.healthy is False
        assert health.status == "unknown"

    @pytest.mark.asyncio
    async def test_health_last_checked_is_recent(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """last_checked should be within a few seconds of now."""
        _setup_request_router(
            mock_http_client,
            {
                "/devices/entities/devices/v2": {
                    "resources": [{"device_id": "dev-001", "status": "normal"}]
                }
            },
        )

        health = await connector.get_health("dev-001")

        delta = datetime.now(UTC) - health.last_checked
        assert delta.total_seconds() < 5

    @pytest.mark.asyncio
    async def test_health_prevention_policy_not_applied(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """prevention_policy_applied=False produces metric 0.0."""
        _setup_request_router(
            mock_http_client,
            {
                "/devices/entities/devices/v2": {
                    "resources": [
                        {
                            "device_id": "dev-007",
                            "status": "normal",
                            "prevention_policy_applied": False,
                        }
                    ]
                }
            },
        )

        health = await connector.get_health("dev-007")

        assert health.metrics["prevention_policy_applied"] == 0.0


# ============================================================================
# List Resources
# ============================================================================


class TestListResources:
    @pytest.mark.asyncio
    async def test_list_hosts_returns_resources(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Listing hosts performs scroll query then fetches device details."""
        call_count = 0

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            nonlocal call_count
            if "devices-scroll" in path:
                return _mock_response({"resources": ["dev-001", "dev-002"]})
            if "/devices/entities/devices/v2" in path:
                return _mock_response(
                    {
                        "resources": [
                            {
                                "device_id": "dev-001",
                                "hostname": "web-server-01",
                                "platform_name": "Linux",
                                "os_version": "Ubuntu 22.04",
                                "agent_version": "7.10.0",
                                "last_seen": "2026-04-01T12:00:00Z",
                                "status": "normal",
                            },
                            {
                                "device_id": "dev-002",
                                "hostname": "db-server-01",
                                "platform_name": "Windows",
                                "os_version": "Server 2022",
                                "agent_version": "7.10.0",
                                "last_seen": "2026-04-01T11:00:00Z",
                                "status": "online",
                            },
                        ]
                    }
                )
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        resources = await connector.list_resources("host", Environment.PRODUCTION)

        assert len(resources) == 2
        assert resources[0].id == "dev-001"
        assert resources[0].name == "web-server-01"
        assert resources[0].resource_type == "host"
        assert resources[0].provider == "crowdstrike"
        assert resources[0].environment == Environment.PRODUCTION
        assert resources[0].labels["platform"] == "Linux"
        assert resources[0].labels["os_version"] == "Ubuntu 22.04"
        assert resources[0].metadata["agent_version"] == "7.10.0"
        assert resources[0].metadata["status"] == "normal"

    @pytest.mark.asyncio
    async def test_list_devices_alias(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """resource_type 'device' is treated the same as 'host'."""

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "devices-scroll" in path:
                return _mock_response({"resources": ["dev-001"]})
            if "/devices/entities/devices/v2" in path:
                return _mock_response(
                    {"resources": [{"device_id": "dev-001", "hostname": "srv-01"}]}
                )
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        resources = await connector.list_resources("device", Environment.STAGING)

        assert len(resources) == 1
        assert resources[0].resource_type == "host"

    @pytest.mark.asyncio
    async def test_list_detections_returns_resources(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Listing detections queries detection IDs and wraps them as Resources."""
        _setup_request_router(
            mock_http_client,
            {"/detects/queries/detects/v1": {"resources": ["ldt:abc:123", "ldt:abc:456"]}},
        )

        resources = await connector.list_resources("detection", Environment.PRODUCTION)

        assert len(resources) == 2
        assert resources[0].id == "ldt:abc:123"
        assert resources[0].resource_type == "detection"
        assert resources[0].provider == "crowdstrike"

    @pytest.mark.asyncio
    async def test_list_hosts_empty_scroll(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """When scroll returns no device IDs, result is empty."""
        _setup_request_router(mock_http_client, {"devices-scroll": {"resources": []}})

        resources = await connector.list_resources("host", Environment.DEVELOPMENT)

        assert resources == []

    @pytest.mark.asyncio
    async def test_list_resources_api_error_returns_empty(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """API errors during listing are caught, returning empty list."""
        _setup_request_router(mock_http_client, {"devices-scroll": Exception("RateLimitExceeded")})

        resources = await connector.list_resources("host", Environment.PRODUCTION)

        assert resources == []

    @pytest.mark.asyncio
    async def test_list_unsupported_type_returns_empty(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Unsupported resource_type returns empty list without error."""
        resources = await connector.list_resources("firewall", Environment.PRODUCTION)

        assert resources == []

    @pytest.mark.asyncio
    async def test_list_hosts_with_fql_filter(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """FQL filter from filters dict is passed to the scroll query."""
        captured_params: list[dict] = []

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "devices-scroll" in path:
                captured_params.append(kwargs.get("params", {}))
                return _mock_response({"resources": []})
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        await connector.list_resources(
            "host",
            Environment.PRODUCTION,
            filters={"fql": "platform_name:'Linux'"},
        )

        assert len(captured_params) == 1
        assert captured_params[0]["filter"] == "platform_name:'Linux'"


# ============================================================================
# Get Events
# ============================================================================


class TestGetEvents:
    @pytest.mark.asyncio
    async def test_get_events_returns_detection_details(
        self,
        connector: CrowdStrikeConnector,
        mock_http_client: AsyncMock,
        time_range: TimeRange,
    ) -> None:
        """Events query returns detection details for a device in time range."""

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/detects/queries/detects/v1" in path:
                return _mock_response({"resources": ["ldt:abc:1", "ldt:abc:2"]})
            if "/detects/entities/summaries" in path:
                return _mock_response(
                    {
                        "resources": [
                            {"detection_id": "ldt:abc:1", "severity": 5, "tactic": "Execution"},
                            {"detection_id": "ldt:abc:2", "severity": 3, "tactic": "Discovery"},
                        ]
                    }
                )
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        events = await connector.get_events("dev-001", time_range)

        assert len(events) == 2
        assert events[0]["detection_id"] == "ldt:abc:1"
        assert events[1]["tactic"] == "Discovery"

    @pytest.mark.asyncio
    async def test_get_events_no_detections(
        self,
        connector: CrowdStrikeConnector,
        mock_http_client: AsyncMock,
        time_range: TimeRange,
    ) -> None:
        """No detections in time range returns empty list."""
        _setup_request_router(mock_http_client, {"/detects/queries/detects/v1": {"resources": []}})

        events = await connector.get_events("dev-001", time_range)

        assert events == []

    @pytest.mark.asyncio
    async def test_get_events_api_error_returns_empty(
        self,
        connector: CrowdStrikeConnector,
        mock_http_client: AsyncMock,
        time_range: TimeRange,
    ) -> None:
        """API error during event query returns empty list."""
        _setup_request_router(
            mock_http_client, {"/detects/queries/detects/v1": Exception("Forbidden")}
        )

        events = await connector.get_events("dev-001", time_range)

        assert events == []

    @pytest.mark.asyncio
    async def test_get_events_builds_fql_with_device_and_time(
        self,
        connector: CrowdStrikeConnector,
        mock_http_client: AsyncMock,
        time_range: TimeRange,
    ) -> None:
        """FQL filter includes device_id and time range boundaries."""
        captured_params: dict = {}

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/detects/queries/detects/v1" in path:
                captured_params.update(kwargs.get("params", {}))
                return _mock_response({"resources": []})
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        await connector.get_events("dev-xyz", time_range)

        fql = captured_params.get("filter", "")
        assert "dev-xyz" in fql
        assert "created_timestamp" in fql


# ============================================================================
# Execute Action
# ============================================================================


class TestExecuteAction:
    @pytest.mark.asyncio
    async def test_rtr_command_succeeds(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """RTR command action returns SUCCESS with stdout in message."""
        _setup_request_router(
            mock_http_client,
            {
                "/real-time-response/entities/command/v1": {
                    "resources": [{"stdout": "Process killed successfully"}]
                }
            },
        )
        action = _make_action(
            "rtr_command",
            parameters={"command": "kill", "command_string": "kill -9 1234"},
        )

        result = await connector.execute_action(action)

        assert result.status == ExecutionStatus.SUCCESS
        assert "Process killed successfully" in result.message
        assert result.action_id == "action-001"
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.completed_at >= result.started_at

    @pytest.mark.asyncio
    async def test_update_prevention_policy_succeeds(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Policy update action returns SUCCESS."""
        _setup_request_router(
            mock_http_client, {"/policy/entities/prevention/v1": {"resources": [{"id": "pol-001"}]}}
        )
        action = _make_action(
            "update_prevention_policy",
            parameters={"policy_body": {"id": "pol-001", "enabled": True}},
        )

        result = await connector.execute_action(action)

        assert result.status == ExecutionStatus.SUCCESS
        assert "policy updated" in result.message.lower()

    @pytest.mark.asyncio
    async def test_contain_host_action_succeeds(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Contain host action delegates to contain_host method and returns SUCCESS."""
        _setup_request_router(
            mock_http_client,
            {"/devices/entities/devices-actions/v2": {"resources": [{"id": "dev-001"}]}},
        )
        action = _make_action("contain_host", target="dev-001")

        result = await connector.execute_action(action)

        assert result.status == ExecutionStatus.SUCCESS
        assert "dev-001" in result.message
        assert "contained" in result.message.lower()

    @pytest.mark.asyncio
    async def test_unsupported_action_returns_failed(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Unknown action type returns FAILED with descriptive message."""
        action = _make_action("delete_everything")

        result = await connector.execute_action(action)

        assert result.status == ExecutionStatus.FAILED
        assert "Unsupported action type" in result.message
        assert "delete_everything" in result.message

    @pytest.mark.asyncio
    async def test_action_api_error_returns_failed(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """API error during action execution returns FAILED with error details."""
        _setup_request_router(
            mock_http_client, {"/real-time-response": Exception("UnauthorizedAccess")}
        )
        action = _make_action("rtr_command", parameters={"command": "ls"})

        result = await connector.execute_action(action)

        assert result.status == ExecutionStatus.FAILED
        assert result.error is not None
        assert "UnauthorizedAccess" in result.error

    @pytest.mark.asyncio
    async def test_action_timestamps_present(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Both started_at and completed_at are populated on all results."""
        action = _make_action("unsupported_type")

        result = await connector.execute_action(action)

        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.completed_at >= result.started_at

    @pytest.mark.asyncio
    async def test_action_id_propagated(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """action_id on the result matches the input action's id."""
        action = _make_action("unsupported_type")

        result = await connector.execute_action(action)

        assert result.action_id == "action-001"


# ============================================================================
# Snapshot & Rollback
# ============================================================================


class TestSnapshotRollback:
    @pytest.mark.asyncio
    async def test_create_snapshot_captures_policies_and_host_groups(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Snapshot captures prevention policies and host group IDs."""

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/policy/queries/prevention/v1" in path:
                return _mock_response({"resources": ["pol-001", "pol-002"]})
            if "/policy/entities/prevention/v1" in path:
                return _mock_response(
                    {
                        "resources": [
                            {"id": "pol-001", "name": "Default", "enabled": True},
                            {"id": "pol-002", "name": "Strict", "enabled": True},
                        ]
                    }
                )
            if "/devices/queries/host-groups/v1" in path:
                return _mock_response({"resources": ["hg-001", "hg-002"]})
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        snapshot = await connector.create_snapshot("dev-001")

        assert snapshot.resource_id == "dev-001"
        assert snapshot.snapshot_type == "crowdstrike_config"
        assert snapshot.created_at is not None
        assert snapshot.id in connector._snapshots
        state = connector._snapshots[snapshot.id]
        assert len(state["prevention_policies"]) == 2
        assert state["prevention_policies"][0]["id"] == "pol-001"
        assert state["host_group_ids"] == ["hg-001", "hg-002"]
        assert "captured_at" in state

    @pytest.mark.asyncio
    async def test_create_snapshot_no_policies(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Snapshot with no policies stores empty list."""

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/policy/queries/prevention/v1" in path:
                return _mock_response({"resources": []})
            if "/devices/queries/host-groups/v1" in path:
                return _mock_response({"resources": []})
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        snapshot = await connector.create_snapshot("dev-empty")

        state = connector._snapshots[snapshot.id]
        assert state["prevention_policies"] == []
        assert state["host_group_ids"] == []

    @pytest.mark.asyncio
    async def test_rollback_valid_snapshot_restores_policies(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Rollback with a valid snapshot PATCHes each policy and returns SUCCESS."""
        connector._snapshots["snap-001"] = {
            "prevention_policies": [
                {"id": "pol-001", "name": "Default", "enabled": True},
                {"id": "pol-002", "name": "Strict", "enabled": False},
            ],
            "host_group_ids": ["hg-001"],
            "captured_at": "2026-04-01T12:00:00",
        }
        patch_calls: list[dict] = []

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/policy/entities/prevention/v1" in path:
                patch_calls.append(kwargs.get("json", {}))
                return _mock_response({"resources": []})
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        result = await connector.rollback("snap-001")

        assert result.status == ExecutionStatus.SUCCESS
        assert result.snapshot_id == "snap-001"
        assert "restored" in result.message.lower()
        # Should have PATCHed each policy
        assert len(patch_calls) == 2

    @pytest.mark.asyncio
    async def test_rollback_missing_snapshot_returns_failed(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Rollback with nonexistent snapshot_id returns FAILED."""
        result = await connector.rollback("snap-nonexistent")

        assert result.status == ExecutionStatus.FAILED
        assert "not found" in result.message.lower()
        assert result.action_id == "snap-nonexistent"

    @pytest.mark.asyncio
    async def test_rollback_api_error_returns_failed(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """API error during rollback returns FAILED with error detail."""
        connector._snapshots["snap-err"] = {
            "prevention_policies": [{"id": "pol-001"}],
            "host_group_ids": [],
        }
        _setup_request_router(
            mock_http_client, {"/policy/entities/prevention/v1": Exception("ServiceUnavailable")}
        )

        result = await connector.rollback("snap-err")

        assert result.status == ExecutionStatus.FAILED
        assert "ServiceUnavailable" in (result.error or result.message)

    @pytest.mark.asyncio
    async def test_rollback_has_timestamps(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Both success and failure rollbacks have started_at and completed_at."""
        result = await connector.rollback("snap-missing")

        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.completed_at >= result.started_at


# ============================================================================
# Validate Health (polling)
# ============================================================================


class TestValidateHealth:
    @pytest.mark.asyncio
    async def test_returns_true_when_immediately_healthy(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """When device is already healthy, returns True immediately."""
        _setup_request_router(
            mock_http_client,
            {
                "/devices/entities/devices/v2": {
                    "resources": [{"device_id": "dev-001", "status": "normal"}]
                }
            },
        )

        result = await connector.validate_health("dev-001", timeout_seconds=5)

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_timeout(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """With zero timeout and unhealthy device, returns False."""
        _setup_request_router(
            mock_http_client,
            {
                "/devices/entities/devices/v2": {
                    "resources": [{"device_id": "dev-001", "status": "offline"}]
                }
            },
        )

        with patch(
            "shieldops.connectors.crowdstrike.connector.asyncio.sleep",
            new_callable=AsyncMock,
        ):
            result = await connector.validate_health("dev-001", timeout_seconds=0)

        assert result is False

    @pytest.mark.asyncio
    async def test_polls_until_healthy(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """validate_health retries and eventually succeeds when device becomes healthy."""
        call_count = 0
        unhealthy_resp = {"resources": [{"device_id": "dev-001", "status": "offline"}]}
        healthy_resp = {"resources": [{"device_id": "dev-001", "status": "normal"}]}

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            nonlocal call_count
            if "/devices/entities/devices/v2" in path:
                call_count += 1
                if call_count >= 3:
                    return _mock_response(healthy_resp)
                return _mock_response(unhealthy_resp)
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        with patch(
            "shieldops.connectors.crowdstrike.connector.asyncio.sleep",
            new_callable=AsyncMock,
        ):
            result = await connector.validate_health("dev-001", timeout_seconds=120)

        assert result is True
        assert call_count >= 3


# ============================================================================
# OAuth2 Authentication
# ============================================================================


class TestAuth:
    @pytest.mark.asyncio
    async def test_auth_token_obtained_before_first_api_call(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """First API call triggers OAuth2 token request."""
        token_resp = _mock_response(
            {
                "access_token": "fresh-token-xyz",
                "expires_in": 1799,
            }
        )
        mock_http_client.post.return_value = token_resp
        mock_http_client.request.return_value = _mock_response({"resources": []})

        await connector.get_detections()

        # Token request should have been made
        mock_http_client.post.assert_called_once()
        call_args = mock_http_client.post.call_args
        assert call_args[0][0] == "/oauth2/token"
        # Subsequent request should carry the bearer token
        request_call = mock_http_client.request.call_args
        assert "Bearer fresh-token-xyz" in str(request_call)

    @pytest.mark.asyncio
    async def test_token_cached_on_subsequent_calls(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Token is reused when not expired."""
        mock_http_client.post.return_value = _mock_response(
            {
                "access_token": "cached-token",
                "expires_in": 1799,
            }
        )
        mock_http_client.request.return_value = _mock_response({"resources": []})

        await connector.get_detections()
        await connector.get_detections()

        # Only one token request despite two API calls
        assert mock_http_client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_token_refresh_when_expired(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Token is refreshed when within 60 seconds of expiry."""
        mock_http_client.post.return_value = _mock_response(
            {
                "access_token": "refreshed-token",
                "expires_in": 1799,
            }
        )
        mock_http_client.request.return_value = _mock_response({"resources": []})

        # Simulate an expired token
        connector._access_token = "old-expired-token"
        connector._token_expires_at = time.time() - 10  # Already expired

        await connector.get_detections()

        # Should have requested a new token
        mock_http_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_token_refresh_within_60s_window(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """Token is refreshed when expiry is less than 60 seconds away."""
        mock_http_client.post.return_value = _mock_response(
            {
                "access_token": "renewed-token",
                "expires_in": 1799,
            }
        )
        mock_http_client.request.return_value = _mock_response({"resources": []})

        # Token expires in 30 seconds (within the 60s refresh window)
        connector._access_token = "soon-expiring-token"
        connector._token_expires_at = time.time() + 30

        await connector.get_detections()

        # Should have refreshed
        mock_http_client.post.assert_called_once()


# ============================================================================
# Domain Methods
# ============================================================================


class TestDomainMethods:
    @pytest.mark.asyncio
    async def test_get_detections_with_results(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """get_detections returns detail objects via two-phase query."""

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/detects/queries/detects/v1" in path:
                return _mock_response({"resources": ["ldt:1", "ldt:2"]})
            if "/detects/entities/summaries" in path:
                return _mock_response(
                    {
                        "resources": [
                            {"detection_id": "ldt:1", "severity": 5},
                            {"detection_id": "ldt:2", "severity": 2},
                        ]
                    }
                )
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        detections = await connector.get_detections(
            filter_query="severity:>=3",
            limit=50,
        )

        assert len(detections) == 2
        assert detections[0]["detection_id"] == "ldt:1"

    @pytest.mark.asyncio
    async def test_get_detections_no_results(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """get_detections returns empty list when no IDs found."""
        _setup_request_router(mock_http_client, {"/detects/queries/detects/v1": {"resources": []}})

        detections = await connector.get_detections()

        assert detections == []

    @pytest.mark.asyncio
    async def test_get_incidents_with_results(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """get_incidents uses two-phase query and returns incident details."""

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/incidents/queries/incidents/v1" in path:
                return _mock_response({"resources": ["inc:001"]})
            if "/incidents/entities/incidents" in path:
                return _mock_response({"resources": [{"incident_id": "inc:001", "state": "open"}]})
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        incidents = await connector.get_incidents()

        assert len(incidents) == 1
        assert incidents[0]["incident_id"] == "inc:001"

    @pytest.mark.asyncio
    async def test_get_incidents_no_results(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """get_incidents returns empty list when no incident IDs found."""
        _setup_request_router(
            mock_http_client, {"/incidents/queries/incidents/v1": {"resources": []}}
        )

        incidents = await connector.get_incidents()

        assert incidents == []

    @pytest.mark.asyncio
    async def test_contain_host_calls_correct_endpoint(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """contain_host POSTs to devices-actions/v2 with action_name=contain."""
        captured: dict[str, Any] = {}

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/devices/entities/devices-actions/v2" in path:
                captured["method"] = method
                captured["params"] = kwargs.get("params", {})
                captured["json"] = kwargs.get("json", {})
                return _mock_response({"resources": [{"id": "dev-target"}]})
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        await connector.contain_host("dev-target")

        assert captured["method"] == "POST"
        assert captured["params"]["action_name"] == "contain"
        assert captured["json"]["ids"] == ["dev-target"]

    @pytest.mark.asyncio
    async def test_lift_containment_calls_correct_endpoint(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """lift_containment POSTs with action_name=lift_containment."""
        captured: dict[str, Any] = {}

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/devices/entities/devices-actions/v2" in path:
                captured["params"] = kwargs.get("params", {})
                captured["json"] = kwargs.get("json", {})
                return _mock_response({"resources": [{"id": "dev-target"}]})
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        await connector.lift_containment("dev-target")

        assert captured["params"]["action_name"] == "lift_containment"
        assert captured["json"]["ids"] == ["dev-target"]

    @pytest.mark.asyncio
    async def test_get_threat_graph(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """get_threat_graph queries the threat graph API with indicator param."""
        captured_params: dict = {}

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/threatgraph/queries/indicators/v1" in path:
                captured_params.update(kwargs.get("params", {}))
                return _mock_response(
                    {"resources": [{"indicator": "8.8.8.8", "type": "ip_address"}]}
                )
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        result = await connector.get_threat_graph("8.8.8.8")

        assert captured_params["indicator"] == "8.8.8.8"
        assert "resources" in result

    @pytest.mark.asyncio
    async def test_query_iocs_builds_fql_with_type_and_value(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """query_iocs builds FQL filter from ioc_type and value."""
        captured_params: dict = {}

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/iocs/queries/indicators/v1" in path:
                captured_params.update(kwargs.get("params", {}))
                return _mock_response({"resources": ["ioc-001"]})
            if "/iocs/entities/indicators/v1" in path:
                return _mock_response(
                    {"resources": [{"id": "ioc-001", "type": "sha256", "value": "abc123"}]}
                )
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        iocs = await connector.query_iocs(ioc_type="sha256", value="abc123")

        assert len(iocs) == 1
        fql = captured_params.get("filter", "")
        assert "type:'sha256'" in fql
        assert "value:'abc123'" in fql

    @pytest.mark.asyncio
    async def test_query_iocs_type_only(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """query_iocs with only ioc_type filters by type only."""
        captured_params: dict = {}

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/iocs/queries/indicators/v1" in path:
                captured_params.update(kwargs.get("params", {}))
                return _mock_response({"resources": []})
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        iocs = await connector.query_iocs(ioc_type="domain")

        assert iocs == []
        fql = captured_params.get("filter", "")
        assert "type:'domain'" in fql
        assert "value:" not in fql

    @pytest.mark.asyncio
    async def test_query_iocs_no_filter(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """query_iocs with no type/value omits filter param."""
        captured_params: dict = {}

        async def _route(method: str, path: str, **kwargs: Any) -> MagicMock:
            if "/iocs/queries/indicators/v1" in path:
                captured_params.update(kwargs.get("params", {}))
                return _mock_response({"resources": []})
            return _mock_response({})

        mock_http_client.request.side_effect = _route

        iocs = await connector.query_iocs()

        assert iocs == []
        assert "filter" not in captured_params

    @pytest.mark.asyncio
    async def test_query_iocs_no_results(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """query_iocs returns empty list when no IOC IDs found."""
        _setup_request_router(mock_http_client, {"/iocs/queries/indicators/v1": {"resources": []}})

        iocs = await connector.query_iocs(ioc_type="ip", value="1.2.3.4")

        assert iocs == []

    @pytest.mark.asyncio
    async def test_close_closes_http_client(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """close() calls aclose() on the HTTP client and sets it to None."""
        await connector.close()

        mock_http_client.aclose.assert_called_once()
        assert connector._http_client is None

    @pytest.mark.asyncio
    async def test_close_when_no_client(
        self, connector: CrowdStrikeConnector, mock_http_client: AsyncMock
    ) -> None:
        """close() is safe to call when no HTTP client exists."""
        connector._http_client = None

        await connector.close()  # Should not raise


# ============================================================================
# Connector Initialization
# ============================================================================


class TestConnectorInit:
    def test_provider_is_crowdstrike(self) -> None:
        conn = CrowdStrikeConnector(client_id="id", client_secret="secret")
        assert conn.provider == "crowdstrike"

    def test_default_base_url(self) -> None:
        conn = CrowdStrikeConnector(client_id="id", client_secret="secret")
        assert conn._base_url == "https://api.crowdstrike.com"

    def test_custom_base_url_trailing_slash_stripped(self) -> None:
        conn = CrowdStrikeConnector(
            client_id="id",
            client_secret="secret",
            base_url="https://api.us-2.crowdstrike.com/",
        )
        assert conn._base_url == "https://api.us-2.crowdstrike.com"

    def test_snapshots_initialized_empty(self) -> None:
        conn = CrowdStrikeConnector(client_id="id", client_secret="secret")
        assert conn._snapshots == {}

    def test_token_initially_none(self) -> None:
        conn = CrowdStrikeConnector(client_id="id", client_secret="secret")
        assert conn._access_token is None
        assert conn._token_expires_at == 0.0

    def test_http_client_initially_none(self) -> None:
        conn = CrowdStrikeConnector(client_id="id", client_secret="secret")
        assert conn._http_client is None

    def test_import_from_package(self) -> None:
        from shieldops.connectors.crowdstrike import CrowdStrikeConnector as Imported

        assert Imported is CrowdStrikeConnector
