"""Unit tests for endpoint_protection_manager agent models."""

from __future__ import annotations

from shieldops.agents.endpoint_protection_manager.models import (
    EndpointOS,
    EndpointProtectionManagerState,
    EPMStage,
    ProtectionStatus,
)


class TestEnums:
    def test_epm_stage_values(self) -> None:
        assert EPMStage.INVENTORY_ENDPOINTS == "inventory_endpoints"
        assert EPMStage.SCAN_MALWARE == "scan_malware"
        assert EPMStage.REPORT == "report"

    def test_endpoint_os_values(self) -> None:
        assert EndpointOS.WINDOWS == "windows"
        assert EndpointOS.LINUX == "linux"
        assert EndpointOS.MACOS == "macos"

    def test_protection_status_values(self) -> None:
        assert ProtectionStatus.PROTECTED == "protected"
        assert ProtectionStatus.UNPROTECTED == "unprotected"
        assert ProtectionStatus.QUARANTINED == "quarantined"


class TestState:
    def test_default_state(self) -> None:
        state = EndpointProtectionManagerState()
        assert state.request_id == ""
        assert state.stage == EPMStage.INVENTORY_ENDPOINTS
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = EndpointProtectionManagerState(
            request_id="req-001",
            tenant_id="t-001",
            stage=EPMStage.SCAN_MALWARE,
        )
        assert state.request_id == "req-001"
        assert state.stage == EPMStage.SCAN_MALWARE
