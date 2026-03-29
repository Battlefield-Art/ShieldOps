"""Tests for multi_cloud_compliance."""

from __future__ import annotations

from shieldops.agents.multi_cloud_compliance.models import (
    ComplianceFramework,
    ComplianceStage,
    ComplianceStatus,
    MultiCloudComplianceState,
)


class TestEnums:
    def test_complianceframework(self) -> None:
        assert ComplianceFramework.CIS_AWS == "cis_aws"
        assert len(ComplianceFramework) >= 3

    def test_compliancestage(self) -> None:
        assert ComplianceStage.COLLECT_CONFIGS == "collect_configs"
        assert len(ComplianceStage) >= 3

    def test_compliancestatus(self) -> None:
        assert ComplianceStatus.COMPLIANT == "compliant"
        assert len(ComplianceStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = MultiCloudComplianceState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = MultiCloudComplianceState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
