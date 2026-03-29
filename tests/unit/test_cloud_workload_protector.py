"""Tests for cloud_workload_protector."""

from __future__ import annotations

from shieldops.agents.cloud_workload_protector.models import (
    CloudWorkloadProtectorState,
    WorkloadPlatform,
    WorkloadSeverity,
)


class TestEnums:
    def test_workloadplatform(self) -> None:
        assert WorkloadPlatform.EC2 == "ec2"
        assert len(WorkloadPlatform) >= 3

    def test_workloadseverity(self) -> None:
        assert WorkloadSeverity.CRITICAL == "critical"
        assert len(WorkloadSeverity) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CloudWorkloadProtectorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CloudWorkloadProtectorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
