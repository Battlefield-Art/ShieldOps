"""Tests for shieldops.agents.cloud_workload_protector."""

from __future__ import annotations

from shieldops.agents.cloud_workload_protector.models import (
    CloudWorkloadProtectorState,
    WorkloadPlatform,
    WorkloadSeverity,
    WorkloadStage,
)


class TestEnums:
    def test_stage_inventory(self):
        assert WorkloadStage.INVENTORY_WORKLOADS == "inventory_workloads"

    def test_stage_runtime(self):
        assert WorkloadStage.MONITOR_RUNTIME == "monitor_runtime"

    def test_stage_drift(self):
        assert WorkloadStage.DETECT_DRIFT == "detect_drift"

    def test_stage_vulns(self):
        assert WorkloadStage.SCAN_VULNERABILITIES == "scan_vulnerabilities"

    def test_stage_risk(self):
        assert WorkloadStage.ASSESS_RISK == "assess_risk"

    def test_stage_report(self):
        assert WorkloadStage.REPORT == "report"

    def test_platform_ec2(self):
        assert WorkloadPlatform.EC2 == "ec2"

    def test_platform_gce(self):
        assert WorkloadPlatform.GCE == "gce"

    def test_platform_azure_vm(self):
        assert WorkloadPlatform.AZURE_VM == "azure_vm"

    def test_severity_critical(self):
        assert WorkloadSeverity.CRITICAL == "critical"

    def test_severity_high(self):
        assert WorkloadSeverity.HIGH == "high"

    def test_severity_low(self):
        assert WorkloadSeverity.LOW == "low"


class TestState:
    def test_state_defaults(self):
        s = CloudWorkloadProtectorState()
        assert s.error == ""

    def test_state_request_id(self):
        s = CloudWorkloadProtectorState()
        assert s.request_id == ""

    def test_state_stage(self):
        s = CloudWorkloadProtectorState()
        assert s.stage == WorkloadStage.INVENTORY_WORKLOADS


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.cloud_workload_protector.graph import (
            create_cloud_workload_protector_graph,
        )

        sg = create_cloud_workload_protector_graph()
        assert sg.compile() is not None
