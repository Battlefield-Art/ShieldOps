"""Tests for shieldops.agents.cloud_posture."""

from __future__ import annotations

from shieldops.agents.cloud_posture.models import (
    BenchmarkFramework,
    CloudPostureState,
    CloudProvider,
    PostureStage,
)


class TestEnums:
    def test_posturestage_scan_cloud(self):
        assert PostureStage.SCAN_CLOUD == "scan_cloud"

    def test_posturestage_assess_benchmarks(self):
        assert PostureStage.ASSESS_BENCHMARKS == "assess_benchmarks"

    def test_posturestage_detect_misconfigs(self):
        assert PostureStage.DETECT_MISCONFIGS == "detect_misconfigs"

    def test_posturestage_prioritize_risks(self):
        assert PostureStage.PRIORITIZE_RISKS == "prioritize_risks"

    def test_cloudprovider_aws(self):
        assert CloudProvider.AWS == "aws"

    def test_cloudprovider_gcp(self):
        assert CloudProvider.GCP == "gcp"

    def test_cloudprovider_azure(self):
        assert CloudProvider.AZURE == "azure"

    def test_cloudprovider_kubernetes(self):
        assert CloudProvider.KUBERNETES == "kubernetes"

    def test_benchmarkframework_cis_aws(self):
        assert BenchmarkFramework.CIS_AWS == "cis_aws"

    def test_benchmarkframework_cis_gcp(self):
        assert BenchmarkFramework.CIS_GCP == "cis_gcp"

    def test_benchmarkframework_cis_azure(self):
        assert BenchmarkFramework.CIS_AZURE == "cis_azure"

    def test_benchmarkframework_cis_k8s(self):
        assert BenchmarkFramework.CIS_K8S == "cis_k8s"


class TestModels:
    def test_state_defaults(self):
        s = CloudPostureState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.cloud_posture.graph import (
            create_cloud_posture_graph,
        )

        sg = create_cloud_posture_graph()
        assert sg.compile() is not None
