"""Tests for shieldops.agents.unified_cloud_security."""

from __future__ import annotations

from shieldops.agents.unified_cloud_security.models import (
    CloudPlatform,
    CloudSecStage,
    SecurityFunction,
    UnifiedCloudSecurityState,
)


class TestEnums:
    def test_cloudsecstage_collect_cloud_state(self):
        assert CloudSecStage.COLLECT_CLOUD_STATE == "collect_cloud_state"

    def test_cloudsecstage_assess_posture(self):
        assert CloudSecStage.ASSESS_POSTURE == "assess_posture"

    def test_cloudsecstage_detect_threats(self):
        assert CloudSecStage.DETECT_THREATS == "detect_threats"

    def test_cloudsecstage_prioritize_risks(self):
        assert CloudSecStage.PRIORITIZE_RISKS == "prioritize_risks"

    def test_cloudplatform_aws(self):
        assert CloudPlatform.AWS == "aws"

    def test_cloudplatform_gcp(self):
        assert CloudPlatform.GCP == "gcp"

    def test_cloudplatform_azure(self):
        assert CloudPlatform.AZURE == "azure"

    def test_cloudplatform_kubernetes(self):
        assert CloudPlatform.KUBERNETES == "kubernetes"

    def test_securityfunction_cspm(self):
        assert SecurityFunction.CSPM == "cspm"

    def test_securityfunction_cwpp(self):
        assert SecurityFunction.CWPP == "cwpp"

    def test_securityfunction_cdr(self):
        assert SecurityFunction.CDR == "cdr"

    def test_securityfunction_ciem(self):
        assert SecurityFunction.CIEM == "ciem"


class TestModels:
    def test_state_defaults(self):
        s = UnifiedCloudSecurityState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.unified_cloud_security.graph import (
            create_unified_cloud_security_graph,
        )

        sg = create_unified_cloud_security_graph()
        assert sg.compile() is not None
