"""Tests for shieldops.agents.service_account_tracker."""

from __future__ import annotations

from shieldops.agents.service_account_tracker.models import (
    AccountStatus,
    CloudSource,
    ServiceAccountTrackerState,
    TrackerStage,
)


class TestEnums:
    def test_trackerstage_discover(self):
        assert TrackerStage.DISCOVER == "discover"

    def test_trackerstage_analyze_usage(self):
        assert TrackerStage.ANALYZE_USAGE == "analyze_usage"

    def test_trackerstage_detect_anomalies(self):
        assert TrackerStage.DETECT_ANOMALIES == "detect_anomalies"

    def test_trackerstage_classify_risk(self):
        assert TrackerStage.CLASSIFY_RISK == "classify_risk"

    def test_accountstatus_active(self):
        assert AccountStatus.ACTIVE == "active"

    def test_accountstatus_dormant(self):
        assert AccountStatus.DORMANT == "dormant"

    def test_accountstatus_orphaned(self):
        assert AccountStatus.ORPHANED == "orphaned"

    def test_accountstatus_shared(self):
        assert AccountStatus.SHARED == "shared"

    def test_cloudsource_aws_iam(self):
        assert CloudSource.AWS_IAM == "aws_iam"

    def test_cloudsource_gcp_iam(self):
        assert CloudSource.GCP_IAM == "gcp_iam"

    def test_cloudsource_azure_ad(self):
        assert CloudSource.AZURE_AD == "azure_ad"

    def test_cloudsource_kubernetes_sa(self):
        assert CloudSource.KUBERNETES_SA == "kubernetes_sa"


class TestModels:
    def test_state_defaults(self):
        s = ServiceAccountTrackerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.service_account_tracker.graph import (
            create_service_account_tracker_graph,
        )

        sg = create_service_account_tracker_graph()
        assert sg.compile() is not None
