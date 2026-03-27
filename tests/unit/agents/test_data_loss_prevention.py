"""Tests for shieldops.agents.data_loss_prevention."""

from __future__ import annotations

from shieldops.agents.data_loss_prevention.models import (
    DataLossPreventionState,
    DataSensitivity,
    DLPStage,
    ExfiltrationChannel,
)


class TestEnums:
    def test_dlpstage_discover_data_flows(self):
        assert DLPStage.DISCOVER_DATA_FLOWS == "discover_data_flows"

    def test_dlpstage_classify_sensitive_data(self):
        assert DLPStage.CLASSIFY_SENSITIVE_DATA == "classify_sensitive_data"

    def test_dlpstage_detect_exfiltration(self):
        assert DLPStage.DETECT_EXFILTRATION == "detect_exfiltration"

    def test_dlpstage_enforce_policies(self):
        assert DLPStage.ENFORCE_POLICIES == "enforce_policies"

    def test_datasensitivity_public(self):
        assert DataSensitivity.PUBLIC == "public"

    def test_datasensitivity_internal(self):
        assert DataSensitivity.INTERNAL == "internal"

    def test_datasensitivity_confidential(self):
        assert DataSensitivity.CONFIDENTIAL == "confidential"

    def test_datasensitivity_restricted(self):
        assert DataSensitivity.RESTRICTED == "restricted"

    def test_exfiltrationchannel_endpoint(self):
        assert ExfiltrationChannel.ENDPOINT == "endpoint"

    def test_exfiltrationchannel_cloud_storage(self):
        assert ExfiltrationChannel.CLOUD_STORAGE == "cloud_storage"

    def test_exfiltrationchannel_email(self):
        assert ExfiltrationChannel.EMAIL == "email"

    def test_exfiltrationchannel_browser(self):
        assert ExfiltrationChannel.BROWSER == "browser"


class TestModels:
    def test_state_defaults(self):
        s = DataLossPreventionState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.data_loss_prevention.graph import (
            create_data_loss_prevention_graph,
        )

        sg = create_data_loss_prevention_graph()
        assert sg.compile() is not None
