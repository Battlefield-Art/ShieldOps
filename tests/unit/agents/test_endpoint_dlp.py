"""Tests for shieldops.agents.endpoint_dlp."""

from __future__ import annotations

from shieldops.agents.endpoint_dlp.models import (
    DataMovementType,
    EndpointDLPStage,
    EndpointDLPState,
    PolicyAction,
)


class TestEnums:
    def test_endpointdlpstage_monitor_endpoints(self):
        assert EndpointDLPStage.MONITOR_ENDPOINTS == "monitor_endpoints"

    def test_endpointdlpstage_detect_data_movement(self):
        assert EndpointDLPStage.DETECT_DATA_MOVEMENT == "detect_data_movement"

    def test_endpointdlpstage_classify_sensitivity(self):
        assert EndpointDLPStage.CLASSIFY_SENSITIVITY == "classify_sensitivity"

    def test_endpointdlpstage_enforce_policies(self):
        assert EndpointDLPStage.ENFORCE_POLICIES == "enforce_policies"

    def test_datamovementtype_clipboard(self):
        assert DataMovementType.CLIPBOARD == "clipboard"

    def test_datamovementtype_usb(self):
        assert DataMovementType.USB == "usb"

    def test_datamovementtype_print(self):
        assert DataMovementType.PRINT == "print"

    def test_datamovementtype_upload(self):
        assert DataMovementType.UPLOAD == "upload"

    def test_policyaction_allow(self):
        assert PolicyAction.ALLOW == "allow"

    def test_policyaction_log(self):
        assert PolicyAction.LOG == "log"

    def test_policyaction_warn(self):
        assert PolicyAction.WARN == "warn"

    def test_policyaction_block(self):
        assert PolicyAction.BLOCK == "block"


class TestModels:
    def test_state_defaults(self):
        s = EndpointDLPState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.endpoint_dlp.graph import (
            create_endpoint_dlp_graph,
        )

        sg = create_endpoint_dlp_graph()
        assert sg.compile() is not None
