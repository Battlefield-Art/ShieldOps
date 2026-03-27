"""Tests for shieldops.agents.vendor_normalizer."""

from __future__ import annotations

from shieldops.agents.vendor_normalizer.models import (
    NormalizerStage,
    OCSFCategory,
    VendorNormalizerState,
    VendorType,
)


class TestEnums:
    def test_normalizerstage_ingest(self):
        assert NormalizerStage.INGEST == "ingest"

    def test_normalizerstage_detect_schema(self):
        assert NormalizerStage.DETECT_SCHEMA == "detect_schema"

    def test_normalizerstage_map_to_ocsf(self):
        assert NormalizerStage.MAP_TO_OCSF == "map_to_ocsf"

    def test_normalizerstage_validate(self):
        assert NormalizerStage.VALIDATE == "validate"

    def test_vendortype_crowdstrike(self):
        assert VendorType.CROWDSTRIKE == "crowdstrike"

    def test_vendortype_microsoft_defender(self):
        assert VendorType.MICROSOFT_DEFENDER == "microsoft_defender"

    def test_vendortype_wiz(self):
        assert VendorType.WIZ == "wiz"

    def test_vendortype_splunk(self):
        assert VendorType.SPLUNK == "splunk"

    def test_ocsfcategory_security_finding(self):
        assert OCSFCategory.SECURITY_FINDING == "security_finding"

    def test_ocsfcategory_detection_finding(self):
        assert OCSFCategory.DETECTION_FINDING == "detection_finding"

    def test_ocsfcategory_vulnerability_finding(self):
        assert OCSFCategory.VULNERABILITY_FINDING == "vulnerability_finding"

    def test_ocsfcategory_compliance_finding(self):
        assert OCSFCategory.COMPLIANCE_FINDING == "compliance_finding"


class TestModels:
    def test_state_defaults(self):
        s = VendorNormalizerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.vendor_normalizer.graph import (
            create_vendor_normalizer_graph,
        )

        sg = create_vendor_normalizer_graph()
        assert sg.compile() is not None
