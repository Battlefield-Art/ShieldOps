"""Tests for shieldops.agents.model_security."""

from __future__ import annotations

from shieldops.agents.model_security.models import (
    ModelSecurityState,
    ScanVerdict,
    SecurityStage,
    ThreatLevel,
)


class TestEnums:
    def test_securitystage_scan_models(self):
        assert SecurityStage.SCAN_MODELS == "scan_models"

    def test_securitystage_verify_provenance(self):
        assert SecurityStage.VERIFY_PROVENANCE == "verify_provenance"

    def test_securitystage_detect_backdoors(self):
        assert SecurityStage.DETECT_BACKDOORS == "detect_backdoors"

    def test_securitystage_assess_integrity(self):
        assert SecurityStage.ASSESS_INTEGRITY == "assess_integrity"

    def test_threatlevel_critical(self):
        assert ThreatLevel.CRITICAL == "critical"

    def test_threatlevel_high(self):
        assert ThreatLevel.HIGH == "high"

    def test_threatlevel_medium(self):
        assert ThreatLevel.MEDIUM == "medium"

    def test_threatlevel_low(self):
        assert ThreatLevel.LOW == "low"

    def test_scanverdict_clean(self):
        assert ScanVerdict.CLEAN == "clean"

    def test_scanverdict_suspicious(self):
        assert ScanVerdict.SUSPICIOUS == "suspicious"

    def test_scanverdict_compromised(self):
        assert ScanVerdict.COMPROMISED == "compromised"

    def test_scanverdict_unknown(self):
        assert ScanVerdict.UNKNOWN == "unknown"


class TestModels:
    def test_state_defaults(self):
        s = ModelSecurityState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.model_security.graph import (
            create_model_security_graph,
        )

        sg = create_model_security_graph()
        assert sg.compile() is not None
