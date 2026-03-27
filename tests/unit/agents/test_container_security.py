"""Tests for shieldops.agents.container_security."""

from __future__ import annotations

from shieldops.agents.container_security.models import (
    ContainerSecurityState,
    ContainerStage,
    ImageSeverity,
    RuntimeThreat,
)


class TestEnums:
    def test_containerstage_scan_images(self):
        assert ContainerStage.SCAN_IMAGES == "scan_images"

    def test_containerstage_analyze_runtime(self):
        assert ContainerStage.ANALYZE_RUNTIME == "analyze_runtime"

    def test_containerstage_detect_anomalies(self):
        assert ContainerStage.DETECT_ANOMALIES == "detect_anomalies"

    def test_containerstage_enforce_admission(self):
        assert ContainerStage.ENFORCE_ADMISSION == "enforce_admission"

    def test_imageseverity_critical(self):
        assert ImageSeverity.CRITICAL == "critical"

    def test_imageseverity_high(self):
        assert ImageSeverity.HIGH == "high"

    def test_imageseverity_medium(self):
        assert ImageSeverity.MEDIUM == "medium"

    def test_imageseverity_low(self):
        assert ImageSeverity.LOW == "low"

    def test_runtimethreat_privilege_escalation(self):
        assert RuntimeThreat.PRIVILEGE_ESCALATION == "privilege_escalation"

    def test_runtimethreat_container_escape(self):
        assert RuntimeThreat.CONTAINER_ESCAPE == "container_escape"

    def test_runtimethreat_crypto_mining(self):
        assert RuntimeThreat.CRYPTO_MINING == "crypto_mining"

    def test_runtimethreat_reverse_shell(self):
        assert RuntimeThreat.REVERSE_SHELL == "reverse_shell"


class TestModels:
    def test_state_defaults(self):
        s = ContainerSecurityState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.container_security.graph import (
            create_container_security_graph,
        )

        sg = create_container_security_graph()
        assert sg.compile() is not None
