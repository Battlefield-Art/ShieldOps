"""Tests for shieldops.agents.sensitive_data_monitor."""

from __future__ import annotations

from shieldops.agents.sensitive_data_monitor.models import (
    DataCategory,
    ExposureLevel,
    MonitorStage,
    SensitiveDataMonitorState,
)


class TestEnums:
    def test_monitorstage_discover_data_sources(self):
        assert MonitorStage.DISCOVER_DATA_SOURCES == "discover_data_sources"

    def test_monitorstage_scan_for_sensitive(self):
        assert MonitorStage.SCAN_FOR_SENSITIVE == "scan_for_sensitive"

    def test_monitorstage_classify_data(self):
        assert MonitorStage.CLASSIFY_DATA == "classify_data"

    def test_monitorstage_assess_exposure(self):
        assert MonitorStage.ASSESS_EXPOSURE == "assess_exposure"

    def test_datacategory_pii(self):
        assert DataCategory.PII == "pii"

    def test_datacategory_phi(self):
        assert DataCategory.PHI == "phi"

    def test_datacategory_pci(self):
        assert DataCategory.PCI == "pci"

    def test_datacategory_intellectual_property(self):
        assert DataCategory.INTELLECTUAL_PROPERTY == "intellectual_property"

    def test_exposurelevel_public(self):
        assert ExposureLevel.PUBLIC == "public"

    def test_exposurelevel_shared(self):
        assert ExposureLevel.SHARED == "shared"

    def test_exposurelevel_internal(self):
        assert ExposureLevel.INTERNAL == "internal"

    def test_exposurelevel_restricted(self):
        assert ExposureLevel.RESTRICTED == "restricted"


class TestModels:
    def test_state_defaults(self):
        s = SensitiveDataMonitorState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.sensitive_data_monitor.graph import (
            create_sensitive_data_monitor_graph,
        )

        sg = create_sensitive_data_monitor_graph()
        assert sg.compile() is not None
