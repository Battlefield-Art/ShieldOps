"""Tests for shieldops.agents.iot_ot_security."""

from __future__ import annotations

from shieldops.agents.iot_ot_security.models import (
    DeviceCategory,
    IoTOTSecurityState,
    IoTStage,
    ThreatLevel,
)


class TestEnums:
    def test_iotstage_discover_devices(self):
        assert IoTStage.DISCOVER_DEVICES == "discover_devices"

    def test_iotstage_profile_behavior(self):
        assert IoTStage.PROFILE_BEHAVIOR == "profile_behavior"

    def test_iotstage_detect_anomalies(self):
        assert IoTStage.DETECT_ANOMALIES == "detect_anomalies"

    def test_iotstage_assess_vulnerabilities(self):
        assert IoTStage.ASSESS_VULNERABILITIES == "assess_vulnerabilities"

    def test_devicecategory_iot_sensor(self):
        assert DeviceCategory.IOT_SENSOR == "iot_sensor"

    def test_devicecategory_ot_controller(self):
        assert DeviceCategory.OT_CONTROLLER == "ot_controller"

    def test_devicecategory_edge_ai(self):
        assert DeviceCategory.EDGE_AI == "edge_ai"

    def test_devicecategory_smart_camera(self):
        assert DeviceCategory.SMART_CAMERA == "smart_camera"

    def test_threatlevel_critical(self):
        assert ThreatLevel.CRITICAL == "critical"

    def test_threatlevel_high(self):
        assert ThreatLevel.HIGH == "high"

    def test_threatlevel_medium(self):
        assert ThreatLevel.MEDIUM == "medium"

    def test_threatlevel_low(self):
        assert ThreatLevel.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = IoTOTSecurityState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.iot_ot_security.graph import (
            create_iot_ot_security_graph,
        )

        sg = create_iot_ot_security_graph()
        assert sg.compile() is not None
