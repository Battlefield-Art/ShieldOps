"""Tests for shieldops.agents.container_image_scanner — container image security scanning."""

from __future__ import annotations

import pytest

from shieldops.agents.container_image_scanner.models import (
    ComplianceStatus,
    ContainerImageScannerState,
    ImageLayer,
    ImageScanStage,
    ImageVuln,
    LayerRisk,
)


def _state(**kw) -> ContainerImageScannerState:
    return ContainerImageScannerState(**kw)


class TestEnums:
    def test_image_scan_stage_values(self):
        assert ImageScanStage.DISCOVER_IMAGES == "discover_images"
        assert ImageScanStage.ANALYZE_LAYERS == "analyze_layers"
        assert ImageScanStage.SCAN_VULNERABILITIES == "scan_vulnerabilities"
        assert ImageScanStage.CHECK_COMPLIANCE == "check_compliance"
        assert ImageScanStage.PRIORITIZE == "prioritize"
        assert ImageScanStage.REPORT == "report"

    def test_layer_risk_values(self):
        assert LayerRisk.CRITICAL == "critical"
        assert LayerRisk.HIGH == "high"
        assert LayerRisk.CLEAN == "clean"

    def test_compliance_status_values(self):
        assert ComplianceStatus.PASS == "pass"  # noqa: S105
        assert ComplianceStatus.FAIL == "fail"
        assert ComplianceStatus.WARNING == "warning"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == ImageScanStage.DISCOVER_IMAGES
        assert s.image_refs == []
        assert s.discovered_images == []
        assert s.total_images == 0
        assert s.layers == []
        assert s.vulnerabilities == []
        assert s.compliance_results == []
        assert s.prioritized == []
        assert s.total_findings == 0
        assert s.critical_count == 0
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(tenant_id="t-01", total_images=5)
        assert s.tenant_id == "t-01"
        assert s.total_images == 5

    def test_image_layer_defaults(self):
        layer = ImageLayer()
        assert layer.id == ""
        assert layer.risk == LayerRisk.CLEAN
        assert layer.has_secrets is False
        assert layer.has_malware is False

    def test_image_vuln_defaults(self):
        v = ImageVuln()
        assert v.id == ""
        assert v.cve_id == ""
        assert v.severity == "medium"
        assert v.is_fixable is False
        assert v.exploit_available is False


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.container_image_scanner.tools import ContainerImageScannerToolkit

        return ContainerImageScannerToolkit()

    @pytest.mark.asyncio()
    async def test_discover_images(self, toolkit):
        images = await toolkit.discover_images("t-01", ["nginx:latest"])
        assert isinstance(images, list)
        assert len(images) == 1
        assert images[0]["ref"] == "nginx:latest"

    @pytest.mark.asyncio()
    async def test_analyze_layers(self, toolkit):
        images = [{"ref": "nginx:latest", "id": "img-1"}]
        layers = await toolkit.analyze_layers(images)
        assert isinstance(layers, list)
        assert len(layers) >= 3

    @pytest.mark.asyncio()
    async def test_scan_vulnerabilities(self, toolkit):
        images = [{"ref": "nginx:latest"}]
        vulns = await toolkit.scan_vulnerabilities(images, [])
        assert isinstance(vulns, list)
        assert len(vulns) >= 1

    @pytest.mark.asyncio()
    async def test_check_compliance(self, toolkit):
        images = [{"ref": "nginx:latest"}]
        layers = [ImageLayer(has_secrets=True)]
        results = await toolkit.check_compliance(images, layers)
        assert isinstance(results, list)
        assert any(r["status"] == "fail" for r in results)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.container_image_scanner.graph import (
            create_container_image_scanner_graph,
        )

        sg = create_container_image_scanner_graph()
        assert sg.compile() is not None
