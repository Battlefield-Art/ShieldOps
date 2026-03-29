"""Unit tests for container_image_scanner."""

from __future__ import annotations

from shieldops.agents.container_image_scanner.models import (
    ComplianceStatus,
    ContainerImageScannerState,
    ImageScanStage,
    LayerRisk,
)


class TestEnums:
    def test_compliancestatus(self) -> None:
        assert ComplianceStatus.PASS == "pass"  # noqa: S105
        assert len(ComplianceStatus) >= 3

    def test_imagescanstage(self) -> None:
        assert ImageScanStage.DISCOVER_IMAGES == "discover_images"
        assert len(ImageScanStage) >= 3

    def test_layerrisk(self) -> None:
        assert LayerRisk.CRITICAL == "critical"
        assert len(LayerRisk) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ContainerImageScannerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ContainerImageScannerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
