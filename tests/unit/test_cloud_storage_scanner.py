"""Tests for cloud_storage_scanner."""

from __future__ import annotations

from shieldops.agents.cloud_storage_scanner.models import (
    CloudStorageScannerState,
    StorageProvider,
    StorageSeverity,
    StorageStage,
)


class TestEnums:
    def test_storageprovider(self) -> None:
        assert StorageProvider.S3 == "s3"
        assert len(StorageProvider) >= 3

    def test_storageseverity(self) -> None:
        assert StorageSeverity.CRITICAL == "critical"
        assert len(StorageSeverity) >= 3

    def test_storagestage(self) -> None:
        assert StorageStage.DISCOVER_BUCKETS == "discover_buckets"
        assert len(StorageStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CloudStorageScannerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CloudStorageScannerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
