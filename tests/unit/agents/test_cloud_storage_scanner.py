"""Tests for shieldops.agents.cloud_storage_scanner."""

from __future__ import annotations

from shieldops.agents.cloud_storage_scanner.models import (
    CloudStorageScannerState,
    StorageProvider,
    StorageSeverity,
    StorageStage,
)


class TestEnums:
    def test_stage_discover(self):
        assert StorageStage.DISCOVER_BUCKETS == "discover_buckets"

    def test_stage_access(self):
        assert StorageStage.SCAN_ACCESS == "scan_access"

    def test_stage_encryption(self):
        assert StorageStage.CHECK_ENCRYPTION == "check_encryption"

    def test_stage_sensitive(self):
        assert StorageStage.DETECT_SENSITIVE_DATA == "detect_sensitive_data"

    def test_stage_risk(self):
        assert StorageStage.ASSESS_RISK == "assess_risk"

    def test_stage_report(self):
        assert StorageStage.REPORT == "report"

    def test_provider_s3(self):
        assert StorageProvider.S3 == "s3"

    def test_provider_gcs(self):
        assert StorageProvider.GCS == "gcs"

    def test_provider_azure_blob(self):
        assert StorageProvider.AZURE_BLOB == "azure_blob"

    def test_severity_critical(self):
        assert StorageSeverity.CRITICAL == "critical"

    def test_severity_high(self):
        assert StorageSeverity.HIGH == "high"

    def test_severity_info(self):
        assert StorageSeverity.INFO == "info"


class TestState:
    def test_state_defaults(self):
        s = CloudStorageScannerState()
        assert s.error == ""

    def test_state_request_id(self):
        s = CloudStorageScannerState()
        assert s.request_id == ""

    def test_state_stage(self):
        s = CloudStorageScannerState()
        assert s.stage == StorageStage.DISCOVER_BUCKETS


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.cloud_storage_scanner.graph import (
            create_cloud_storage_scanner_graph,
        )

        sg = create_cloud_storage_scanner_graph()
        assert sg.compile() is not None
