"""Tests for shieldops.agents.secrets_scanner."""

from __future__ import annotations

from shieldops.agents.secrets_scanner.models import (
    ScannerStage,
    SecretsScannerState,
    SecretType,
    SourceType,
)


class TestEnums:
    def test_scannerstage_scan_sources(self):
        assert ScannerStage.SCAN_SOURCES == "scan_sources"

    def test_scannerstage_detect_secrets(self):
        assert ScannerStage.DETECT_SECRETS == "detect_secrets"

    def test_scannerstage_classify_severity(self):
        assert ScannerStage.CLASSIFY_SEVERITY == "classify_severity"

    def test_scannerstage_verify_exposure(self):
        assert ScannerStage.VERIFY_EXPOSURE == "verify_exposure"

    def test_secrettype_api_key(self):
        assert SecretType.API_KEY == "api_key"

    def test_secrettype_aws_access_key(self):
        assert SecretType.AWS_ACCESS_KEY == "aws_access_key"

    def test_secrettype_gcp_service_key(self):
        assert SecretType.GCP_SERVICE_KEY == "gcp_service_key"

    def test_secrettype_azure_secret(self):
        assert SecretType.AZURE_SECRET == "azure_secret"  # noqa: S105

    def test_sourcetype_git_repo(self):
        assert SourceType.GIT_REPO == "git_repo"

    def test_sourcetype_config_file(self):
        assert SourceType.CONFIG_FILE == "config_file"

    def test_sourcetype_container_image(self):
        assert SourceType.CONTAINER_IMAGE == "container_image"

    def test_sourcetype_log_file(self):
        assert SourceType.LOG_FILE == "log_file"


class TestModels:
    def test_state_defaults(self):
        s = SecretsScannerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.secrets_scanner.graph import (
            create_secrets_scanner_graph,
        )

        sg = create_secrets_scanner_graph()
        assert sg.compile() is not None
