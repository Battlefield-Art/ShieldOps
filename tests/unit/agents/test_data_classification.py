"""Tests for shieldops.agents.data_classification."""

from __future__ import annotations

from shieldops.agents.data_classification.models import (
    ClassificationStage,
    DataCategory,
    DataClassificationState,
    SensitivityLevel,
)


class TestEnums:
    def test_classificationstage_scan_sources(self):
        assert ClassificationStage.SCAN_SOURCES == "scan_sources"

    def test_classificationstage_detect_sensitive(self):
        assert ClassificationStage.DETECT_SENSITIVE == "detect_sensitive"

    def test_classificationstage_classify_level(self):
        assert ClassificationStage.CLASSIFY_LEVEL == "classify_level"

    def test_classificationstage_map_regulations(self):
        assert ClassificationStage.MAP_REGULATIONS == "map_regulations"

    def test_sensitivitylevel_top_secret(self):
        assert SensitivityLevel.TOP_SECRET == "top_secret"  # noqa: S105

    def test_sensitivitylevel_confidential(self):
        assert SensitivityLevel.CONFIDENTIAL == "confidential"

    def test_sensitivitylevel_internal(self):
        assert SensitivityLevel.INTERNAL == "internal"

    def test_sensitivitylevel_public(self):
        assert SensitivityLevel.PUBLIC == "public"

    def test_datacategory_pii(self):
        assert DataCategory.PII == "pii"

    def test_datacategory_phi(self):
        assert DataCategory.PHI == "phi"

    def test_datacategory_pci(self):
        assert DataCategory.PCI == "pci"

    def test_datacategory_credentials(self):
        assert DataCategory.CREDENTIALS == "credentials"


class TestModels:
    def test_state_defaults(self):
        s = DataClassificationState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.data_classification.graph import (
            create_data_classification_graph,
        )

        sg = create_data_classification_graph()
        assert sg.compile() is not None
