"""Tests for shieldops.agents.data_pipeline_security."""

from __future__ import annotations

from shieldops.agents.data_pipeline_security.models import (
    DataPipelineSecurityState,
    DataSourceType,
    PipelineStage,
    RiskLevel,
)


class TestEnums:
    def test_pipelinestage_scan_rag(self):
        assert PipelineStage.SCAN_RAG == "scan_rag"

    def test_pipelinestage_audit_data_flows(self):
        assert PipelineStage.AUDIT_DATA_FLOWS == "audit_data_flows"

    def test_pipelinestage_detect_poisoning(self):
        assert PipelineStage.DETECT_POISONING == "detect_poisoning"

    def test_pipelinestage_assess_provenance(self):
        assert PipelineStage.ASSESS_PROVENANCE == "assess_provenance"

    def test_datasourcetype_vector_db(self):
        assert DataSourceType.VECTOR_DB == "vector_db"

    def test_datasourcetype_document_store(self):
        assert DataSourceType.DOCUMENT_STORE == "document_store"

    def test_datasourcetype_model_registry(self):
        assert DataSourceType.MODEL_REGISTRY == "model_registry"

    def test_datasourcetype_training_data(self):
        assert DataSourceType.TRAINING_DATA == "training_data"

    def test_risklevel_critical(self):
        assert RiskLevel.CRITICAL == "critical"

    def test_risklevel_high(self):
        assert RiskLevel.HIGH == "high"

    def test_risklevel_medium(self):
        assert RiskLevel.MEDIUM == "medium"

    def test_risklevel_low(self):
        assert RiskLevel.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = DataPipelineSecurityState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.data_pipeline_security.graph import (
            create_data_pipeline_security_graph,
        )

        sg = create_data_pipeline_security_graph()
        assert sg.compile() is not None
