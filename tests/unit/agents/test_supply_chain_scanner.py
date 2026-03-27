"""Tests for shieldops.agents.supply_chain_scanner."""

from __future__ import annotations

import pytest

from shieldops.agents.supply_chain_scanner.models import (
    AIAsset,
    AssetType,
    RAGSourceScan,
    ReasoningStep,
    RegistryScan,
    ScanStage,
    SupplyChainScannerState,
    TemplateAudit,
    ThreatType,
    ToolDefinitionAudit,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_scan_stage_values(self) -> None:
        assert ScanStage.INVENTORY_AI_ASSETS == "inventory_ai_assets"
        assert ScanStage.SCAN_MODEL_REGISTRIES == "scan_model_registries"
        assert ScanStage.SCAN_RAG_SOURCES == "scan_rag_sources"
        assert ScanStage.SCAN_PROMPT_TEMPLATES == "scan_prompt_templates"
        assert ScanStage.SCAN_TOOL_DEFINITIONS == "scan_tool_definitions"
        assert ScanStage.REPORT == "report"
        assert len(ScanStage) == 6

    def test_asset_type_values(self) -> None:
        assert AssetType.MODEL_WEIGHT == "model_weight"
        assert AssetType.RAG_DOCUMENT == "rag_document"
        assert AssetType.PROMPT_TEMPLATE == "prompt_template"
        assert AssetType.TOOL_DEFINITION == "tool_definition"
        assert AssetType.TRAINING_DATASET == "training_dataset"
        assert AssetType.EMBEDDING_MODEL == "embedding_model"
        assert len(AssetType) == 6

    def test_threat_type_values(self) -> None:
        assert ThreatType.DATA_POISONING == "data_poisoning"
        assert ThreatType.MODEL_BACKDOOR == "model_backdoor"
        assert ThreatType.PROMPT_INJECTION_TEMPLATE == "prompt_injection_template"
        assert ThreatType.TOOL_HIJACKING == "tool_hijacking"
        assert ThreatType.DEPENDENCY_TAMPERING == "dependency_tampering"
        assert len(ThreatType) == 5


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self) -> None:
        state = SupplyChainScannerState()
        assert state.request_id == ""
        assert state.stage == ScanStage.INVENTORY_AI_ASSETS
        assert state.tenant_id == ""
        assert state.ai_assets == []
        assert state.registry_findings == []
        assert state.rag_findings == []
        assert state.template_findings == []
        assert state.tool_findings == []
        assert state.total_threats == 0
        assert state.supply_chain_score == 0.0
        assert state.stats == {}
        assert state.error == ""

    def test_ai_asset_defaults(self) -> None:
        asset = AIAsset()
        assert asset.asset_type == AssetType.MODEL_WEIGHT
        assert asset.verified is False
        assert asset.risk_score == 0.0
        assert asset.metadata == {}

    def test_registry_scan_defaults(self) -> None:
        rs = RegistryScan()
        assert rs.checksum_match is True
        assert rs.provenance_verified is False
        assert rs.signature_valid is False
        assert rs.threat_type is None
        assert rs.severity == "low"

    def test_rag_source_scan_defaults(self) -> None:
        rss = RAGSourceScan()
        assert rss.document_count == 0
        assert rss.poisoned_count == 0
        assert rss.adversarial_embeddings == 0
        assert rss.threat_type is None

    def test_template_audit_defaults(self) -> None:
        ta = TemplateAudit()
        assert ta.injection_vulnerable is False
        assert ta.unescaped_variables == []
        assert ta.threat_type is None

    def test_tool_definition_audit_defaults(self) -> None:
        tda = ToolDefinitionAudit()
        assert tda.hijack_risk is False
        assert tda.unauthorized_scope is False
        assert tda.exfiltration_capable is False

    def test_reasoning_step_defaults(self) -> None:
        step = ReasoningStep()
        assert step.step == ""
        assert step.confidence == 0.0


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.supply_chain_scanner.tools import SupplyChainScannerToolkit

        return SupplyChainScannerToolkit()

    @pytest.mark.asyncio
    async def test_inventory_ai_assets(self, toolkit) -> None:
        result = await toolkit.inventory_ai_assets("tenant-1")
        assert isinstance(result, list)
        assert len(result) >= 1

    @pytest.mark.asyncio
    async def test_scan_model_registry(self, toolkit) -> None:
        assets = [{"id": "a1", "name": "model-v1", "asset_type": "model_weight", "checksum": "abc"}]
        result = await toolkit.scan_model_registry(assets)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_scan_rag_sources(self, toolkit) -> None:
        assets = [
            {"id": "a1", "name": "corpus", "asset_type": "rag_document", "source": "s3://bucket"}
        ]
        result = await toolkit.scan_rag_sources(assets)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_audit_prompt_templates(self, toolkit) -> None:
        assets = [{"id": "a1", "name": "sys-prompt", "asset_type": "prompt_template"}]
        result = await toolkit.audit_prompt_templates(assets)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_audit_tool_definitions(self, toolkit) -> None:
        assets = [{"id": "a1", "name": "web_search", "asset_type": "tool_definition"}]
        result = await toolkit.audit_tool_definitions(assets)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.supply_chain_scanner.graph import build_graph
        from shieldops.agents.supply_chain_scanner.tools import SupplyChainScannerToolkit

        toolkit = SupplyChainScannerToolkit()
        graph = build_graph(toolkit)
        compiled = graph.compile()
        assert compiled is not None

    def test_create_factory(self) -> None:
        from shieldops.agents.supply_chain_scanner.graph import (
            create_supply_chain_scanner_graph,
        )

        graph = create_supply_chain_scanner_graph()
        compiled = graph.compile()
        assert compiled is not None
