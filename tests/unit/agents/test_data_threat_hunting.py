"""Tests for shieldops.agents.data_threat_hunting."""

from __future__ import annotations

import pytest

from shieldops.agents.data_threat_hunting.models import (
    BackupScanResult,
    DataThreatHuntingState,
    EvidenceCollection,
    HuntFinding,
    HuntHypothesis,
    HuntSource,
    HuntStage,
    IndicatorAnalysis,
    ReasoningStep,
    ThreatVerdict,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_hunt_stage_values(self) -> None:
        assert HuntStage.init == "init"
        assert HuntStage.generate_hypotheses == "generate_hypotheses"
        assert HuntStage.collect_evidence == "collect_evidence"
        assert HuntStage.analyze_indicators == "analyze_indicators"
        assert HuntStage.hunt_in_backups == "hunt_in_backups"
        assert HuntStage.correlate_findings == "correlate_findings"
        assert HuntStage.report == "report"
        assert HuntStage.complete == "complete"
        assert HuntStage.failed == "failed"
        assert len(HuntStage) == 9

    def test_hunt_source_values(self) -> None:
        assert HuntSource.production == "production"
        assert HuntSource.backup_snapshot == "backup_snapshot"
        assert HuntSource.ai_pipeline == "ai_pipeline"
        assert HuntSource.cloud_storage == "cloud_storage"
        assert HuntSource.database == "database"
        assert len(HuntSource) == 5

    def test_threat_verdict_values(self) -> None:
        assert ThreatVerdict.confirmed_threat == "confirmed_threat"
        assert ThreatVerdict.likely_threat == "likely_threat"
        assert ThreatVerdict.suspicious == "suspicious"
        assert ThreatVerdict.benign == "benign"
        assert ThreatVerdict.inconclusive == "inconclusive"
        assert len(ThreatVerdict) == 5


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self) -> None:
        state = DataThreatHuntingState()
        assert state.tenant_id == ""
        assert state.hunt_id == ""
        assert state.initial_hypotheses == []
        assert state.target_sources == []
        assert state.hunt_scope == {}
        assert state.hypotheses == []
        assert state.evidence == []
        assert state.indicators == []
        assert state.backup_scans == []
        assert state.findings == []
        assert state.threats_confirmed == 0
        assert state.hunt_duration_seconds == 0.0
        assert state.hunt_report == {}
        assert state.current_step == HuntStage.init
        assert state.error == ""

    def test_hunt_hypothesis_defaults(self) -> None:
        hh = HuntHypothesis()
        assert hh.mitre_techniques == []
        assert hh.target_sources == []
        assert hh.confidence == 0.0
        assert hh.priority == "medium"

    def test_evidence_collection_defaults(self) -> None:
        ec = EvidenceCollection()
        assert ec.artifacts == []
        assert ec.record_count == 0
        assert ec.collection_timestamp is None

    def test_indicator_analysis_defaults(self) -> None:
        ia = IndicatorAnalysis()
        assert ia.matched is False
        assert ia.severity == "low"
        assert ia.context == {}

    def test_backup_scan_result_defaults(self) -> None:
        bsr = BackupScanResult()
        assert bsr.threats_found == 0
        assert bsr.ransomware_staging is False
        assert bsr.persistence_detected is False
        assert bsr.exfiltration_traces is False

    def test_hunt_finding_defaults(self) -> None:
        hf = HuntFinding()
        assert hf.verdict == ThreatVerdict.inconclusive
        assert hf.confidence == 0.0
        assert hf.cross_source_correlated is False

    def test_reasoning_step_requires_fields(self) -> None:
        step = ReasoningStep(
            step_number=1,
            action="hunt",
            input_summary="in",
            output_summary="out",
        )
        assert step.step_number == 1


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.data_threat_hunting.tools import DataThreatHuntingToolkit

        return DataThreatHuntingToolkit()

    @pytest.mark.asyncio
    async def test_generate_hypotheses(self, toolkit) -> None:
        result = await toolkit.generate_hypotheses(
            context={"environment": "prod"},
            initial_hypotheses=["Lateral movement via service accounts"],
        )
        assert isinstance(result, list)
        assert len(result) >= 1
        assert result[0]["hypothesis_id"] == "hyp-000"

    @pytest.mark.asyncio
    async def test_generate_hypotheses_empty(self, toolkit) -> None:
        result = await toolkit.generate_hypotheses(context={}, initial_hypotheses=[])
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_collect_evidence(self, toolkit) -> None:
        result = await toolkit.collect_evidence(
            sources=["production"],
            hypotheses=[{"hypothesis_id": "h1", "target_sources": ["production"]}],
        )
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_analyze_indicators(self, toolkit) -> None:
        result = await toolkit.analyze_indicators(
            evidence=[{"artifacts": [{"type": "ip", "value": "10.0.0.1"}]}],
        )
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_scan_backup_snapshot(self, toolkit) -> None:
        result = await toolkit.scan_backup_snapshot(
            snapshot_id="snap-001",
            iocs=["evil.exe"],
        )
        assert isinstance(result, dict)
        assert "snapshot_id" in result

    @pytest.mark.asyncio
    async def test_correlate_cross_source(self, toolkit) -> None:
        result = await toolkit.correlate_cross_source(
            indicators=[{"indicator_value": "10.0.0.1"}],
            backup_scans=[{"threats_found": 1}],
        )
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_check_mitre_techniques(self, toolkit) -> None:
        result = await toolkit.check_mitre_techniques(
            techniques=["T1078"],
        )
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.data_threat_hunting.graph import (
            create_data_threat_hunting_graph,
        )

        graph = create_data_threat_hunting_graph()
        compiled = graph.compile()
        assert compiled is not None

    def test_should_hunt_backups_with_backup_source(self) -> None:
        from shieldops.agents.data_threat_hunting.graph import should_hunt_backups

        state = DataThreatHuntingState(target_sources=["backup_snapshot"])
        assert should_hunt_backups(state) == "hunt_in_backups"

    def test_should_hunt_backups_without_backup(self) -> None:
        from shieldops.agents.data_threat_hunting.graph import should_hunt_backups

        state = DataThreatHuntingState(target_sources=["production"])
        assert should_hunt_backups(state) == "correlate_findings"

    def test_should_hunt_backups_with_indicators(self) -> None:
        from shieldops.agents.data_threat_hunting.graph import should_hunt_backups

        state = DataThreatHuntingState(
            target_sources=["production"],
            indicators=[{"indicator_value": "10.0.0.1"}],
        )
        assert should_hunt_backups(state) == "hunt_in_backups"

    def test_should_hunt_backups_on_error(self) -> None:
        from shieldops.agents.data_threat_hunting.graph import should_hunt_backups

        state = DataThreatHuntingState(error="failed")
        assert should_hunt_backups(state) == "report"
