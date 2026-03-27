"""Tests for shieldops.agents.ransomware_forensics."""

from __future__ import annotations

import pytest

from shieldops.agents.ransomware_forensics.models import (
    AttackChainAnalysis,
    BlastRadiusAssessment,
    BlastRadiusLevel,
    ForensicArtifact,
    ForensicsStage,
    RansomwareForensicsState,
    RansomwareVariant,
    ReasoningStep,
    RecoveryRecommendation,
    VariantIdentification,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_forensics_stage_values(self) -> None:
        assert ForensicsStage.COLLECT_ARTIFACTS == "collect_artifacts"
        assert ForensicsStage.ANALYZE_ATTACK_CHAIN == "analyze_attack_chain"
        assert ForensicsStage.IDENTIFY_VARIANT == "identify_variant"
        assert ForensicsStage.ASSESS_BLAST_RADIUS == "assess_blast_radius"
        assert ForensicsStage.RECOMMEND_RECOVERY == "recommend_recovery"
        assert ForensicsStage.REPORT == "report"
        assert len(ForensicsStage) == 6

    def test_ransomware_variant_values(self) -> None:
        assert RansomwareVariant.LOCKBIT == "lockbit"
        assert RansomwareVariant.BLACKCAT == "blackcat"
        assert RansomwareVariant.CLOP == "clop"
        assert RansomwareVariant.ROYAL == "royal"
        assert RansomwareVariant.PLAY == "play"
        assert RansomwareVariant.RHYSIDA == "rhysida"
        assert RansomwareVariant.UNKNOWN == "unknown"
        assert len(RansomwareVariant) == 7

    def test_blast_radius_level_values(self) -> None:
        assert BlastRadiusLevel.CONTAINED == "contained"
        assert BlastRadiusLevel.SPREADING == "spreading"
        assert BlastRadiusLevel.WIDESPREAD == "widespread"
        assert BlastRadiusLevel.CATASTROPHIC == "catastrophic"
        assert len(BlastRadiusLevel) == 4


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self) -> None:
        state = RansomwareForensicsState()
        assert state.tenant_id == ""
        assert state.incident_id == ""
        assert state.target_systems == []
        assert state.current_stage == ForensicsStage.COLLECT_ARTIFACTS
        assert state.artifacts_collected == []
        assert state.attack_chain == {}
        assert state.variant_identified == {}
        assert state.blast_radius == {}
        assert state.recovery_plan == []
        assert state.affected_systems_count == 0
        assert state.estimated_data_encrypted_gb == 0.0
        assert state.report == {}
        assert state.error == ""

    def test_forensic_artifact_defaults(self) -> None:
        fa = ForensicArtifact()
        assert fa.artifact_id == ""
        assert fa.encryption_detected is False
        assert fa.ransom_note_found is False
        assert fa.metadata == {}

    def test_attack_chain_analysis_defaults(self) -> None:
        aca = AttackChainAnalysis()
        assert aca.initial_access_vector == ""
        assert aca.lateral_movement_path == []
        assert aca.c2_servers == []
        assert aca.dwell_time_hours == 0.0
        assert aca.mitre_techniques == []

    def test_variant_identification_defaults(self) -> None:
        vi = VariantIdentification()
        assert vi.variant == RansomwareVariant.UNKNOWN
        assert vi.confidence == 0.0
        assert vi.known_decryptor_available is False
        assert vi.iocs == []

    def test_blast_radius_assessment_defaults(self) -> None:
        bra = BlastRadiusAssessment()
        assert bra.level == BlastRadiusLevel.CONTAINED
        assert bra.affected_hosts == []
        assert bra.data_encrypted_gb == 0.0
        assert bra.business_impact_score == 0.0
        assert bra.propagation_vectors == []

    def test_recovery_recommendation_defaults(self) -> None:
        rr = RecoveryRecommendation()
        assert rr.priority == 0
        assert rr.requires_backup_restore is False
        assert rr.backup_available is False

    def test_reasoning_step_requires_fields(self) -> None:
        step = ReasoningStep(
            step_number=1,
            action="collect",
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
        from shieldops.agents.ransomware_forensics.tools import RansomwareForensicsToolkit

        return RansomwareForensicsToolkit()

    @pytest.mark.asyncio
    async def test_collect_encrypted_files(self, toolkit) -> None:
        result = await toolkit.collect_encrypted_files(["host-01", "host-02"])
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["artifact_type"] == "encrypted_file"
        assert result[0]["encryption_detected"] is True

    @pytest.mark.asyncio
    async def test_collect_ransom_notes(self, toolkit) -> None:
        result = await toolkit.collect_ransom_notes(["host-01"])
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_collect_process_traces(self, toolkit) -> None:
        result = await toolkit.collect_process_traces(["host-01"])
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_collect_registry_changes(self, toolkit) -> None:
        result = await toolkit.collect_registry_changes(["host-01"])
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_collect_network_artifacts(self, toolkit) -> None:
        result = await toolkit.collect_network_artifacts(["host-01"])
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_collect_identity_artifacts(self, toolkit) -> None:
        result = await toolkit.collect_identity_artifacts(["host-01"])
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_query_threat_intel(self, toolkit) -> None:
        result = await toolkit.query_threat_intel(iocs=["hash-abc123"])
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_check_backup_status(self, toolkit) -> None:
        result = await toolkit.check_backup_status(["host-01"])
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_get_network_topology(self, toolkit) -> None:
        result = await toolkit.get_network_topology(["host-01"])
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.ransomware_forensics.graph import (
            create_ransomware_forensics_graph,
        )

        graph = create_ransomware_forensics_graph()
        compiled = graph.compile()
        assert compiled is not None

    def test_should_continue_after_blast_catastrophic(self) -> None:
        from shieldops.agents.ransomware_forensics.graph import should_continue_after_blast

        state = RansomwareForensicsState(blast_radius={"level": "catastrophic"})
        assert should_continue_after_blast(state) == "generate_report"

    def test_should_continue_after_blast_normal(self) -> None:
        from shieldops.agents.ransomware_forensics.graph import should_continue_after_blast

        state = RansomwareForensicsState(blast_radius={"level": "contained"})
        assert should_continue_after_blast(state) == "recommend_recovery"

    def test_should_continue_after_blast_on_error(self) -> None:
        from shieldops.agents.ransomware_forensics.graph import should_continue_after_blast

        state = RansomwareForensicsState(error="failed")
        assert should_continue_after_blast(state) == "generate_report"
