"""Tests for SOCEvidenceChain engine."""

import pytest

from shieldops.security.soc_evidence_chain import (
    DecisionOutcome,
    EvidenceChainReport,
    EvidenceType,
    SOCEvidenceChain,
)


@pytest.fixture
def engine():
    return SOCEvidenceChain(max_records=100)


def test_add_evidence(engine):
    ev = engine.add_evidence(
        situation_id="sit-1",
        evidence_type=EvidenceType.VENDOR_ALERT,
        source_vendor="datadog",
        summary="CPU spike detected",
        confidence=0.9,
    )
    assert ev.situation_id == "sit-1"
    assert ev.evidence_type == EvidenceType.VENDOR_ALERT
    assert ev.confidence == 0.9
    assert len(engine._evidence) == 1


def test_record_decision(engine):
    ev = engine.add_evidence("sit-1", summary="alert data")
    dec = engine.record_decision(
        situation_id="sit-1",
        action_proposed="restart_pod",
        evidence_ids=[ev.id],
        llm_reasoning="High CPU indicates OOM",
        confidence=0.85,
        decided_by="auto-agent",
    )
    assert dec.situation_id == "sit-1"
    assert dec.action_proposed == "restart_pod"
    assert ev.id in dec.evidence_ids


def test_get_chain(engine):
    ev = engine.add_evidence("sit-1", summary="evidence 1")
    engine.record_decision("sit-1", "action-1", evidence_ids=[ev.id])
    chain = engine.get_chain("sit-1")
    assert chain["situation_id"] == "sit-1"
    assert chain["evidence_count"] == 1
    assert chain["decision_count"] == 1


def test_get_chain_empty(engine):
    chain = engine.get_chain("nonexistent")
    assert chain["evidence_count"] == 0
    assert chain["decision_count"] == 0


def test_validate_chain_complete(engine):
    ev = engine.add_evidence("sit-1", summary="evidence")
    engine.record_decision("sit-1", "action-1", evidence_ids=[ev.id])
    result = engine.validate_chain_completeness("sit-1")
    assert result["is_complete"] is True
    assert result["unsupported_decisions"] == 0


def test_validate_chain_incomplete(engine):
    engine.record_decision("sit-1", "action-1", evidence_ids=["nonexistent-id"])
    result = engine.validate_chain_completeness("sit-1")
    assert result["is_complete"] is False
    assert result["unsupported_decisions"] == 1


def test_validate_chain_no_decisions(engine):
    engine.add_evidence("sit-1", summary="evidence only")
    result = engine.validate_chain_completeness("sit-1")
    assert result["is_complete"] is False  # no decisions means not complete


def test_generate_report(engine):
    ev = engine.add_evidence("sit-1", evidence_type=EvidenceType.LLM_ANALYSIS)
    engine.record_decision(
        "sit-1", "action", evidence_ids=[ev.id], outcome=DecisionOutcome.APPROVED
    )
    report = engine.generate_chain_report()
    assert isinstance(report, EvidenceChainReport)
    assert report.total_evidence == 1
    assert report.total_decisions == 1
    assert report.unique_situations == 1


def test_generate_report_empty(engine):
    report = engine.generate_chain_report()
    assert report.total_evidence == 0
    assert "All evidence chains are complete and valid" in report.recommendations


def test_get_stats(engine):
    engine.add_evidence("sit-1")
    stats = engine.get_stats()
    assert "total_evidence" in stats
    assert "total_decisions" in stats
    assert "unique_situations" in stats
    assert "evidence_type_distribution" in stats
    assert stats["total_evidence"] == 1


def test_clear_data(engine):
    engine.add_evidence("sit-1")
    engine.record_decision("sit-1", "action")
    engine.clear_data()
    assert len(engine._evidence) == 0
    assert len(engine._decisions) == 0
