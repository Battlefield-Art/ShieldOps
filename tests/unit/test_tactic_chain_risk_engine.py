"""Tests for shieldops.security.tactic_chain_risk_engine."""

from __future__ import annotations

from shieldops.security.tactic_chain_risk_engine import (
    AmplificationLevel,
    ChainCompleteness,
    ChainPattern,
    TacticChainAnalysis,
    TacticChainRecord,
    TacticChainReport,
    TacticChainRiskEngine,
)


def _engine(**kw) -> TacticChainRiskEngine:
    return TacticChainRiskEngine(**kw)


# --- Enums ---


class TestEnums:
    def test_pattern_linear(self):
        assert ChainPattern.LINEAR_PROGRESSION == "linear_progression"

    def test_pattern_branching(self):
        assert ChainPattern.BRANCHING == "branching"

    def test_pattern_looping(self):
        assert ChainPattern.LOOPING == "looping"

    def test_pattern_incomplete(self):
        assert ChainPattern.INCOMPLETE == "incomplete"

    def test_completeness_full(self):
        assert ChainCompleteness.FULL_KILL_CHAIN == "full_kill_chain"

    def test_completeness_fragmented(self):
        assert ChainCompleteness.FRAGMENTED == "fragmented"

    def test_amplification_critical(self):
        assert AmplificationLevel.CRITICAL_AMPLIFY == "critical_amplify"

    def test_amplification_none(self):
        assert AmplificationLevel.NO_AMPLIFY == "no_amplify"


# --- Models ---


class TestModels:
    def test_record_defaults(self):
        r = TacticChainRecord()
        assert r.id
        assert r.tactic_sequence == []
        assert r.tactic_count == 0

    def test_analysis_defaults(self):
        a = TacticChainAnalysis()
        assert a.amplification_factor == 0.0
        assert a.completion_probability == 0.0

    def test_report_defaults(self):
        r = TacticChainReport()
        assert r.total_records == 0
        assert r.critical_chain_ids == []


# --- add_record ---


class TestAddRecord:
    def test_basic(self):
        eng = _engine()
        r = eng.add_record(
            chain_id="CH-001",
            entity_id="host-001",
            amplification_level=AmplificationLevel.CRITICAL_AMPLIFY,
            tactic_sequence=["initial_access", "lateral_movement", "exfiltration"],
            tactic_count=3,
        )
        assert r.chain_id == "CH-001"
        assert r.tactic_count == 3
        assert len(r.tactic_sequence) == 3

    def test_eviction(self):
        eng = _engine(max_records=2)
        for i in range(5):
            eng.add_record(chain_id=f"CH-{i}")
        assert len(eng._records) == 2


# --- process ---


class TestProcess:
    def test_critical_amp(self):
        eng = _engine()
        r = eng.add_record(
            chain_id="CH-001",
            amplification_level=AmplificationLevel.CRITICAL_AMPLIFY,
            tactic_sequence=["t1", "t2"],
        )
        result = eng.process(r.id)
        assert isinstance(result, TacticChainAnalysis)
        assert result.amplification_factor == 3.0

    def test_full_kill_chain_prob(self):
        eng = _engine()
        r = eng.add_record(
            chain_id="CH-002",
            chain_completeness=ChainCompleteness.FULL_KILL_CHAIN,
        )
        result = eng.process(r.id)
        assert result.completion_probability == 1.0

    def test_predicted_next_tactic(self):
        eng = _engine()
        r = eng.add_record(
            chain_id="CH-003",
            tactic_sequence=["t1", "t2", "t3"],
        )
        result = eng.process(r.id)
        assert result.predicted_next_tactic == "t3"

    def test_not_found(self):
        eng = _engine()
        result = eng.process("ghost")
        assert result["status"] == "not_found"


# --- generate_report ---


class TestGenerateReport:
    def test_critical_flagged(self):
        eng = _engine()
        eng.add_record(
            chain_id="CH-001",
            amplification_level=AmplificationLevel.CRITICAL_AMPLIFY,
        )
        report = eng.generate_report()
        assert "CH-001" in report.critical_chain_ids
        assert "critical" in report.recommendations[0]

    def test_empty(self):
        eng = _engine()
        report = eng.generate_report()
        assert "No critical" in report.recommendations[0]


# --- get_stats / clear ---


class TestGetStatsAndClear:
    def test_stats(self):
        eng = _engine()
        eng.add_record(amplification_level=AmplificationLevel.HIGH_AMPLIFY)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "high_amplify" in stats["amplification_distribution"]

    def test_clear(self):
        eng = _engine()
        eng.add_record()
        eng.clear_data()
        assert len(eng._records) == 0


# --- domain methods ---


class TestDetectTacticChains:
    def test_min_count_filter(self):
        eng = _engine()
        eng.add_record(chain_id="CH-001", tactic_count=3)
        eng.add_record(chain_id="CH-002", tactic_count=1)
        results = eng.detect_tactic_chains(min_tactic_count=2)
        assert len(results) == 1
        assert results[0]["chain_id"] == "CH-001"

    def test_empty(self):
        eng = _engine()
        assert eng.detect_tactic_chains() == []


class TestComputeChainAmplification:
    def test_critical(self):
        eng = _engine()
        eng.add_record(
            chain_id="CH-001",
            base_risk_score=100.0,
            amplified_risk_score=300.0,
            amplification_level=AmplificationLevel.CRITICAL_AMPLIFY,
        )
        results = eng.compute_chain_amplification()
        assert results[0]["effective_amplification"] == 3.0

    def test_no_amplify(self):
        eng = _engine()
        eng.add_record(
            chain_id="CH-002",
            base_risk_score=50.0,
            amplified_risk_score=50.0,
            amplification_level=AmplificationLevel.NO_AMPLIFY,
        )
        results = eng.compute_chain_amplification()
        assert results[0]["effective_amplification"] == 1.0


class TestPredictChainCompletion:
    def test_linear_high_prob(self):
        eng = _engine()
        eng.add_record(
            chain_id="CH-001",
            chain_completeness=ChainCompleteness.PARTIAL_CHAIN,
            chain_pattern=ChainPattern.LINEAR_PROGRESSION,
        )
        results = eng.predict_chain_completion()
        assert results[0]["completion_probability"] > 0.6

    def test_single_tactic_low_prob(self):
        eng = _engine()
        eng.add_record(
            chain_id="CH-002",
            chain_completeness=ChainCompleteness.SINGLE_TACTIC,
            chain_pattern=ChainPattern.INCOMPLETE,
        )
        results = eng.predict_chain_completion()
        assert results[0]["completion_probability"] < 0.3

    def test_empty(self):
        eng = _engine()
        assert eng.predict_chain_completion() == []
