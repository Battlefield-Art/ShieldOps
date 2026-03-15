"""Unit tests for ProcessorChainOptimizerEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.processor_chain_optimizer_engine import (
    ChainEfficiency,
    OptimizationGoal,
    ProcessorChainOptimizerEngine,
    ProcessorChainRecord,
    ProcessorChainReport,
    ProcessorType,
)


@pytest.fixture()
def engine() -> ProcessorChainOptimizerEngine:
    return ProcessorChainOptimizerEngine(max_records=100)


def _add_sample(engine: ProcessorChainOptimizerEngine, **kwargs: object) -> ProcessorChainRecord:
    defaults: dict[str, object] = {
        "chain_id": "chain-1",
        "processor_type": ProcessorType.BATCH,
        "chain_efficiency": ChainEfficiency.OPTIMAL,
        "optimization_goal": OptimizationGoal.MAXIMIZE_THROUGHPUT,
        "chain_position": 0,
        "drop_rate_pct": 0.0,
        "latency_added_ms": 5.0,
        "throughput_items_per_sec": 5000.0,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: ProcessorChainOptimizerEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, ProcessorChainRecord)

    def test_ring_buffer(self, engine: ProcessorChainOptimizerEngine) -> None:
        for i in range(110):
            _add_sample(engine, chain_id=f"c{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_optimal_ordering_score(self, engine: ProcessorChainOptimizerEngine) -> None:
        rec = _add_sample(engine, chain_efficiency=ChainEfficiency.OPTIMAL)
        analysis = engine.process(rec.id)
        assert analysis.ordering_score == 100.0  # type: ignore[union-attr]

    def test_broken_ordering_score_zero(self, engine: ProcessorChainOptimizerEngine) -> None:
        rec = _add_sample(engine, chain_efficiency=ChainEfficiency.BROKEN)
        analysis = engine.process(rec.id)
        assert analysis.ordering_score == 0.0  # type: ignore[union-attr]

    def test_simplification_possible_wasteful(self, engine: ProcessorChainOptimizerEngine) -> None:
        rec = _add_sample(engine, chain_efficiency=ChainEfficiency.WASTEFUL)
        analysis = engine.process(rec.id)
        assert analysis.simplification_possible is True  # type: ignore[union-attr]

    def test_simplification_possible_high_drop(self, engine: ProcessorChainOptimizerEngine) -> None:
        rec = _add_sample(engine, drop_rate_pct=25.0)
        analysis = engine.process(rec.id)
        assert analysis.simplification_possible is True  # type: ignore[union-attr]

    def test_not_found(self, engine: ProcessorChainOptimizerEngine) -> None:
        result = engine.process("bad")
        assert result["status"] == "not_found"  # type: ignore[index]


class TestGenerateReport:
    def test_report_type(self, engine: ProcessorChainOptimizerEngine) -> None:
        _add_sample(engine)
        assert isinstance(engine.generate_report(), ProcessorChainReport)

    def test_inefficient_chains_populated(self, engine: ProcessorChainOptimizerEngine) -> None:
        _add_sample(engine, chain_id="waste", chain_efficiency=ChainEfficiency.WASTEFUL)
        report = engine.generate_report()
        assert "waste" in report.inefficient_chains

    def test_avg_drop_rate(self, engine: ProcessorChainOptimizerEngine) -> None:
        _add_sample(engine, drop_rate_pct=10.0)
        _add_sample(engine, drop_rate_pct=20.0)
        report = engine.generate_report()
        assert report.avg_drop_rate_pct == 15.0

    def test_recommendations_not_empty(self, engine: ProcessorChainOptimizerEngine) -> None:
        _add_sample(engine)
        assert len(engine.generate_report().recommendations) > 0


class TestGetStats:
    def test_efficiency_distribution_present(self, engine: ProcessorChainOptimizerEngine) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "efficiency_distribution" in stats


class TestClearData:
    def test_clears(self, engine: ProcessorChainOptimizerEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert engine._records == []


class TestDomainMethods:
    def test_evaluate_chain_ordering_filter_before_transform(
        self, engine: ProcessorChainOptimizerEngine
    ) -> None:
        _add_sample(engine, chain_id="c1", processor_type=ProcessorType.FILTER, chain_position=0)
        _add_sample(engine, chain_id="c1", processor_type=ProcessorType.TRANSFORM, chain_position=1)
        results = engine.evaluate_chain_ordering()
        assert results[0]["ordering_ok"] is True

    def test_measure_processor_drop_impact_sorted_desc(
        self, engine: ProcessorChainOptimizerEngine
    ) -> None:
        _add_sample(engine, chain_id="high", drop_rate_pct=30.0)
        _add_sample(engine, chain_id="low", drop_rate_pct=5.0)
        results = engine.measure_processor_drop_impact()
        assert results[0]["total_drop_pct"] >= results[-1]["total_drop_pct"]

    def test_recommend_chain_simplification_finds_wasteful(
        self, engine: ProcessorChainOptimizerEngine
    ) -> None:
        _add_sample(engine, chain_id="w", chain_efficiency=ChainEfficiency.WASTEFUL)
        results = engine.recommend_chain_simplification()
        assert any(r["chain_id"] == "w" for r in results)

    def test_empty_returns_empty(self, engine: ProcessorChainOptimizerEngine) -> None:
        assert engine.evaluate_chain_ordering() == []
        assert engine.measure_processor_drop_impact() == []
        assert engine.recommend_chain_simplification() == []
