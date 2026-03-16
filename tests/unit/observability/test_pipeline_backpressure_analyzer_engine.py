"""Unit tests for PipelineBackpressureAnalyzerEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.pipeline_backpressure_analyzer_engine import (
    BackpressureLevel,
    PipelineBackpressureAnalyzerEngine,
    PipelineBackpressureRecord,
    PipelineBackpressureReport,
    PipelineStage,
    PropagationDirection,
)


@pytest.fixture()
def engine() -> PipelineBackpressureAnalyzerEngine:
    return PipelineBackpressureAnalyzerEngine(max_records=100)


def _add_sample(
    engine: PipelineBackpressureAnalyzerEngine, **kwargs: object
) -> PipelineBackpressureRecord:
    defaults: dict[str, object] = {
        "pipeline_id": "pipe-1",
        "pipeline_stage": PipelineStage.RECEIVER,
        "backpressure_level": BackpressureLevel.NONE,
        "propagation_direction": PropagationDirection.ISOLATED,
        "queue_depth": 100,
        "queue_capacity": 10000,
        "drain_rate_per_sec": 1000.0,
        "fill_rate_per_sec": 500.0,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: PipelineBackpressureAnalyzerEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, PipelineBackpressureRecord)

    def test_ring_buffer(self, engine: PipelineBackpressureAnalyzerEngine) -> None:
        for i in range(110):
            _add_sample(engine, pipeline_id=f"p{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_queue_fill_pct_calculated(self, engine: PipelineBackpressureAnalyzerEngine) -> None:
        rec = _add_sample(engine, queue_depth=5000, queue_capacity=10000)
        analysis = engine.process(rec.id)
        assert analysis.queue_fill_pct == 50.0  # type: ignore[union-attr]

    def test_drain_deficit_positive_means_filling(
        self, engine: PipelineBackpressureAnalyzerEngine
    ) -> None:
        rec = _add_sample(engine, fill_rate_per_sec=1000.0, drain_rate_per_sec=500.0)
        analysis = engine.process(rec.id)
        assert analysis.drain_deficit == pytest.approx(500.0)  # type: ignore[union-attr]

    def test_source_stage_identified_when_full(
        self, engine: PipelineBackpressureAnalyzerEngine
    ) -> None:
        rec = _add_sample(
            engine,
            queue_depth=9000,
            queue_capacity=10000,
            pipeline_stage=PipelineStage.EXPORTER,
        )
        analysis = engine.process(rec.id)
        assert analysis.source_stage == "exporter"  # type: ignore[union-attr]

    def test_no_source_stage_when_empty(self, engine: PipelineBackpressureAnalyzerEngine) -> None:
        rec = _add_sample(engine, queue_depth=100, queue_capacity=10000)
        analysis = engine.process(rec.id)
        assert analysis.source_stage == "none"  # type: ignore[union-attr]

    def test_not_found(self, engine: PipelineBackpressureAnalyzerEngine) -> None:
        assert engine.process("bad")["status"] == "not_found"  # type: ignore[index]


class TestGenerateReport:
    def test_report_type(self, engine: PipelineBackpressureAnalyzerEngine) -> None:
        _add_sample(engine)
        assert isinstance(engine.generate_report(), PipelineBackpressureReport)

    def test_critical_pipelines_populated(self, engine: PipelineBackpressureAnalyzerEngine) -> None:
        _add_sample(engine, pipeline_id="crit", backpressure_level=BackpressureLevel.CRITICAL)
        report = engine.generate_report()
        assert "crit" in report.critical_pipelines

    def test_avg_queue_fill_calculated(self, engine: PipelineBackpressureAnalyzerEngine) -> None:
        _add_sample(engine, queue_depth=5000, queue_capacity=10000)
        report = engine.generate_report()
        assert report.avg_queue_fill_pct == 50.0

    def test_recommendations_present(self, engine: PipelineBackpressureAnalyzerEngine) -> None:
        _add_sample(engine)
        assert len(engine.generate_report().recommendations) > 0


class TestGetStats:
    def test_backpressure_level_distribution_key(
        self, engine: PipelineBackpressureAnalyzerEngine
    ) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "backpressure_level_distribution" in stats


class TestClearData:
    def test_clears(self, engine: PipelineBackpressureAnalyzerEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert engine._records == []


class TestDomainMethods:
    def test_trace_backpressure_source_sorted_by_fill(
        self, engine: PipelineBackpressureAnalyzerEngine
    ) -> None:
        _add_sample(
            engine,
            pipeline_stage=PipelineStage.EXPORTER,
            queue_depth=9000,
            queue_capacity=10000,
        )
        _add_sample(
            engine,
            pipeline_stage=PipelineStage.RECEIVER,
            queue_depth=100,
            queue_capacity=10000,
        )
        results = engine.trace_backpressure_source()
        assert results[0]["avg_queue_fill_pct"] >= results[-1]["avg_queue_fill_pct"]

    def test_measure_queue_drain_rate_deficit_positive(
        self, engine: PipelineBackpressureAnalyzerEngine
    ) -> None:
        _add_sample(
            engine, pipeline_id="overfull", fill_rate_per_sec=2000.0, drain_rate_per_sec=500.0
        )
        results = engine.measure_queue_drain_rate()
        overfull = next(r for r in results if r["pipeline_id"] == "overfull")
        assert overfull["deficit"] > 0
        assert overfull["draining"] is False

    def test_simulate_load_shed_impact_75pct_relieves(
        self, engine: PipelineBackpressureAnalyzerEngine
    ) -> None:
        _add_sample(
            engine, pipeline_id="heavy", fill_rate_per_sec=4000.0, drain_rate_per_sec=1000.0
        )
        results = engine.simulate_load_shed_impact()
        heavy = next(r for r in results if r["pipeline_id"] == "heavy")
        assert heavy["scenarios"]["shed_75_pct"]["relieved"] is True

    def test_simulate_25pct_does_not_relieve_heavy_load(
        self, engine: PipelineBackpressureAnalyzerEngine
    ) -> None:
        _add_sample(
            engine, pipeline_id="very_heavy", fill_rate_per_sec=4000.0, drain_rate_per_sec=100.0
        )
        results = engine.simulate_load_shed_impact()
        heavy = next(r for r in results if r["pipeline_id"] == "very_heavy")
        assert heavy["scenarios"]["shed_25_pct"]["relieved"] is False
