"""Unit tests for ReceiverPipelineStageEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.receiver_pipeline_stage_engine import (
    IngestionPattern,
    ReceiverHealth,
    ReceiverPipelineRecord,
    ReceiverPipelineReport,
    ReceiverPipelineStageEngine,
    ReceiverType,
)


@pytest.fixture()
def engine() -> ReceiverPipelineStageEngine:
    return ReceiverPipelineStageEngine(max_records=100)


def _add_sample(engine: ReceiverPipelineStageEngine, **kwargs: object) -> ReceiverPipelineRecord:
    defaults: dict[str, object] = {
        "receiver_id": "recv-1",
        "receiver_type": ReceiverType.OTLP_GRPC,
        "receiver_health": ReceiverHealth.ACCEPTING,
        "ingestion_pattern": IngestionPattern.STEADY,
        "accepted_per_sec": 1000.0,
        "rejected_per_sec": 0.0,
        "throttle_pct": 0.0,
        "latency_ms": 5.0,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: ReceiverPipelineStageEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, ReceiverPipelineRecord)

    def test_ring_buffer(self, engine: ReceiverPipelineStageEngine) -> None:
        for i in range(110):
            _add_sample(engine, receiver_id=f"r{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_acceptance_rate_full(self, engine: ReceiverPipelineStageEngine) -> None:
        rec = _add_sample(engine, accepted_per_sec=100.0, rejected_per_sec=0.0)
        analysis = engine.process(rec.id)
        assert analysis.acceptance_rate == 100.0  # type: ignore[union-attr]

    def test_acceptance_rate_partial(self, engine: ReceiverPipelineStageEngine) -> None:
        rec = _add_sample(engine, accepted_per_sec=75.0, rejected_per_sec=25.0)
        analysis = engine.process(rec.id)
        assert analysis.acceptance_rate == 75.0  # type: ignore[union-attr]

    def test_saturated_on_throttle(self, engine: ReceiverPipelineStageEngine) -> None:
        rec = _add_sample(engine, throttle_pct=85.0)
        analysis = engine.process(rec.id)
        assert analysis.saturated is True  # type: ignore[union-attr]

    def test_not_saturated_low_throttle(self, engine: ReceiverPipelineStageEngine) -> None:
        rec = _add_sample(engine, throttle_pct=10.0)
        analysis = engine.process(rec.id)
        assert analysis.saturated is False  # type: ignore[union-attr]

    def test_not_found(self, engine: ReceiverPipelineStageEngine) -> None:
        result = engine.process("bad-id")
        assert result["status"] == "not_found"  # type: ignore[index]


class TestGenerateReport:
    def test_report_type(self, engine: ReceiverPipelineStageEngine) -> None:
        _add_sample(engine)
        assert isinstance(engine.generate_report(), ReceiverPipelineReport)

    def test_saturated_populated(self, engine: ReceiverPipelineStageEngine) -> None:
        _add_sample(engine, receiver_id="sat", throttle_pct=90.0)
        report = engine.generate_report()
        assert "sat" in report.saturated_receivers

    def test_avg_accepted_per_sec(self, engine: ReceiverPipelineStageEngine) -> None:
        _add_sample(engine, accepted_per_sec=200.0)
        _add_sample(engine, accepted_per_sec=400.0)
        report = engine.generate_report()
        assert report.avg_accepted_per_sec == 300.0

    def test_recommendations_not_empty(self, engine: ReceiverPipelineStageEngine) -> None:
        _add_sample(engine)
        report = engine.generate_report()
        assert len(report.recommendations) > 0


class TestGetStats:
    def test_contains_health_distribution(self, engine: ReceiverPipelineStageEngine) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "health_distribution" in stats


class TestClearData:
    def test_clears_records(self, engine: ReceiverPipelineStageEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert engine._records == []


class TestDomainMethods:
    def test_analyze_acceptance_rate_sorted_asc(self, engine: ReceiverPipelineStageEngine) -> None:
        _add_sample(engine, receiver_id="good", accepted_per_sec=990.0, rejected_per_sec=10.0)
        _add_sample(engine, receiver_id="bad", accepted_per_sec=500.0, rejected_per_sec=500.0)
        results = engine.analyze_receiver_acceptance_rate()
        assert results[0]["acceptance_rate_pct"] <= results[-1]["acceptance_rate_pct"]

    def test_detect_receiver_saturation_includes_throttled(
        self, engine: ReceiverPipelineStageEngine
    ) -> None:
        _add_sample(engine, receiver_id="throttled", throttle_pct=70.0)
        results = engine.detect_receiver_saturation()
        assert any(r["receiver_id"] == "throttled" for r in results)

    def test_compare_receiver_efficiency_sorted_desc(
        self, engine: ReceiverPipelineStageEngine
    ) -> None:
        _add_sample(engine, receiver_type=ReceiverType.OTLP_GRPC, accepted_per_sec=2000.0, latency_ms=1.0)
        _add_sample(engine, receiver_type=ReceiverType.PROMETHEUS, accepted_per_sec=100.0, latency_ms=50.0)
        results = engine.compare_receiver_efficiency()
        assert results[0]["efficiency_score"] >= results[-1]["efficiency_score"]

    def test_empty_engine_returns_empty_lists(self, engine: ReceiverPipelineStageEngine) -> None:
        assert engine.analyze_receiver_acceptance_rate() == []
        assert engine.detect_receiver_saturation() == []
        assert engine.compare_receiver_efficiency() == []
