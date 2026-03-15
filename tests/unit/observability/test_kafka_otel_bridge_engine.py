"""Unit tests for KafkaOtelBridgeEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.kafka_otel_bridge_engine import (
    BridgeFidelity,
    BridgeMode,
    KafkaOtelBridgeEngine,
    KafkaOtelBridgeRecord,
    KafkaOtelBridgeReport,
    SignalMapping,
)


@pytest.fixture()
def engine() -> KafkaOtelBridgeEngine:
    return KafkaOtelBridgeEngine(max_records=100)


def _add_sample(engine: KafkaOtelBridgeEngine, **kwargs: object) -> KafkaOtelBridgeRecord:
    defaults: dict[str, object] = {
        "topic": "orders",
        "bridge_mode": BridgeMode.PASSTHROUGH,
        "signal_mapping": SignalMapping.MESSAGE_TO_SPAN,
        "bridge_fidelity": BridgeFidelity.EXACT,
        "messages_per_sec": 500.0,
        "signal_value_score": 80.0,
        "mapping_drift_pct": 0.0,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: KafkaOtelBridgeEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, KafkaOtelBridgeRecord)
        assert rec.topic == "orders"

    def test_id_assigned(self, engine: KafkaOtelBridgeEngine) -> None:
        rec = _add_sample(engine)
        assert rec.id != ""

    def test_ring_buffer_eviction(self, engine: KafkaOtelBridgeEngine) -> None:
        for i in range(110):
            _add_sample(engine, topic=f"t{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_found_record_returns_analysis(self, engine: KafkaOtelBridgeEngine) -> None:
        rec = _add_sample(engine, signal_value_score=90.0)
        result = engine.process(rec.id)
        assert hasattr(result, "fidelity_score")

    def test_not_found_returns_dict(self, engine: KafkaOtelBridgeEngine) -> None:
        result = engine.process("nonexistent-id")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"

    def test_drift_detected_flag(self, engine: KafkaOtelBridgeEngine) -> None:
        rec = _add_sample(engine, mapping_drift_pct=10.0)
        analysis = engine.process(rec.id)
        assert hasattr(analysis, "drift_detected")
        assert analysis.drift_detected is True  # type: ignore[union-attr]

    def test_no_drift_when_low(self, engine: KafkaOtelBridgeEngine) -> None:
        rec = _add_sample(engine, mapping_drift_pct=1.0)
        analysis = engine.process(rec.id)
        assert analysis.drift_detected is False  # type: ignore[union-attr]

    def test_fidelity_score_lossy_lower(self, engine: KafkaOtelBridgeEngine) -> None:
        rec_exact = _add_sample(engine, bridge_fidelity=BridgeFidelity.EXACT, signal_value_score=100.0)
        rec_lossy = _add_sample(engine, bridge_fidelity=BridgeFidelity.LOSSY, signal_value_score=100.0)
        a_exact = engine.process(rec_exact.id)
        a_lossy = engine.process(rec_lossy.id)
        assert a_exact.fidelity_score > a_lossy.fidelity_score  # type: ignore[union-attr]


class TestGenerateReport:
    def test_returns_report(self, engine: KafkaOtelBridgeEngine) -> None:
        _add_sample(engine)
        report = engine.generate_report()
        assert isinstance(report, KafkaOtelBridgeReport)

    def test_counts_correct(self, engine: KafkaOtelBridgeEngine) -> None:
        _add_sample(engine)
        _add_sample(engine, topic="payments")
        report = engine.generate_report()
        assert report.total_records == 2

    def test_drifted_topics_populated(self, engine: KafkaOtelBridgeEngine) -> None:
        _add_sample(engine, topic="drift-topic", mapping_drift_pct=20.0)
        report = engine.generate_report()
        assert "drift-topic" in report.drifted_topics

    def test_recommendations_not_empty(self, engine: KafkaOtelBridgeEngine) -> None:
        _add_sample(engine)
        report = engine.generate_report()
        assert len(report.recommendations) > 0


class TestGetStats:
    def test_returns_dict(self, engine: KafkaOtelBridgeEngine) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "total_records" in stats
        assert "mode_distribution" in stats


class TestClearData:
    def test_clears_records(self, engine: KafkaOtelBridgeEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert engine._records == []

    def test_returns_cleared(self, engine: KafkaOtelBridgeEngine) -> None:
        result = engine.clear_data()
        assert result["status"] == "cleared"


class TestDomainMethods:
    def test_evaluate_bridge_throughput(self, engine: KafkaOtelBridgeEngine) -> None:
        _add_sample(engine, topic="a", messages_per_sec=1000.0)
        _add_sample(engine, topic="b", messages_per_sec=200.0)
        results = engine.evaluate_bridge_throughput()
        assert results[0]["avg_messages_per_sec"] >= results[1]["avg_messages_per_sec"]

    def test_detect_mapping_drift(self, engine: KafkaOtelBridgeEngine) -> None:
        _add_sample(engine, topic="drifted", mapping_drift_pct=15.0)
        _add_sample(engine, topic="clean", mapping_drift_pct=0.5)
        results = engine.detect_mapping_drift()
        topics = [r["topic"] for r in results]
        assert "drifted" in topics
        assert "clean" not in topics

    def test_rank_topics_by_signal_value(self, engine: KafkaOtelBridgeEngine) -> None:
        _add_sample(engine, topic="high", signal_value_score=95.0)
        _add_sample(engine, topic="low", signal_value_score=10.0)
        results = engine.rank_topics_by_signal_value()
        assert results[0]["topic"] == "high"
        assert results[0]["rank"] == 1

    def test_rank_assigns_sequential_ranks(self, engine: KafkaOtelBridgeEngine) -> None:
        for i in range(3):
            _add_sample(engine, topic=f"topic-{i}", signal_value_score=float(i * 10))
        results = engine.rank_topics_by_signal_value()
        ranks = [r["rank"] for r in results]
        assert ranks == list(range(1, len(ranks) + 1))
