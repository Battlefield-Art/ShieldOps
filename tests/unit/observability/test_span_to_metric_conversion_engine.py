"""Unit tests for SpanToMetricConversionEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.span_to_metric_conversion_engine import (
    CardinalityRisk,
    ConversionType,
    MetricGranularity,
    SpanToMetricConversionEngine,
    SpanToMetricRecord,
    SpanToMetricReport,
)


@pytest.fixture()
def engine() -> SpanToMetricConversionEngine:
    return SpanToMetricConversionEngine(max_records=100)


def _add_sample(engine: SpanToMetricConversionEngine, **kwargs: object) -> SpanToMetricRecord:
    defaults: dict[str, object] = {
        "rule_id": "rule-1",
        "conversion_type": ConversionType.REQUEST_RATE,
        "cardinality_risk": CardinalityRisk.SAFE,
        "metric_granularity": MetricGranularity.SERVICE_LEVEL,
        "spans_per_sec": 1000.0,
        "metrics_produced": 10,
        "unique_label_sets": 50,
        "accuracy_pct": 99.0,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: SpanToMetricConversionEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, SpanToMetricRecord)

    def test_ring_buffer(self, engine: SpanToMetricConversionEngine) -> None:
        for i in range(110):
            _add_sample(engine, rule_id=f"r{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_explosion_detected_explosive(self, engine: SpanToMetricConversionEngine) -> None:
        rec = _add_sample(engine, cardinality_risk=CardinalityRisk.EXPLOSIVE)
        analysis = engine.process(rec.id)
        assert analysis.explosion_detected is True  # type: ignore[union-attr]

    def test_no_explosion_safe(self, engine: SpanToMetricConversionEngine) -> None:
        rec = _add_sample(engine, cardinality_risk=CardinalityRisk.SAFE)
        analysis = engine.process(rec.id)
        assert analysis.explosion_detected is False  # type: ignore[union-attr]

    def test_conversion_ratio_computed(self, engine: SpanToMetricConversionEngine) -> None:
        rec = _add_sample(engine, spans_per_sec=1000.0, metrics_produced=100)
        analysis = engine.process(rec.id)
        assert analysis.conversion_ratio == pytest.approx(0.1, rel=1e-3)  # type: ignore[union-attr]

    def test_explosion_detected_label_threshold(self, engine: SpanToMetricConversionEngine) -> None:
        rec = _add_sample(engine, unique_label_sets=60000, cardinality_risk=CardinalityRisk.HIGH)
        analysis = engine.process(rec.id)
        assert analysis.explosion_detected is True  # type: ignore[union-attr]

    def test_not_found(self, engine: SpanToMetricConversionEngine) -> None:
        assert engine.process("bad")["status"] == "not_found"  # type: ignore[index]


class TestGenerateReport:
    def test_report_type(self, engine: SpanToMetricConversionEngine) -> None:
        _add_sample(engine)
        assert isinstance(engine.generate_report(), SpanToMetricReport)

    def test_explosive_rules_populated(self, engine: SpanToMetricConversionEngine) -> None:
        _add_sample(engine, rule_id="boom", cardinality_risk=CardinalityRisk.EXPLOSIVE)
        report = engine.generate_report()
        assert "boom" in report.explosive_rules

    def test_avg_accuracy_calculated(self, engine: SpanToMetricConversionEngine) -> None:
        _add_sample(engine, accuracy_pct=80.0)
        _add_sample(engine, accuracy_pct=60.0)
        report = engine.generate_report()
        assert report.avg_accuracy_pct == 70.0

    def test_recommendations_present(self, engine: SpanToMetricConversionEngine) -> None:
        _add_sample(engine)
        assert len(engine.generate_report().recommendations) > 0


class TestGetStats:
    def test_cardinality_distribution_key(self, engine: SpanToMetricConversionEngine) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "cardinality_distribution" in stats


class TestClearData:
    def test_clears(self, engine: SpanToMetricConversionEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert engine._records == []


class TestDomainMethods:
    def test_evaluate_conversion_accuracy_sorted_asc(
        self, engine: SpanToMetricConversionEngine
    ) -> None:
        _add_sample(engine, rule_id="low", accuracy_pct=50.0)
        _add_sample(engine, rule_id="high", accuracy_pct=99.0)
        results = engine.evaluate_conversion_accuracy()
        assert results[0]["avg_accuracy_pct"] <= results[-1]["avg_accuracy_pct"]

    def test_detect_cardinality_explosion_threshold(
        self, engine: SpanToMetricConversionEngine
    ) -> None:
        _add_sample(engine, rule_id="big", unique_label_sets=20000)
        _add_sample(engine, rule_id="small", unique_label_sets=100)
        results = engine.detect_cardinality_explosion()
        ids = [r["rule_id"] for r in results]
        assert "big" in ids
        assert "small" not in ids

    def test_optimize_conversion_rules_suggestions(
        self, engine: SpanToMetricConversionEngine
    ) -> None:
        _add_sample(
            engine,
            rule_id="bad",
            unique_label_sets=15000,
            accuracy_pct=85.0,
            metric_granularity=MetricGranularity.ATTRIBUTE_LEVEL,
        )
        results = engine.optimize_conversion_rules()
        assert any(r["rule_id"] == "bad" for r in results)

    def test_empty_returns_empty(self, engine: SpanToMetricConversionEngine) -> None:
        assert engine.evaluate_conversion_accuracy() == []
        assert engine.detect_cardinality_explosion() == []
        assert engine.optimize_conversion_rules() == []
