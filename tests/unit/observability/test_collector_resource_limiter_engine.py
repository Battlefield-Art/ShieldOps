"""Unit tests for CollectorResourceLimiterEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.collector_resource_limiter_engine import (
    CollectorResourceLimiterEngine,
    CollectorResourceRecord,
    CollectorResourceReport,
    LimitStatus,
    MitigationAction,
    ResourceType,
)


@pytest.fixture()
def engine() -> CollectorResourceLimiterEngine:
    return CollectorResourceLimiterEngine(max_records=100)


def _add_sample(
    engine: CollectorResourceLimiterEngine, **kwargs: object
) -> CollectorResourceRecord:
    defaults: dict[str, object] = {
        "collector_id": "col-1",
        "resource_type": ResourceType.MEMORY_RSS,
        "limit_status": LimitStatus.WITHIN_BUDGET,
        "mitigation_action": MitigationAction.INCREASE_SAMPLING,
        "current_usage": 200.0,
        "limit_value": 1000.0,
        "usage_trend_pct_per_hour": 1.0,
        "restart_count": 0,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: CollectorResourceLimiterEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, CollectorResourceRecord)

    def test_ring_buffer(self, engine: CollectorResourceLimiterEngine) -> None:
        for i in range(110):
            _add_sample(engine, collector_id=f"c{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_headroom_calculated(self, engine: CollectorResourceLimiterEngine) -> None:
        rec = _add_sample(engine, current_usage=200.0, limit_value=1000.0)
        analysis = engine.process(rec.id)
        assert analysis.headroom_pct == 80.0  # type: ignore[union-attr]

    def test_oom_risk_at_limit_memory(self, engine: CollectorResourceLimiterEngine) -> None:
        rec = _add_sample(
            engine,
            resource_type=ResourceType.MEMORY_RSS,
            limit_status=LimitStatus.AT_LIMIT,
            current_usage=999.0,
            limit_value=1000.0,
        )
        analysis = engine.process(rec.id)
        assert analysis.oom_risk is True  # type: ignore[union-attr]

    def test_no_oom_risk_within_budget(self, engine: CollectorResourceLimiterEngine) -> None:
        rec = _add_sample(engine, limit_status=LimitStatus.WITHIN_BUDGET)
        analysis = engine.process(rec.id)
        assert analysis.oom_risk is False  # type: ignore[union-attr]

    def test_hours_to_limit_computed(self, engine: CollectorResourceLimiterEngine) -> None:
        rec = _add_sample(
            engine,
            current_usage=500.0,
            limit_value=1000.0,
            usage_trend_pct_per_hour=10.0,
        )
        analysis = engine.process(rec.id)
        assert analysis.hours_to_limit == pytest.approx(5.0, rel=0.1)  # type: ignore[union-attr]

    def test_not_found(self, engine: CollectorResourceLimiterEngine) -> None:
        assert engine.process("bad")["status"] == "not_found"  # type: ignore[index]


class TestGenerateReport:
    def test_report_type(self, engine: CollectorResourceLimiterEngine) -> None:
        _add_sample(engine)
        assert isinstance(engine.generate_report(), CollectorResourceReport)

    def test_at_risk_collectors_populated(self, engine: CollectorResourceLimiterEngine) -> None:
        _add_sample(engine, collector_id="risk", limit_status=LimitStatus.AT_LIMIT)
        report = engine.generate_report()
        assert "risk" in report.at_risk_collectors

    def test_recommendations_present(self, engine: CollectorResourceLimiterEngine) -> None:
        _add_sample(engine)
        assert len(engine.generate_report().recommendations) > 0

    def test_avg_headroom_calculated(self, engine: CollectorResourceLimiterEngine) -> None:
        _add_sample(engine, current_usage=200.0, limit_value=1000.0)
        report = engine.generate_report()
        assert report.avg_headroom_pct == pytest.approx(80.0, rel=0.01)


class TestGetStats:
    def test_limit_status_distribution_key(self, engine: CollectorResourceLimiterEngine) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "limit_status_distribution" in stats


class TestClearData:
    def test_clears(self, engine: CollectorResourceLimiterEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert engine._records == []


class TestDomainMethods:
    def test_predict_oom_risk_sorted_by_hours(self, engine: CollectorResourceLimiterEngine) -> None:
        _add_sample(
            engine,
            collector_id="imminent",
            resource_type=ResourceType.MEMORY_RSS,
            current_usage=900.0,
            limit_value=1000.0,
            usage_trend_pct_per_hour=20.0,
        )
        _add_sample(
            engine,
            collector_id="stable",
            resource_type=ResourceType.MEMORY_RSS,
            current_usage=100.0,
            limit_value=1000.0,
            usage_trend_pct_per_hour=0.1,
        )
        results = engine.predict_oom_risk()
        assert results[0]["hours_to_oom"] <= results[-1]["hours_to_oom"]

    def test_evaluate_limit_headroom_sorted_asc(
        self, engine: CollectorResourceLimiterEngine
    ) -> None:
        _add_sample(engine, collector_id="tight", current_usage=950.0, limit_value=1000.0)
        _add_sample(engine, collector_id="roomy", current_usage=100.0, limit_value=1000.0)
        results = engine.evaluate_limit_headroom()
        assert results[0]["avg_headroom_pct"] <= results[-1]["avg_headroom_pct"]

    def test_recommend_resource_allocation_increase(
        self, engine: CollectorResourceLimiterEngine
    ) -> None:
        _add_sample(engine, collector_id="tight", current_usage=990.0, limit_value=1000.0)
        results = engine.recommend_resource_allocation()
        assert any(r["collector_id"] == "tight" for r in results)

    def test_empty_predict_oom_returns_empty(self, engine: CollectorResourceLimiterEngine) -> None:
        assert engine.predict_oom_risk() == []
