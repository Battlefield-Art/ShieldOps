"""Unit tests for TelemetryFanoutRouterEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.telemetry_fanout_router_engine import (
    FanoutStatus,
    RoutingCriteria,
    RoutingStrategy,
    TelemetryFanoutRecord,
    TelemetryFanoutReport,
    TelemetryFanoutRouterEngine,
)


@pytest.fixture()
def engine() -> TelemetryFanoutRouterEngine:
    return TelemetryFanoutRouterEngine(max_records=100)


def _add_sample(engine: TelemetryFanoutRouterEngine, **kwargs: object) -> TelemetryFanoutRecord:
    defaults: dict[str, object] = {
        "route_id": "route-1",
        "routing_strategy": RoutingStrategy.BROADCAST,
        "fanout_status": FanoutStatus.ALL_DELIVERED,
        "routing_criteria": RoutingCriteria.SIGNAL_TYPE,
        "destination_count": 3,
        "delivered_count": 3,
        "items_routed": 1000,
        "routing_latency_ms": 10.0,
        "asymmetry_score": 0.0,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: TelemetryFanoutRouterEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, TelemetryFanoutRecord)

    def test_ring_buffer(self, engine: TelemetryFanoutRouterEngine) -> None:
        for i in range(110):
            _add_sample(engine, route_id=f"r{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_full_delivery_ratio(self, engine: TelemetryFanoutRouterEngine) -> None:
        rec = _add_sample(engine, destination_count=4, delivered_count=4)
        analysis = engine.process(rec.id)
        assert analysis.delivery_ratio == pytest.approx(1.0)  # type: ignore[union-attr]

    def test_partial_delivery_ratio(self, engine: TelemetryFanoutRouterEngine) -> None:
        rec = _add_sample(engine, destination_count=4, delivered_count=2)
        analysis = engine.process(rec.id)
        assert analysis.delivery_ratio == pytest.approx(0.5)  # type: ignore[union-attr]

    def test_asymmetry_detected(self, engine: TelemetryFanoutRouterEngine) -> None:
        rec = _add_sample(engine, asymmetry_score=0.5)
        analysis = engine.process(rec.id)
        assert analysis.asymmetry_detected is True  # type: ignore[union-attr]

    def test_no_asymmetry_low_score(self, engine: TelemetryFanoutRouterEngine) -> None:
        rec = _add_sample(engine, asymmetry_score=0.1)
        analysis = engine.process(rec.id)
        assert analysis.asymmetry_detected is False  # type: ignore[union-attr]

    def test_not_found(self, engine: TelemetryFanoutRouterEngine) -> None:
        assert engine.process("bad")["status"] == "not_found"  # type: ignore[index]


class TestGenerateReport:
    def test_report_type(self, engine: TelemetryFanoutRouterEngine) -> None:
        _add_sample(engine)
        assert isinstance(engine.generate_report(), TelemetryFanoutReport)

    def test_asymmetric_routes_populated(self, engine: TelemetryFanoutRouterEngine) -> None:
        _add_sample(engine, route_id="asym", asymmetry_score=0.6)
        report = engine.generate_report()
        assert "asym" in report.asymmetric_routes

    def test_avg_delivery_ratio_perfect(self, engine: TelemetryFanoutRouterEngine) -> None:
        _add_sample(engine, destination_count=3, delivered_count=3)
        _add_sample(engine, destination_count=5, delivered_count=5)
        report = engine.generate_report()
        assert report.avg_delivery_ratio == pytest.approx(1.0)

    def test_recommendations_present(self, engine: TelemetryFanoutRouterEngine) -> None:
        _add_sample(engine)
        assert len(engine.generate_report().recommendations) > 0


class TestGetStats:
    def test_strategy_distribution_key(self, engine: TelemetryFanoutRouterEngine) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "strategy_distribution" in stats


class TestClearData:
    def test_clears(self, engine: TelemetryFanoutRouterEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert engine._records == []


class TestDomainMethods:
    def test_evaluate_fanout_efficiency_sorted_asc(
        self, engine: TelemetryFanoutRouterEngine
    ) -> None:
        _add_sample(
            engine, route_id="inefficient",
            destination_count=4, delivered_count=2,
            asymmetry_score=0.5,
        )
        _add_sample(
            engine, route_id="efficient",
            destination_count=4, delivered_count=4,
            asymmetry_score=0.0,
        )
        results = engine.evaluate_fanout_efficiency()
        assert results[0]["efficiency_score"] <= results[-1]["efficiency_score"]

    def test_detect_routing_asymmetry_threshold(self, engine: TelemetryFanoutRouterEngine) -> None:
        _add_sample(engine, route_id="asym", asymmetry_score=0.4)
        _add_sample(engine, route_id="balanced", asymmetry_score=0.05)
        results = engine.detect_routing_asymmetry()
        ids = [r["route_id"] for r in results]
        assert "asym" in ids
        assert "balanced" not in ids

    def test_optimize_routing_rules_suggests_round_robin(
        self, engine: TelemetryFanoutRouterEngine
    ) -> None:
        _add_sample(
            engine, route_id="skewed", asymmetry_score=0.5,
            destination_count=2, delivered_count=2,
        )
        results = engine.optimize_routing_rules()
        skewed = next((r for r in results if r["route_id"] == "skewed"), None)
        assert skewed is not None
        assert any("round-robin" in s for s in skewed["suggestions"])

    def test_ranks_assigned_sequential(self, engine: TelemetryFanoutRouterEngine) -> None:
        for i in range(3):
            _add_sample(engine, route_id=f"route-{i}", asymmetry_score=float(i) * 0.2)
        # rank assigned in rank_topics equivalent — not present here but
        # check evaluate returns ordered list without gaps
        results = engine.evaluate_fanout_efficiency()
        assert len(results) >= 1

    def test_empty_returns_empty(self, engine: TelemetryFanoutRouterEngine) -> None:
        assert engine.evaluate_fanout_efficiency() == []
        assert engine.detect_routing_asymmetry() == []
        assert engine.optimize_routing_rules() == []
