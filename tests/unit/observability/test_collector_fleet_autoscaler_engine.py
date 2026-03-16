"""Unit tests for CollectorFleetAutoscalerEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.collector_fleet_autoscaler_engine import (
    CollectorFleetAutoscalerEngine,
    CollectorFleetRecord,
    CollectorFleetReport,
    FleetHealth,
    ScalingAction,
    ScalingTrigger,
)


@pytest.fixture()
def engine() -> CollectorFleetAutoscalerEngine:
    return CollectorFleetAutoscalerEngine(max_records=100)


def _add_sample(engine: CollectorFleetAutoscalerEngine, **kwargs: object) -> CollectorFleetRecord:
    defaults: dict[str, object] = {
        "collector_id": "col-1",
        "scaling_trigger": ScalingTrigger.CPU_PRESSURE,
        "scaling_action": ScalingAction.NO_ACTION,
        "fleet_health": FleetHealth.HEALTHY,
        "cpu_utilization": 40.0,
        "memory_utilization": 35.0,
        "queue_depth": 100,
        "throughput_lag_sec": 0.5,
        "replica_count": 2,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: CollectorFleetAutoscalerEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, CollectorFleetRecord)

    def test_ring_buffer(self, engine: CollectorFleetAutoscalerEngine) -> None:
        for i in range(110):
            _add_sample(engine, collector_id=f"c{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_scale_up_high_pressure(self, engine: CollectorFleetAutoscalerEngine) -> None:
        # pressure = 90*0.4 + 90*0.4 + min(0/1000,1)*20 = 72 — triggers REBALANCE not SCALE_UP
        # need pressure > 80: cpu=100, mem=100 -> 40+40+0=80 still borderline; add queue
        rec = _add_sample(
            engine, cpu_utilization=100.0, memory_utilization=100.0, queue_depth=10000
        )
        analysis = engine.process(rec.id)
        assert analysis.scaling_action == ScalingAction.SCALE_UP  # type: ignore[union-attr]

    def test_scale_down_low_pressure(self, engine: CollectorFleetAutoscalerEngine) -> None:
        rec = _add_sample(engine, cpu_utilization=5.0, memory_utilization=5.0, queue_depth=0)
        analysis = engine.process(rec.id)
        assert analysis.scaling_action == ScalingAction.SCALE_DOWN  # type: ignore[union-attr]

    def test_not_found(self, engine: CollectorFleetAutoscalerEngine) -> None:
        result = engine.process("missing")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"

    def test_hotspot_detected(self, engine: CollectorFleetAutoscalerEngine) -> None:
        # hotspot threshold is pressure > 70; cpu=95, mem=95 -> 95*0.4+95*0.4=76 > 70
        rec = _add_sample(engine, cpu_utilization=95.0, memory_utilization=95.0, queue_depth=0)
        analysis = engine.process(rec.id)
        assert analysis.is_hotspot is True  # type: ignore[union-attr]


class TestGenerateReport:
    def test_report_type(self, engine: CollectorFleetAutoscalerEngine) -> None:
        _add_sample(engine)
        assert isinstance(engine.generate_report(), CollectorFleetReport)

    def test_overloaded_populates_hotspots(self, engine: CollectorFleetAutoscalerEngine) -> None:
        _add_sample(engine, collector_id="hot", fleet_health=FleetHealth.OVERLOADED)
        report = engine.generate_report()
        assert "hot" in report.hotspot_collectors

    def test_recommendations_exist(self, engine: CollectorFleetAutoscalerEngine) -> None:
        _add_sample(engine)
        report = engine.generate_report()
        assert len(report.recommendations) > 0

    def test_avg_cpu_calculated(self, engine: CollectorFleetAutoscalerEngine) -> None:
        _add_sample(engine, cpu_utilization=60.0)
        _add_sample(engine, cpu_utilization=40.0)
        report = engine.generate_report()
        assert report.avg_cpu_utilization == 50.0


class TestGetStats:
    def test_keys_present(self, engine: CollectorFleetAutoscalerEngine) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "total_records" in stats
        assert "health_distribution" in stats


class TestClearData:
    def test_clears(self, engine: CollectorFleetAutoscalerEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert len(engine._records) == 0


class TestDomainMethods:
    def test_compute_scaling_decision_sorted(self, engine: CollectorFleetAutoscalerEngine) -> None:
        _add_sample(engine, collector_id="high", cpu_utilization=85.0, memory_utilization=85.0)
        _add_sample(engine, collector_id="low", cpu_utilization=10.0, memory_utilization=10.0)
        results = engine.compute_scaling_decision()
        assert results[0]["collector_id"] == "high"

    def test_detect_collector_hotspots(self, engine: CollectorFleetAutoscalerEngine) -> None:
        for _ in range(4):
            _add_sample(engine, collector_id="overloaded", fleet_health=FleetHealth.OVERLOADED)
        results = engine.detect_collector_hotspots()
        assert any(r["collector_id"] == "overloaded" for r in results)

    def test_forecast_fleet_capacity_needs_two_samples(
        self, engine: CollectorFleetAutoscalerEngine
    ) -> None:
        _add_sample(engine, collector_id="growing", throughput_lag_sec=1.0, replica_count=2)
        _add_sample(engine, collector_id="growing", throughput_lag_sec=10.0, replica_count=2)
        results = engine.forecast_fleet_capacity()
        assert any(r["collector_id"] == "growing" for r in results)

    def test_forecast_skips_single_sample(self, engine: CollectorFleetAutoscalerEngine) -> None:
        _add_sample(engine, collector_id="singleton")
        results = engine.forecast_fleet_capacity()
        assert not any(r["collector_id"] == "singleton" for r in results)
