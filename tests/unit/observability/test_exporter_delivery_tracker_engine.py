"""Unit tests for ExporterDeliveryTrackerEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.exporter_delivery_tracker_engine import (
    DeliveryStatus,
    ExporterBackend,
    ExporterDeliveryRecord,
    ExporterDeliveryReport,
    ExporterDeliveryTrackerEngine,
    ExportFailureReason,
)


@pytest.fixture()
def engine() -> ExporterDeliveryTrackerEngine:
    return ExporterDeliveryTrackerEngine(max_records=100)


def _add_sample(engine: ExporterDeliveryTrackerEngine, **kwargs: object) -> ExporterDeliveryRecord:
    defaults: dict[str, object] = {
        "exporter_id": "exp-1",
        "exporter_backend": ExporterBackend.SPLUNK,
        "delivery_status": DeliveryStatus.DELIVERED,
        "failure_reason": ExportFailureReason.BACKEND_UNAVAILABLE,
        "items_sent": 1000,
        "items_dropped": 0,
        "queue_size": 0,
        "cost_per_million_items": 5.0,
        "latency_ms": 50.0,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: ExporterDeliveryTrackerEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, ExporterDeliveryRecord)

    def test_ring_buffer(self, engine: ExporterDeliveryTrackerEngine) -> None:
        for i in range(110):
            _add_sample(engine, exporter_id=f"e{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_full_reliability(self, engine: ExporterDeliveryTrackerEngine) -> None:
        rec = _add_sample(engine, items_sent=100, items_dropped=0)
        analysis = engine.process(rec.id)
        assert analysis.delivery_reliability_pct == 100.0  # type: ignore[union-attr]

    def test_partial_reliability(self, engine: ExporterDeliveryTrackerEngine) -> None:
        rec = _add_sample(engine, items_sent=80, items_dropped=20)
        analysis = engine.process(rec.id)
        assert analysis.delivery_reliability_pct == 80.0  # type: ignore[union-attr]

    def test_backpressure_large_queue(self, engine: ExporterDeliveryTrackerEngine) -> None:
        rec = _add_sample(engine, queue_size=20000)
        analysis = engine.process(rec.id)
        assert analysis.backpressure_detected is True  # type: ignore[union-attr]

    def test_no_backpressure_small_queue(self, engine: ExporterDeliveryTrackerEngine) -> None:
        rec = _add_sample(engine, queue_size=100, delivery_status=DeliveryStatus.DELIVERED)
        analysis = engine.process(rec.id)
        assert analysis.backpressure_detected is False  # type: ignore[union-attr]

    def test_not_found(self, engine: ExporterDeliveryTrackerEngine) -> None:
        assert engine.process("bad")["status"] == "not_found"  # type: ignore[index]


class TestGenerateReport:
    def test_report_type(self, engine: ExporterDeliveryTrackerEngine) -> None:
        _add_sample(engine)
        assert isinstance(engine.generate_report(), ExporterDeliveryReport)

    def test_backpressure_exporters_populated(self, engine: ExporterDeliveryTrackerEngine) -> None:
        _add_sample(engine, exporter_id="bp", queue_size=15000)
        report = engine.generate_report()
        assert "bp" in report.backpressure_exporters

    def test_avg_reliability_perfect(self, engine: ExporterDeliveryTrackerEngine) -> None:
        _add_sample(engine, items_sent=100, items_dropped=0)
        _add_sample(engine, items_sent=100, items_dropped=0)
        report = engine.generate_report()
        assert report.avg_reliability_pct == 100.0

    def test_recommendations_present(self, engine: ExporterDeliveryTrackerEngine) -> None:
        _add_sample(engine)
        assert len(engine.generate_report().recommendations) > 0


class TestGetStats:
    def test_status_distribution_key(self, engine: ExporterDeliveryTrackerEngine) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "status_distribution" in stats


class TestClearData:
    def test_clears(self, engine: ExporterDeliveryTrackerEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert engine._records == []


class TestDomainMethods:
    def test_compute_delivery_reliability_sorted_asc(
        self, engine: ExporterDeliveryTrackerEngine
    ) -> None:
        _add_sample(engine, exporter_id="good", items_sent=100, items_dropped=0)
        _add_sample(engine, exporter_id="bad", items_sent=50, items_dropped=50)
        results = engine.compute_delivery_reliability()
        assert results[0]["reliability_pct"] <= results[-1]["reliability_pct"]

    def test_detect_export_backpressure_threshold(
        self, engine: ExporterDeliveryTrackerEngine
    ) -> None:
        _add_sample(engine, exporter_id="bp", queue_size=8000)
        results = engine.detect_export_backpressure()
        assert any(r["exporter_id"] == "bp" for r in results)

    def test_rank_backends_by_cost_efficiency_ranks(
        self, engine: ExporterDeliveryTrackerEngine
    ) -> None:
        _add_sample(engine, exporter_backend=ExporterBackend.SPLUNK, cost_per_million_items=10.0)
        _add_sample(engine, exporter_backend=ExporterBackend.DATADOG, cost_per_million_items=1.0)
        results = engine.rank_backends_by_cost_efficiency()
        assert results[0]["rank"] == 1
        ranks = [r["rank"] for r in results]
        assert ranks == list(range(1, len(ranks) + 1))

    def test_empty_lists(self, engine: ExporterDeliveryTrackerEngine) -> None:
        assert engine.compute_delivery_reliability() == []
        assert engine.detect_export_backpressure() == []
        assert engine.rank_backends_by_cost_efficiency() == []
