"""Unit tests for AutoInstrumentationCoverageEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.auto_instrumentation_coverage_engine import (
    AutoInstrumentationCoverageEngine,
    AutoInstrumentationRecord,
    AutoInstrumentationReport,
    CoverageStatus,
    InstrumentationLanguage,
    InstrumentationQuality,
)


@pytest.fixture()
def engine() -> AutoInstrumentationCoverageEngine:
    return AutoInstrumentationCoverageEngine(max_records=100)


def _add_sample(
    engine: AutoInstrumentationCoverageEngine, **kwargs: object
) -> AutoInstrumentationRecord:
    defaults: dict[str, object] = {
        "service_name": "payment-svc",
        "language": InstrumentationLanguage.PYTHON,
        "coverage_status": CoverageStatus.FULLY_INSTRUMENTED,
        "instrumentation_quality": InstrumentationQuality.RICH_CONTEXT,
        "endpoint_count": 20,
        "instrumented_endpoints": 20,
        "propagation_breaks": 0,
        "missing_attribute_count": 0,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: AutoInstrumentationCoverageEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, AutoInstrumentationRecord)

    def test_ring_buffer(self, engine: AutoInstrumentationCoverageEngine) -> None:
        for i in range(110):
            _add_sample(engine, service_name=f"svc{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_full_coverage(self, engine: AutoInstrumentationCoverageEngine) -> None:
        rec = _add_sample(engine, endpoint_count=10, instrumented_endpoints=10)
        analysis = engine.process(rec.id)
        assert analysis.coverage_pct == 100.0  # type: ignore[union-attr]

    def test_partial_coverage(self, engine: AutoInstrumentationCoverageEngine) -> None:
        rec = _add_sample(engine, endpoint_count=10, instrumented_endpoints=5)
        analysis = engine.process(rec.id)
        assert analysis.coverage_pct == 50.0  # type: ignore[union-attr]

    def test_propagation_broken_flag(self, engine: AutoInstrumentationCoverageEngine) -> None:
        rec = _add_sample(engine, propagation_breaks=3)
        analysis = engine.process(rec.id)
        assert analysis.propagation_broken is True  # type: ignore[union-attr]

    def test_no_propagation_break(self, engine: AutoInstrumentationCoverageEngine) -> None:
        rec = _add_sample(engine, propagation_breaks=0)
        analysis = engine.process(rec.id)
        assert analysis.propagation_broken is False  # type: ignore[union-attr]

    def test_not_found(self, engine: AutoInstrumentationCoverageEngine) -> None:
        assert engine.process("bad")["status"] == "not_found"  # type: ignore[index]


class TestGenerateReport:
    def test_report_type(self, engine: AutoInstrumentationCoverageEngine) -> None:
        _add_sample(engine)
        assert isinstance(engine.generate_report(), AutoInstrumentationReport)

    def test_uninstrumented_services_populated(
        self, engine: AutoInstrumentationCoverageEngine
    ) -> None:
        _add_sample(engine, service_name="dark", coverage_status=CoverageStatus.UNINSTRUMENTED)
        report = engine.generate_report()
        assert "dark" in report.uninstrumented_services

    def test_avg_coverage_perfect(self, engine: AutoInstrumentationCoverageEngine) -> None:
        _add_sample(engine, endpoint_count=10, instrumented_endpoints=10)
        report = engine.generate_report()
        assert report.avg_coverage_pct == 100.0

    def test_recommendations_present(self, engine: AutoInstrumentationCoverageEngine) -> None:
        _add_sample(engine)
        assert len(engine.generate_report().recommendations) > 0


class TestGetStats:
    def test_coverage_status_distribution_key(self, engine: AutoInstrumentationCoverageEngine) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "coverage_status_distribution" in stats


class TestClearData:
    def test_clears(self, engine: AutoInstrumentationCoverageEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert engine._records == []


class TestDomainMethods:
    def test_compute_instrumentation_coverage_sorted_asc(
        self, engine: AutoInstrumentationCoverageEngine
    ) -> None:
        _add_sample(engine, service_name="low", endpoint_count=10, instrumented_endpoints=2)
        _add_sample(engine, service_name="high", endpoint_count=10, instrumented_endpoints=9)
        results = engine.compute_instrumentation_coverage()
        assert results[0]["coverage_pct"] <= results[-1]["coverage_pct"]

    def test_detect_propagation_breaks_includes_broken(
        self, engine: AutoInstrumentationCoverageEngine
    ) -> None:
        _add_sample(engine, service_name="broken", propagation_breaks=5)
        _add_sample(engine, service_name="clean", propagation_breaks=0)
        results = engine.detect_propagation_breaks()
        names = [r["service_name"] for r in results]
        assert "broken" in names
        assert "clean" not in names

    def test_prioritize_instrumentation_gaps_rank_assigned(
        self, engine: AutoInstrumentationCoverageEngine
    ) -> None:
        _add_sample(engine, service_name="gap", endpoint_count=10, instrumented_endpoints=3)
        results = engine.prioritize_instrumentation_gaps()
        assert results[0]["rank"] == 1

    def test_empty_returns_empty(self, engine: AutoInstrumentationCoverageEngine) -> None:
        assert engine.compute_instrumentation_coverage() == []
        assert engine.detect_propagation_breaks() == []
        assert engine.prioritize_instrumentation_gaps() == []
