"""Unit tests for CollectorConfigDriftEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.collector_config_drift_engine import (
    CollectorConfigDriftEngine,
    CollectorConfigDriftRecord,
    CollectorConfigDriftReport,
    ConfigSource,
    DriftSeverity,
    DriftType,
)


@pytest.fixture()
def engine() -> CollectorConfigDriftEngine:
    return CollectorConfigDriftEngine(max_records=100)


def _add_sample(engine: CollectorConfigDriftEngine, **kwargs: object) -> CollectorConfigDriftRecord:
    defaults: dict[str, object] = {
        "collector_id": "col-1",
        "drift_type": DriftType.RECEIVER_MISMATCH,
        "drift_severity": DriftSeverity.LOW,
        "config_source": ConfigSource.CONFIGMAP,
        "drift_field": "receivers.otlp.endpoint",
        "expected_value": "0.0.0.0:4317",
        "actual_value": "127.0.0.1:4317",
        "drift_age_hours": 1.0,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: CollectorConfigDriftEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, CollectorConfigDriftRecord)

    def test_ring_buffer(self, engine: CollectorConfigDriftEngine) -> None:
        for i in range(110):
            _add_sample(engine, collector_id=f"c{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_critical_severity_patch_required(self, engine: CollectorConfigDriftEngine) -> None:
        rec = _add_sample(engine, drift_severity=DriftSeverity.CRITICAL)
        analysis = engine.process(rec.id)
        assert analysis.patch_required is True  # type: ignore[union-attr]

    def test_low_severity_no_patch(self, engine: CollectorConfigDriftEngine) -> None:
        rec = _add_sample(engine, drift_severity=DriftSeverity.LOW)
        analysis = engine.process(rec.id)
        assert analysis.patch_required is False  # type: ignore[union-attr]

    def test_high_severity_patch_required(self, engine: CollectorConfigDriftEngine) -> None:
        rec = _add_sample(engine, drift_severity=DriftSeverity.HIGH)
        analysis = engine.process(rec.id)
        assert analysis.patch_required is True  # type: ignore[union-attr]

    def test_impact_score_increases_with_age(self, engine: CollectorConfigDriftEngine) -> None:
        rec_new = _add_sample(engine, drift_severity=DriftSeverity.MEDIUM, drift_age_hours=1.0)
        rec_old = _add_sample(engine, drift_severity=DriftSeverity.MEDIUM, drift_age_hours=48.0)
        a_new = engine.process(rec_new.id)
        a_old = engine.process(rec_old.id)
        assert a_old.impact_score > a_new.impact_score  # type: ignore[union-attr]

    def test_not_found(self, engine: CollectorConfigDriftEngine) -> None:
        assert engine.process("bad")["status"] == "not_found"  # type: ignore[index]


class TestGenerateReport:
    def test_report_type(self, engine: CollectorConfigDriftEngine) -> None:
        _add_sample(engine)
        assert isinstance(engine.generate_report(), CollectorConfigDriftReport)

    def test_drifted_collectors_critical(self, engine: CollectorConfigDriftEngine) -> None:
        _add_sample(engine, collector_id="crit", drift_severity=DriftSeverity.CRITICAL)
        report = engine.generate_report()
        assert "crit" in report.drifted_collectors

    def test_recommendations_not_empty(self, engine: CollectorConfigDriftEngine) -> None:
        _add_sample(engine)
        assert len(engine.generate_report().recommendations) > 0

    def test_by_drift_type_counted(self, engine: CollectorConfigDriftEngine) -> None:
        _add_sample(engine, drift_type=DriftType.EXPORTER_MISMATCH)
        report = engine.generate_report()
        assert report.by_drift_type.get("exporter_mismatch", 0) == 1


class TestGetStats:
    def test_severity_distribution_key(self, engine: CollectorConfigDriftEngine) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "severity_distribution" in stats


class TestClearData:
    def test_clears(self, engine: CollectorConfigDriftEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert engine._records == []


class TestDomainMethods:
    def test_detect_fleet_config_drift_sorted_by_critical(
        self, engine: CollectorConfigDriftEngine
    ) -> None:
        _add_sample(engine, collector_id="bad", drift_severity=DriftSeverity.CRITICAL)
        _add_sample(engine, collector_id="ok", drift_severity=DriftSeverity.LOW)
        results = engine.detect_fleet_config_drift()
        assert results[0]["collector_id"] == "bad"

    def test_classify_drift_impact_returns_all_records(
        self, engine: CollectorConfigDriftEngine
    ) -> None:
        _add_sample(engine)
        _add_sample(engine)
        results = engine.classify_drift_impact()
        assert len(results) == 2

    def test_generate_remediation_patches_only_high_critical(
        self, engine: CollectorConfigDriftEngine
    ) -> None:
        _add_sample(engine, collector_id="patch", drift_severity=DriftSeverity.HIGH)
        _add_sample(engine, collector_id="ignore", drift_severity=DriftSeverity.LOW)
        results = engine.generate_remediation_patches()
        collector_ids = [r["collector_id"] for r in results]
        assert "patch" in collector_ids
        assert "ignore" not in collector_ids

    def test_patches_include_field_info(self, engine: CollectorConfigDriftEngine) -> None:
        _add_sample(
            engine,
            collector_id="p1",
            drift_severity=DriftSeverity.CRITICAL,
            drift_field="memory_limit",
        )
        results = engine.generate_remediation_patches()
        patches = results[0]["patches"]
        assert patches[0]["field"] == "memory_limit"
