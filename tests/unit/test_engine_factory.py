"""Tests for the engine module factory."""

from __future__ import annotations

import pytest

from shieldops.engine import EnumDef, FieldDef, engine

# ---------------------------------------------------------------------------
# Fixture: build a sample engine via the factory
# ---------------------------------------------------------------------------


def _make_risk_engine(**overrides):
    """Build a BehavioralRiskAggregator-like engine for testing."""
    defaults = dict(
        name="TestRiskAggregator",
        module="analytics",
        description="Aggregate risk signals from multiple sources.",
        enums={
            "risk_source": EnumDef(
                name="RiskSource",
                values={"UEBA": "ueba", "DLP": "dlp", "IAM": "iam"},
            ),
            "aggregation_method": EnumDef(
                name="AggregationMethod",
                values={"WEIGHTED_AVERAGE": "weighted_average", "MAXIMUM": "maximum"},
            ),
            "risk_tier": EnumDef(
                name="RiskTier",
                values={"CRITICAL": "critical", "HIGH": "high", "NORMAL": "normal"},
            ),
        },
        record_fields=[
            FieldDef(name="team", type=str, default=""),
        ],
        score_field="aggregated_score",
        key_field="entity_name",
        group_field="service",
        threshold=50.0,
        max_records=200_000,
    )
    defaults.update(overrides)
    return engine(**defaults)


@pytest.fixture
def risk_engine_class():
    return _make_risk_engine()


@pytest.fixture
def risk_engine(risk_engine_class):
    return risk_engine_class()


# ---------------------------------------------------------------------------
# 1. Engine creation with enums + fields
# ---------------------------------------------------------------------------


class TestEngineCreation:
    def test_class_name(self, risk_engine_class):
        assert risk_engine_class.__name__ == "TestRiskAggregator"

    def test_enum_classes_accessible(self, risk_engine_class):
        assert hasattr(risk_engine_class, "RiskSource")
        assert hasattr(risk_engine_class, "AggregationMethod")
        assert hasattr(risk_engine_class, "RiskTier")

    def test_enum_values(self, risk_engine_class):
        assert risk_engine_class.RiskSource.UEBA == "ueba"
        assert risk_engine_class.AggregationMethod.MAXIMUM == "maximum"
        assert risk_engine_class.RiskTier.CRITICAL == "critical"

    def test_model_classes_accessible(self, risk_engine_class):
        assert hasattr(risk_engine_class, "Record")
        assert hasattr(risk_engine_class, "Analysis")
        assert hasattr(risk_engine_class, "Report")

    def test_record_model_fields(self, risk_engine_class):
        rec = risk_engine_class.Record(entity_name="test")
        assert rec.entity_name == "test"
        assert rec.aggregated_score == 0.0
        assert rec.service == ""
        assert rec.id  # uuid generated

    def test_has_add_record_for_analytics(self, risk_engine_class):
        assert hasattr(risk_engine_class, "add_record")
        assert not hasattr(risk_engine_class, "record_item")

    def test_docstring(self, risk_engine_class):
        assert risk_engine_class.__doc__ == "Aggregate risk signals from multiple sources."


# ---------------------------------------------------------------------------
# 2. add_record creates record with correct fields
# ---------------------------------------------------------------------------


class TestAddRecord:
    def test_creates_record(self, risk_engine, risk_engine_class):
        rec = risk_engine.add_record(
            entity_name="user-1",
            risk_source=risk_engine_class.RiskSource.DLP,
            aggregated_score=75.0,
            service="auth-svc",
        )
        assert rec.entity_name == "user-1"
        assert rec.risk_source == risk_engine_class.RiskSource.DLP
        assert rec.aggregated_score == 75.0
        assert rec.service == "auth-svc"
        assert rec.id  # uuid

    def test_record_stored(self, risk_engine):
        risk_engine.add_record(entity_name="a", aggregated_score=10.0)
        assert len(risk_engine._records) == 1


# ---------------------------------------------------------------------------
# 3. get_record finds by ID
# ---------------------------------------------------------------------------


class TestGetRecord:
    def test_found(self, risk_engine):
        rec = risk_engine.add_record(entity_name="x", aggregated_score=42.0)
        found = risk_engine.get_record(rec.id)
        assert found is not None
        assert found.entity_name == "x"

    def test_not_found(self, risk_engine):
        assert risk_engine.get_record("nonexistent") is None


# ---------------------------------------------------------------------------
# 4. list_records with limit and filtering
# ---------------------------------------------------------------------------


class TestListRecords:
    def test_limit(self, risk_engine):
        for i in range(10):
            risk_engine.add_record(entity_name=f"e{i}", aggregated_score=float(i))
        result = risk_engine.list_records(limit=3)
        assert len(result) == 3

    def test_filter_by_service(self, risk_engine):
        risk_engine.add_record(entity_name="a", aggregated_score=1.0, service="svc-a")
        risk_engine.add_record(entity_name="b", aggregated_score=2.0, service="svc-b")
        result = risk_engine.list_records(service="svc-a")
        assert len(result) == 1
        assert result[0].service == "svc-a"


# ---------------------------------------------------------------------------
# 5. Ring buffer eviction (deque maxlen)
# ---------------------------------------------------------------------------


class TestRingBuffer:
    def test_eviction(self):
        eng = _make_risk_engine(max_records=5)
        e = eng(max_records=5)
        for i in range(10):
            e.add_record(entity_name=f"e{i}", aggregated_score=float(i))
        assert len(e._records) == 5
        # oldest should be evicted, newest kept
        names = [r.entity_name for r in e._records]
        assert names == ["e5", "e6", "e7", "e8", "e9"]


# ---------------------------------------------------------------------------
# 6. analyze_distribution groups correctly
# ---------------------------------------------------------------------------


class TestAnalyzeDistribution:
    def test_groups_by_first_enum(self, risk_engine, risk_engine_class):
        risk_engine.add_record(
            entity_name="a",
            risk_source=risk_engine_class.RiskSource.UEBA,
            aggregated_score=60.0,
        )
        risk_engine.add_record(
            entity_name="b",
            risk_source=risk_engine_class.RiskSource.UEBA,
            aggregated_score=80.0,
        )
        risk_engine.add_record(
            entity_name="c",
            risk_source=risk_engine_class.RiskSource.DLP,
            aggregated_score=40.0,
        )
        dist = risk_engine.analyze_distribution()
        assert dist["ueba"]["count"] == 2
        assert dist["ueba"]["avg_aggregated_score"] == 70.0
        assert dist["dlp"]["count"] == 1
        assert dist["dlp"]["avg_aggregated_score"] == 40.0

    def test_empty(self, risk_engine):
        assert risk_engine.analyze_distribution() == {}  # no records


# ---------------------------------------------------------------------------
# 7. identify_gaps filters below threshold
# ---------------------------------------------------------------------------


class TestIdentifyGaps:
    def test_below_threshold(self, risk_engine):
        risk_engine.add_record(entity_name="low", aggregated_score=20.0, service="svc")
        risk_engine.add_record(entity_name="high", aggregated_score=80.0, service="svc")
        gaps = risk_engine.identify_gaps()
        assert len(gaps) == 1
        assert gaps[0]["entity_name"] == "low"
        assert gaps[0]["aggregated_score"] == 20.0

    def test_sorted_ascending(self, risk_engine):
        risk_engine.add_record(entity_name="mid", aggregated_score=30.0)
        risk_engine.add_record(entity_name="lowest", aggregated_score=10.0)
        gaps = risk_engine.identify_gaps()
        assert gaps[0]["aggregated_score"] <= gaps[1]["aggregated_score"]


# ---------------------------------------------------------------------------
# 8. rank_by_score groups by service
# ---------------------------------------------------------------------------


class TestRankByScore:
    def test_groups_by_service(self, risk_engine):
        risk_engine.add_record(entity_name="a", aggregated_score=40.0, service="alpha")
        risk_engine.add_record(entity_name="b", aggregated_score=60.0, service="alpha")
        risk_engine.add_record(entity_name="c", aggregated_score=90.0, service="beta")
        ranked = risk_engine.rank_by_score()
        assert len(ranked) == 2
        # alpha avg=50, beta avg=90 => alpha first (ascending)
        assert ranked[0]["service"] == "alpha"
        assert ranked[0]["avg_aggregated_score"] == 50.0
        assert ranked[1]["service"] == "beta"


# ---------------------------------------------------------------------------
# 9. detect_trends
# ---------------------------------------------------------------------------


class TestDetectTrends:
    def test_insufficient_data(self, risk_engine):
        result = risk_engine.detect_trends()
        assert result["trend"] == "insufficient_data"

    def test_improving(self, risk_engine):
        # first half low, second half high
        risk_engine.add_analysis(entity_name="a", analysis_score=10.0)
        risk_engine.add_analysis(entity_name="b", analysis_score=12.0)
        risk_engine.add_analysis(entity_name="c", analysis_score=30.0)
        risk_engine.add_analysis(entity_name="d", analysis_score=32.0)
        result = risk_engine.detect_trends()
        assert result["trend"] == "improving"
        assert result["delta"] > 5.0

    def test_degrading(self, risk_engine):
        risk_engine.add_analysis(entity_name="a", analysis_score=80.0)
        risk_engine.add_analysis(entity_name="b", analysis_score=82.0)
        risk_engine.add_analysis(entity_name="c", analysis_score=20.0)
        risk_engine.add_analysis(entity_name="d", analysis_score=22.0)
        result = risk_engine.detect_trends()
        assert result["trend"] == "degrading"

    def test_stable(self, risk_engine):
        risk_engine.add_analysis(entity_name="a", analysis_score=50.0)
        risk_engine.add_analysis(entity_name="b", analysis_score=51.0)
        risk_engine.add_analysis(entity_name="c", analysis_score=52.0)
        risk_engine.add_analysis(entity_name="d", analysis_score=53.0)
        result = risk_engine.detect_trends()
        assert result["trend"] == "stable"


# ---------------------------------------------------------------------------
# 10. generate_report has all expected fields
# ---------------------------------------------------------------------------


class TestGenerateReport:
    def test_report_fields(self, risk_engine, risk_engine_class):
        risk_engine.add_record(
            entity_name="x",
            risk_source=risk_engine_class.RiskSource.UEBA,
            aggregated_score=30.0,
        )
        risk_engine.add_record(
            entity_name="y",
            risk_source=risk_engine_class.RiskSource.DLP,
            aggregated_score=70.0,
        )
        risk_engine.add_analysis(entity_name="x", analysis_score=30.0)
        report = risk_engine.generate_report()
        assert report.total_records == 2
        assert report.total_analyses == 1
        assert report.gap_count == 1  # only "x" is below 50
        assert report.avg_aggregated_score == 50.0
        assert "ueba" in report.by_risk_source
        assert "dlp" in report.by_risk_source
        assert len(report.recommendations) >= 1
        assert report.top_gaps == ["x"]

    def test_healthy_report(self, risk_engine):
        risk_engine.add_record(entity_name="ok", aggregated_score=90.0)
        report = risk_engine.generate_report()
        assert report.gap_count == 0
        assert any("healthy" in r.lower() for r in report.recommendations)


# ---------------------------------------------------------------------------
# 11. get_stats returns correct counts
# ---------------------------------------------------------------------------


class TestGetStats:
    def test_stats_structure(self, risk_engine, risk_engine_class):
        risk_engine.add_record(
            entity_name="a",
            risk_source=risk_engine_class.RiskSource.IAM,
            aggregated_score=10.0,
            service="svc1",
            team="team1",
        )
        stats = risk_engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["total_analyses"] == 0
        assert stats["threshold"] == 50.0
        assert "risk_source_distribution" in stats
        assert stats["risk_source_distribution"]["iam"] == 1
        assert stats["unique_teams"] == 1
        assert stats["unique_services"] == 1


# ---------------------------------------------------------------------------
# 12. clear_data resets everything
# ---------------------------------------------------------------------------


class TestClearData:
    def test_clears(self, risk_engine):
        risk_engine.add_record(entity_name="a", aggregated_score=10.0)
        risk_engine.add_analysis(entity_name="a", analysis_score=10.0)
        result = risk_engine.clear_data()
        assert result == {"status": "cleared"}
        assert len(risk_engine._records) == 0
        assert len(risk_engine._analyses) == 0


# ---------------------------------------------------------------------------
# 13. record_item works for operations module
# ---------------------------------------------------------------------------


class TestRecordItem:
    def test_operations_module(self):
        ops_engine = engine(
            "Testops_engine",
            module="operations",
            enums={
                "resource_type": EnumDef(
                    name="ResourceType",
                    values={"CPU": "cpu", "MEMORY": "memory"},
                ),
            },
            score_field="score",
            key_field="name",
        )
        assert hasattr(ops_engine, "record_item")
        assert not hasattr(ops_engine, "add_record")

        e = ops_engine()
        rec = e.record_item(name="server-1", score=75.0)
        assert rec.name == "server-1"
        assert rec.score == 75.0
        assert len(e._records) == 1

    def test_changes_module(self):
        eng = engine("TestChanges", module="changes")
        assert hasattr(eng, "record_item")

    def test_topology_module(self):
        eng = engine("TestTopology", module="topology")
        assert hasattr(eng, "record_item")


# ---------------------------------------------------------------------------
# 14. Subclassing adds custom methods
# ---------------------------------------------------------------------------


class TestSubclassing:
    def test_custom_method(self, risk_engine_class):
        class ExtendedEngine(risk_engine_class):
            def custom_analysis(self) -> str:
                return f"Records: {len(self._records)}"

        e = ExtendedEngine()
        e.add_record(entity_name="a", aggregated_score=10.0)
        assert e.custom_analysis() == "Records: 1"
        # original methods still work
        assert e.get_stats()["total_records"] == 1


# ---------------------------------------------------------------------------
# 15. Enum classes accessible as attributes
# ---------------------------------------------------------------------------


class TestEnumAttributes:
    def test_enum_on_class(self, risk_engine_class):
        assert risk_engine_class.RiskSource.UEBA == "ueba"
        assert risk_engine_class.AggregationMethod.WEIGHTED_AVERAGE == "weighted_average"
        assert risk_engine_class.RiskTier.NORMAL == "normal"

    def test_enum_on_instance(self, risk_engine, risk_engine_class):
        # enums should be accessible via the class, usable with instances
        rec = risk_engine.add_record(
            entity_name="t",
            risk_source=risk_engine_class.RiskSource.IAM,
            aggregated_score=5.0,
        )
        assert rec.risk_source == "iam"


# ---------------------------------------------------------------------------
# 16. process() method
# ---------------------------------------------------------------------------


class TestProcess:
    def test_process_existing_record(self, risk_engine):
        risk_engine.add_record(entity_name="target", aggregated_score=30.0)
        analysis = risk_engine.process("target")
        assert analysis.entity_name == "target"
        assert analysis.analysis_score == 30.0
        assert analysis.breached is True  # 30 < 50

    def test_process_missing_record(self, risk_engine):
        analysis = risk_engine.process("missing")
        assert analysis.entity_name == "missing"
        assert analysis.breached is True
        assert "No records found" in analysis.description


# ---------------------------------------------------------------------------
# 17. No enums edge case
# ---------------------------------------------------------------------------


class TestNoEnums:
    def test_engine_without_enums(self):
        eng = engine("SimpleEngine", module="analytics")
        e = eng()
        rec = e.add_record(name="item1", score=42.0)
        assert rec.name == "item1"
        assert rec.score == 42.0
        # analyze_distribution returns empty with no enums
        assert e.analyze_distribution() == {}
        # report still works
        report = e.generate_report()
        assert report.total_records == 1
