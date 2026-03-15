"""Unit tests for HelmDeploymentIntelligenceEngine."""

from __future__ import annotations

import pytest

from shieldops.observability.helm_deployment_intelligence_engine import (
    ChartHealth,
    DeploymentMode,
    HelmDeploymentIntelligenceEngine,
    HelmDeploymentRecord,
    HelmDeploymentReport,
    MisconfigRisk,
)


@pytest.fixture()
def engine() -> HelmDeploymentIntelligenceEngine:
    return HelmDeploymentIntelligenceEngine(max_records=100)


def _add_sample(
    engine: HelmDeploymentIntelligenceEngine, **kwargs: object
) -> HelmDeploymentRecord:
    defaults: dict[str, object] = {
        "release_name": "otelcol",
        "deployment_mode": DeploymentMode.DEPLOYMENT,
        "chart_health": ChartHealth.UP_TO_DATE,
        "misconfig_risk": MisconfigRisk.NONE,
        "chart_version": "0.93.0",
        "deployed_version": "0.93.0",
        "replica_count": 3,
        "misconfig_count": 0,
        "upgrade_blocking_issues": 0,
    }
    defaults.update(kwargs)
    return engine.add_record(**defaults)  # type: ignore[arg-type]


class TestAddRecord:
    def test_returns_record(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        rec = _add_sample(engine)
        assert isinstance(rec, HelmDeploymentRecord)

    def test_ring_buffer(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        for i in range(110):
            _add_sample(engine, release_name=f"rel{i}")
        assert len(engine._records) == 100


class TestProcess:
    def test_upgrade_ready_no_issues(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        rec = _add_sample(engine, upgrade_blocking_issues=0, chart_health=ChartHealth.UP_TO_DATE)
        analysis = engine.process(rec.id)
        assert analysis.upgrade_ready is True  # type: ignore[union-attr]

    def test_upgrade_blocked(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        rec = _add_sample(engine, upgrade_blocking_issues=3)
        analysis = engine.process(rec.id)
        assert analysis.upgrade_ready is False  # type: ignore[union-attr]

    def test_misconfig_detected(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        rec = _add_sample(engine, misconfig_count=2)
        analysis = engine.process(rec.id)
        assert analysis.misconfig_detected is True  # type: ignore[union-attr]

    def test_risk_score_higher_for_unsupported(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        rec_good = _add_sample(engine, chart_health=ChartHealth.UP_TO_DATE)
        rec_bad = _add_sample(engine, chart_health=ChartHealth.UNSUPPORTED)
        a_good = engine.process(rec_good.id)
        a_bad = engine.process(rec_bad.id)
        assert a_bad.risk_score > a_good.risk_score  # type: ignore[union-attr]

    def test_not_found(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        assert engine.process("bad")["status"] == "not_found"  # type: ignore[index]


class TestGenerateReport:
    def test_report_type(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        _add_sample(engine)
        assert isinstance(engine.generate_report(), HelmDeploymentReport)

    def test_blocking_releases_populated(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        _add_sample(engine, release_name="stuck", upgrade_blocking_issues=1)
        report = engine.generate_report()
        assert "stuck" in report.blocking_releases

    def test_recommendations_present(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        _add_sample(engine)
        assert len(engine.generate_report().recommendations) > 0

    def test_by_chart_health_counted(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        _add_sample(engine, chart_health=ChartHealth.MAJOR_BEHIND)
        report = engine.generate_report()
        assert report.by_chart_health.get("major_behind", 0) == 1


class TestGetStats:
    def test_chart_health_distribution_key(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        _add_sample(engine)
        stats = engine.get_stats()
        assert "chart_health_distribution" in stats


class TestClearData:
    def test_clears(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        _add_sample(engine)
        engine.clear_data()
        assert engine._records == []


class TestDomainMethods:
    def test_assess_upgrade_readiness_sorted_by_blocking(
        self, engine: HelmDeploymentIntelligenceEngine
    ) -> None:
        _add_sample(engine, release_name="blocked", upgrade_blocking_issues=5)
        _add_sample(engine, release_name="ready", upgrade_blocking_issues=0)
        results = engine.assess_upgrade_readiness()
        assert results[0]["total_blocking_issues"] >= results[-1]["total_blocking_issues"]

    def test_detect_helm_misconfigurations_finds_security(
        self, engine: HelmDeploymentIntelligenceEngine
    ) -> None:
        _add_sample(
            engine, release_name="vuln", misconfig_count=1, misconfig_risk=MisconfigRisk.SECURITY
        )
        results = engine.detect_helm_misconfigurations()
        assert any(r["release_name"] == "vuln" for r in results)

    def test_compare_deployment_strategies_returns_all_modes(
        self, engine: HelmDeploymentIntelligenceEngine
    ) -> None:
        _add_sample(engine, deployment_mode=DeploymentMode.DAEMONSET)
        _add_sample(engine, deployment_mode=DeploymentMode.SIDECAR)
        results = engine.compare_deployment_strategies()
        modes = {r["deployment_mode"] for r in results}
        assert "daemonset" in modes
        assert "sidecar" in modes

    def test_empty_assess_returns_empty(self, engine: HelmDeploymentIntelligenceEngine) -> None:
        assert engine.assess_upgrade_readiness() == []
