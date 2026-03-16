"""Tests for Phase 139 engines 4-8 (security + analytics)."""

from __future__ import annotations

import pytest

from shieldops.analytics.agent_decision_quality_engine import (
    AgentDecisionQualityAnalysis,
    AgentDecisionQualityEngine,
    AgentDecisionQualityRecord,
    AgentDecisionQualityReport,
    DecisionOutcome,
    DecisionType,
    QualityTrend,
)
from shieldops.analytics.cost_effectiveness_engine import (
    CostCategory,
    CostEffectivenessAnalysis,
    CostEffectivenessEngine,
    CostEffectivenessRecord,
    CostEffectivenessReport,
    EfficiencyQuartile,
    ROIIndicator,
)
from shieldops.analytics.operational_maturity_engine import (
    AssessmentConfidence,
    MaturityDomain,
    MaturityLevel,
    OperationalMaturityAnalysis,
    OperationalMaturityEngine,
    OperationalMaturityRecord,
    OperationalMaturityReport,
)
from shieldops.security.credential_hygiene_engine import (
    CredentialHygieneAnalysis,
    CredentialHygieneEngine,
    CredentialHygieneRecord,
    CredentialHygieneReport,
    CredentialType,
    HygieneStatus,
    RotationCompliance,
)
from shieldops.security.vulnerability_prioritization_engine import (
    AssetCriticality,
    ExploitabilityLevel,
    RemediationUrgency,
    VulnerabilityPrioritizationAnalysis,
    VulnerabilityPrioritizationEngine,
    VulnerabilityPrioritizationRecord,
    VulnerabilityPrioritizationReport,
)

# ============================================================================
# VulnerabilityPrioritizationEngine
# ============================================================================


class TestVulnPrioritizationEnums:
    def test_exploitability_values(self):
        assert ExploitabilityLevel.ACTIVE_EXPLOIT == "active_exploit"
        assert ExploitabilityLevel.POC_AVAILABLE == "poc_available"
        assert ExploitabilityLevel.NONE == "none"

    def test_asset_criticality_values(self):
        assert AssetCriticality.CROWN_JEWEL == "crown_jewel"
        assert AssetCriticality.DEVELOPMENT == "development"

    def test_remediation_urgency_values(self):
        assert RemediationUrgency.IMMEDIATE == "immediate"
        assert RemediationUrgency.BACKLOG == "backlog"


class TestVulnPrioritizationModels:
    def test_record_defaults(self):
        r = VulnerabilityPrioritizationRecord()
        assert r.exploitability_level == ExploitabilityLevel.NONE
        assert r.asset_criticality == AssetCriticality.STANDARD

    def test_analysis_defaults(self):
        a = VulnerabilityPrioritizationAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = VulnerabilityPrioritizationReport()
        assert r.total_records == 0


class TestVulnPrioritizationEngine:
    @pytest.fixture()
    def engine(self):
        return VulnerabilityPrioritizationEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._threshold == 50.0

    def test_add_record(self, engine):
        r = engine.add_record(
            name="CVE-2024-001",
            exploitability_level=ExploitabilityLevel.ACTIVE_EXPLOIT,
            cvss_score=9.8,
            service="api",
        )
        assert r.cvss_score == 9.8

    def test_get_record(self, engine):
        r = engine.add_record(name="v1", service="s")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("x") is None

    def test_list_records_filter_exploitability(self, engine):
        engine.add_record(name="a", exploitability_level=ExploitabilityLevel.NONE)
        engine.add_record(name="b", exploitability_level=ExploitabilityLevel.ACTIVE_EXPLOIT)
        res = engine.list_records(exploitability_level=ExploitabilityLevel.ACTIVE_EXPLOIT)
        assert len(res) == 1

    def test_list_records_filter_criticality(self, engine):
        engine.add_record(name="a", asset_criticality=AssetCriticality.STANDARD)
        engine.add_record(name="b", asset_criticality=AssetCriticality.CROWN_JEWEL)
        res = engine.list_records(asset_criticality=AssetCriticality.CROWN_JEWEL)
        assert len(res) == 1

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1", analysis_score=80.0)
        assert a.name == "a1"

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r{i}", service="s")
        assert len(engine._records) == 100

    def test_compute_risk_priority_score(self, engine):
        engine.add_record(
            name="cve1",
            exploitability_level=ExploitabilityLevel.ACTIVE_EXPLOIT,
            asset_criticality=AssetCriticality.CROWN_JEWEL,
            cvss_score=9.8,
            service="api",
        )
        engine.add_record(
            name="cve2",
            exploitability_level=ExploitabilityLevel.NONE,
            asset_criticality=AssetCriticality.DEVELOPMENT,
            cvss_score=2.0,
            service="dev",
        )
        result = engine.compute_risk_priority_score()
        assert len(result) == 2
        assert result[0]["priority_score"] > result[1]["priority_score"]

    def test_identify_crown_jewel_vulns(self, engine):
        engine.add_record(
            name="cve1",
            asset_criticality=AssetCriticality.CROWN_JEWEL,
            cvss_score=9.0,
            service="db",
        )
        engine.add_record(
            name="cve2", asset_criticality=AssetCriticality.STANDARD, cvss_score=5.0, service="api"
        )
        result = engine.identify_crown_jewel_vulns()
        assert len(result) == 1
        assert result[0]["name"] == "cve1"

    def test_identify_crown_jewel_vulns_empty(self, engine):
        engine.add_record(name="cve1", asset_criticality=AssetCriticality.STANDARD)
        assert engine.identify_crown_jewel_vulns() == []

    def test_recommend_remediation_order_active_exploit(self, engine):
        engine.add_record(
            name="cve1", exploitability_level=ExploitabilityLevel.ACTIVE_EXPLOIT, service="api"
        )
        recs = engine.recommend_remediation_order()
        assert len(recs) == 1
        assert recs[0]["priority"] == "critical"

    def test_recommend_remediation_order_high_cvss(self, engine):
        engine.add_record(
            name="cve1",
            exploitability_level=ExploitabilityLevel.POC_AVAILABLE,
            cvss_score=9.5,
            service="api",
        )
        recs = engine.recommend_remediation_order()
        assert len(recs) == 1
        assert recs[0]["priority"] == "high"

    def test_recommend_remediation_order_empty(self, engine):
        engine.add_record(
            name="cve1", exploitability_level=ExploitabilityLevel.NONE, cvss_score=3.0
        )
        assert engine.recommend_remediation_order() == []

    def test_process(self, engine):
        engine.add_record(name="cve1", service="api", score=60.0)
        result = engine.process("api")
        assert result["count"] == 1

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=30.0, service="s")
        report = engine.generate_report()
        assert report.total_records == 1

    def test_clear_data(self, engine):
        engine.add_record(name="a", service="s")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1


# ============================================================================
# CredentialHygieneEngine
# ============================================================================


class TestCredentialHygieneEnums:
    def test_credential_type_values(self):
        assert CredentialType.PASSWORD == "password"
        assert CredentialType.API_KEY == "api_key"
        assert CredentialType.SSH_KEY == "ssh_key"
        assert CredentialType.CERTIFICATE == "certificate"
        assert CredentialType.TOKEN == "token"

    def test_hygiene_status_values(self):
        assert HygieneStatus.HEALTHY == "healthy"
        assert HygieneStatus.EXPIRED == "expired"

    def test_rotation_compliance_values(self):
        assert RotationCompliance.ON_SCHEDULE == "on_schedule"
        assert RotationCompliance.NEVER_ROTATED == "never_rotated"


class TestCredentialHygieneModels:
    def test_record_defaults(self):
        r = CredentialHygieneRecord()
        assert r.credential_type == CredentialType.PASSWORD

    def test_analysis_defaults(self):
        a = CredentialHygieneAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = CredentialHygieneReport()
        assert r.total_records == 0


class TestCredentialHygieneEngine:
    @pytest.fixture()
    def engine(self):
        return CredentialHygieneEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._threshold == 50.0

    def test_add_record(self, engine):
        r = engine.add_record(
            name="admin-pw",
            credential_type=CredentialType.PASSWORD,
            hygiene_status=HygieneStatus.HEALTHY,
            service="auth",
        )
        assert r.credential_type == CredentialType.PASSWORD

    def test_get_record(self, engine):
        r = engine.add_record(name="k1", service="s")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("x") is None

    def test_list_records_filter_type(self, engine):
        engine.add_record(name="a", credential_type=CredentialType.PASSWORD)
        engine.add_record(name="b", credential_type=CredentialType.API_KEY)
        res = engine.list_records(credential_type=CredentialType.API_KEY)
        assert len(res) == 1

    def test_list_records_filter_status(self, engine):
        engine.add_record(name="a", hygiene_status=HygieneStatus.HEALTHY)
        engine.add_record(name="b", hygiene_status=HygieneStatus.EXPIRED)
        res = engine.list_records(hygiene_status=HygieneStatus.EXPIRED)
        assert len(res) == 1

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r{i}", service="s")
        assert len(engine._records) == 100

    def test_compute_credential_health(self, engine):
        engine.add_record(
            name="pw1",
            score=80.0,
            hygiene_status=HygieneStatus.HEALTHY,
            rotation_compliance=RotationCompliance.ON_SCHEDULE,
            mfa_enabled=True,
            service="auth",
        )
        result = engine.compute_credential_health()
        assert len(result) == 1
        assert result[0]["health_score"] == 80.0

    def test_compute_credential_health_expired(self, engine):
        engine.add_record(
            name="pw1",
            score=80.0,
            hygiene_status=HygieneStatus.EXPIRED,
            rotation_compliance=RotationCompliance.NEVER_ROTATED,
            mfa_enabled=False,
            service="auth",
        )
        result = engine.compute_credential_health()
        assert result[0]["health_score"] == 0.0
        assert "expired" in result[0]["risk_factors"]
        assert "never_rotated" in result[0]["risk_factors"]
        assert "no_mfa" in result[0]["risk_factors"]

    def test_compute_credential_health_critical(self, engine):
        engine.add_record(
            name="pw1", score=80.0, hygiene_status=HygieneStatus.CRITICAL, service="auth"
        )
        result = engine.compute_credential_health()
        assert "critical_status" in result[0]["risk_factors"]

    def test_compute_credential_health_overdue(self, engine):
        engine.add_record(
            name="pw1", score=80.0, rotation_compliance=RotationCompliance.OVERDUE, service="auth"
        )
        result = engine.compute_credential_health()
        assert "overdue_rotation" in result[0]["risk_factors"]

    def test_identify_expired_credentials(self, engine):
        engine.add_record(
            name="pw1",
            hygiene_status=HygieneStatus.EXPIRED,
            days_since_rotation=500,
            service="auth",
        )
        engine.add_record(name="pw2", hygiene_status=HygieneStatus.HEALTHY, service="api")
        result = engine.identify_expired_credentials()
        assert len(result) == 1
        assert result[0]["name"] == "pw1"

    def test_identify_expired_credentials_critical(self, engine):
        engine.add_record(
            name="pw1",
            hygiene_status=HygieneStatus.CRITICAL,
            days_since_rotation=200,
            service="auth",
        )
        result = engine.identify_expired_credentials()
        assert len(result) == 1

    def test_identify_expired_credentials_empty(self, engine):
        engine.add_record(name="ok", hygiene_status=HygieneStatus.HEALTHY)
        assert engine.identify_expired_credentials() == []

    def test_recommend_rotation_schedule(self, engine):
        engine.add_record(
            name="key1",
            credential_type=CredentialType.API_KEY,
            rotation_compliance=RotationCompliance.OVERDUE,
            days_since_rotation=400,
            service="api",
        )
        recs = engine.recommend_rotation_schedule()
        assert len(recs) == 1
        assert recs[0]["recommended_interval_days"] == 180

    def test_recommend_rotation_schedule_never_rotated(self, engine):
        engine.add_record(
            name="token1",
            credential_type=CredentialType.TOKEN,
            rotation_compliance=RotationCompliance.NEVER_ROTATED,
            days_since_rotation=100,
            service="api",
        )
        recs = engine.recommend_rotation_schedule()
        assert len(recs) == 1
        assert recs[0]["priority"] == "high"

    def test_recommend_rotation_schedule_empty(self, engine):
        engine.add_record(name="ok", rotation_compliance=RotationCompliance.ON_SCHEDULE)
        assert engine.recommend_rotation_schedule() == []

    def test_process(self, engine):
        engine.add_record(name="k1", service="auth", score=70.0)
        result = engine.process("auth")
        assert result["count"] == 1

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=30.0, service="s")
        report = engine.generate_report()
        assert report.total_records == 1

    def test_clear_data(self, engine):
        engine.add_record(name="a", service="s")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1


# ============================================================================
# AgentDecisionQualityEngine
# ============================================================================


class TestDecisionQualityEnums:
    def test_decision_type_values(self):
        assert DecisionType.INVESTIGATE == "investigate"
        assert DecisionType.REMEDIATE == "remediate"
        assert DecisionType.ESCALATE == "escalate"
        assert DecisionType.IGNORE == "ignore"

    def test_decision_outcome_values(self):
        assert DecisionOutcome.CORRECT == "correct"
        assert DecisionOutcome.OVERRIDDEN == "overridden"

    def test_quality_trend_values(self):
        assert QualityTrend.IMPROVING == "improving"
        assert QualityTrend.DECLINING == "declining"


class TestDecisionQualityModels:
    def test_record_defaults(self):
        r = AgentDecisionQualityRecord()
        assert r.decision_type == DecisionType.INVESTIGATE

    def test_analysis_defaults(self):
        a = AgentDecisionQualityAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = AgentDecisionQualityReport()
        assert r.total_records == 0


class TestDecisionQualityEngine:
    @pytest.fixture()
    def engine(self):
        return AgentDecisionQualityEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._threshold == 50.0

    def test_add_record(self, engine):
        r = engine.add_record(
            name="d1",
            decision_type=DecisionType.REMEDIATE,
            decision_outcome=DecisionOutcome.CORRECT,
            score=90.0,
            service="api",
        )
        assert r.decision_type == DecisionType.REMEDIATE

    def test_get_record(self, engine):
        r = engine.add_record(name="d1", service="s")
        assert engine.get_record(r.id) is not None

    def test_list_records_filter_type(self, engine):
        engine.add_record(name="a", decision_type=DecisionType.INVESTIGATE)
        engine.add_record(name="b", decision_type=DecisionType.ESCALATE)
        res = engine.list_records(decision_type=DecisionType.ESCALATE)
        assert len(res) == 1

    def test_list_records_filter_outcome(self, engine):
        engine.add_record(name="a", decision_outcome=DecisionOutcome.CORRECT)
        engine.add_record(name="b", decision_outcome=DecisionOutcome.INCORRECT)
        res = engine.list_records(decision_outcome=DecisionOutcome.INCORRECT)
        assert len(res) == 1

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r{i}", service="s")
        assert len(engine._records) == 100

    def test_compute_decision_accuracy(self, engine):
        engine.add_record(
            name="d1",
            decision_type=DecisionType.INVESTIGATE,
            decision_outcome=DecisionOutcome.CORRECT,
            service="api",
        )
        engine.add_record(
            name="d2",
            decision_type=DecisionType.INVESTIGATE,
            decision_outcome=DecisionOutcome.INCORRECT,
            service="api",
        )
        engine.add_record(
            name="d3",
            decision_type=DecisionType.INVESTIGATE,
            decision_outcome=DecisionOutcome.PARTIAL,
            service="api",
        )
        result = engine.compute_decision_accuracy()
        assert len(result) == 1
        assert result[0]["total_decisions"] == 3
        assert result[0]["correct"] == 1
        assert result[0]["accuracy_pct"] == pytest.approx(33.33, abs=0.1)

    def test_compute_decision_accuracy_empty(self, engine):
        assert engine.compute_decision_accuracy() == []

    def test_identify_systematic_errors(self, engine):
        for i in range(4):
            engine.add_record(
                name=f"d{i}",
                decision_type=DecisionType.REMEDIATE,
                decision_outcome=DecisionOutcome.INCORRECT,
                confidence=0.6,
                service="api",
            )
        result = engine.identify_systematic_errors()
        assert len(result) == 1
        assert result[0]["is_systematic"] is True

    def test_identify_systematic_errors_overridden(self, engine):
        engine.add_record(
            name="d1", decision_outcome=DecisionOutcome.OVERRIDDEN, confidence=0.5, service="api"
        )
        result = engine.identify_systematic_errors()
        assert len(result) == 1

    def test_identify_systematic_errors_empty(self, engine):
        engine.add_record(name="d1", decision_outcome=DecisionOutcome.CORRECT, service="api")
        assert engine.identify_systematic_errors() == []

    def test_recommend_decision_improvements_incorrect(self, engine):
        engine.add_record(
            name="d1", decision_outcome=DecisionOutcome.INCORRECT, confidence=0.3, service="api"
        )
        recs = engine.recommend_decision_improvements()
        high_priority = [r for r in recs if r["priority"] == "high"]
        assert len(high_priority) >= 1

    def test_recommend_decision_improvements_low_confidence(self, engine):
        engine.add_record(
            name="d1", decision_outcome=DecisionOutcome.CORRECT, confidence=0.2, service="api"
        )
        recs = engine.recommend_decision_improvements()
        med_priority = [r for r in recs if r["priority"] == "medium"]
        assert len(med_priority) == 1

    def test_recommend_decision_improvements_empty(self, engine):
        engine.add_record(name="ok", decision_outcome=DecisionOutcome.CORRECT, confidence=0.9)
        assert engine.recommend_decision_improvements() == []

    def test_process(self, engine):
        engine.add_record(name="d1", service="api", score=70.0)
        result = engine.process("api")
        assert result["count"] == 1

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=30.0, service="s")
        report = engine.generate_report()
        assert report.total_records == 1

    def test_clear_data(self, engine):
        engine.add_record(name="a", service="s")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1


# ============================================================================
# CostEffectivenessEngine
# ============================================================================


class TestCostEffectivenessEnums:
    def test_cost_category_values(self):
        assert CostCategory.LLM_TOKENS == "llm_tokens"
        assert CostCategory.COMPUTE == "compute"
        assert CostCategory.API_CALLS == "api_calls"
        assert CostCategory.HUMAN_TIME == "human_time"

    def test_roi_indicator_values(self):
        assert ROIIndicator.POSITIVE == "positive"
        assert ROIIndicator.NEGATIVE == "negative"

    def test_efficiency_quartile_values(self):
        assert EfficiencyQuartile.TOP == "top"
        assert EfficiencyQuartile.BOTTOM == "bottom"


class TestCostEffectivenessModels:
    def test_record_defaults(self):
        r = CostEffectivenessRecord()
        assert r.cost_category == CostCategory.LLM_TOKENS

    def test_analysis_defaults(self):
        a = CostEffectivenessAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = CostEffectivenessReport()
        assert r.total_records == 0


class TestCostEffectivenessEngine:
    @pytest.fixture()
    def engine(self):
        return CostEffectivenessEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._threshold == 50.0

    def test_add_record(self, engine):
        r = engine.add_record(
            name="c1",
            cost_category=CostCategory.LLM_TOKENS,
            cost_usd=0.50,
            time_saved_min=30.0,
            service="api",
        )
        assert r.cost_usd == 0.50

    def test_get_record(self, engine):
        r = engine.add_record(name="c1", service="s")
        assert engine.get_record(r.id) is not None

    def test_list_records_filter_category(self, engine):
        engine.add_record(name="a", cost_category=CostCategory.LLM_TOKENS)
        engine.add_record(name="b", cost_category=CostCategory.COMPUTE)
        res = engine.list_records(cost_category=CostCategory.COMPUTE)
        assert len(res) == 1

    def test_list_records_filter_roi(self, engine):
        engine.add_record(name="a", roi_indicator=ROIIndicator.POSITIVE)
        engine.add_record(name="b", roi_indicator=ROIIndicator.NEGATIVE)
        res = engine.list_records(roi_indicator=ROIIndicator.NEGATIVE)
        assert len(res) == 1

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r{i}", service="s")
        assert len(engine._records) == 100

    def test_compute_cost_per_resolution(self, engine):
        engine.add_record(name="c1", service="api", cost_usd=1.0, time_saved_min=60.0)
        engine.add_record(name="c2", service="api", cost_usd=2.0, time_saved_min=30.0)
        result = engine.compute_cost_per_resolution()
        assert len(result) == 1
        assert result[0]["total_cost_usd"] == 3.0
        assert result[0]["resolution_count"] == 2

    def test_compute_cost_per_resolution_zero_time(self, engine):
        engine.add_record(name="c1", service="api", cost_usd=1.0, time_saved_min=0.0)
        result = engine.compute_cost_per_resolution()
        assert result[0]["cost_per_min_saved"] == 0.0

    def test_compare_agent_vs_manual_cost(self, engine):
        engine.add_record(name="c1", service="api", cost_usd=5.0, time_saved_min=120.0)
        result = engine.compare_agent_vs_manual_cost()
        assert len(result) == 1
        assert result[0]["savings_usd"] > 0
        assert result[0]["verdict"] == "cost_effective"

    def test_compare_agent_vs_manual_cost_negative(self, engine):
        engine.add_record(name="c1", service="api", cost_usd=500.0, time_saved_min=1.0)
        result = engine.compare_agent_vs_manual_cost()
        assert result[0]["verdict"] == "not_cost_effective"

    def test_identify_cost_optimization_negative_roi(self, engine):
        engine.add_record(
            name="c1", roi_indicator=ROIIndicator.NEGATIVE, cost_usd=100.0, service="api"
        )
        recs = engine.identify_cost_optimization_opportunities()
        high = [r for r in recs if r["priority"] == "high"]
        assert len(high) == 1

    def test_identify_cost_optimization_bottom_quartile(self, engine):
        engine.add_record(
            name="c1",
            efficiency_quartile=EfficiencyQuartile.BOTTOM,
            roi_indicator=ROIIndicator.NEUTRAL,
            service="api",
        )
        recs = engine.identify_cost_optimization_opportunities()
        med = [r for r in recs if r["priority"] == "medium"]
        assert len(med) == 1

    def test_identify_cost_optimization_empty(self, engine):
        engine.add_record(
            name="ok",
            roi_indicator=ROIIndicator.POSITIVE,
            efficiency_quartile=EfficiencyQuartile.TOP,
        )
        assert engine.identify_cost_optimization_opportunities() == []

    def test_process(self, engine):
        engine.add_record(name="c1", service="api", score=60.0)
        result = engine.process("api")
        assert result["count"] == 1

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=30.0, service="s")
        report = engine.generate_report()
        assert report.total_records == 1

    def test_generate_report_healthy(self, engine):
        engine.add_record(name="ok", score=90.0, service="s")
        report = engine.generate_report()
        assert "healthy" in report.recommendations[0].lower()

    def test_clear_data(self, engine):
        engine.add_record(name="a", service="s")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1


# ============================================================================
# OperationalMaturityEngine
# ============================================================================


class TestOperationalMaturityEnums:
    def test_maturity_domain_values(self):
        assert MaturityDomain.INCIDENT_MANAGEMENT == "incident_management"
        assert MaturityDomain.MONITORING == "monitoring"
        assert MaturityDomain.AUTOMATION == "automation"
        assert MaturityDomain.LEARNING == "learning"
        assert MaturityDomain.SECURITY == "security"

    def test_maturity_level_values(self):
        assert MaturityLevel.AD_HOC == "ad_hoc"
        assert MaturityLevel.OPTIMIZED == "optimized"

    def test_assessment_confidence_values(self):
        assert AssessmentConfidence.HIGH == "high"
        assert AssessmentConfidence.LOW == "low"


class TestOperationalMaturityModels:
    def test_record_defaults(self):
        r = OperationalMaturityRecord()
        assert r.maturity_domain == MaturityDomain.INCIDENT_MANAGEMENT
        assert r.maturity_level == MaturityLevel.AD_HOC

    def test_analysis_defaults(self):
        a = OperationalMaturityAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = OperationalMaturityReport()
        assert r.total_records == 0


class TestOperationalMaturityEngine:
    @pytest.fixture()
    def engine(self):
        return OperationalMaturityEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._threshold == 50.0

    def test_add_record(self, engine):
        r = engine.add_record(
            name="m1",
            maturity_domain=MaturityDomain.MONITORING,
            maturity_level=MaturityLevel.DEFINED,
            score=70.0,
            service="platform",
            team="sre",
        )
        assert r.maturity_domain == MaturityDomain.MONITORING

    def test_get_record(self, engine):
        r = engine.add_record(name="m1", service="s")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("x") is None

    def test_list_records_filter_domain(self, engine):
        engine.add_record(name="a", maturity_domain=MaturityDomain.MONITORING)
        engine.add_record(name="b", maturity_domain=MaturityDomain.SECURITY)
        res = engine.list_records(maturity_domain=MaturityDomain.SECURITY)
        assert len(res) == 1

    def test_list_records_filter_level(self, engine):
        engine.add_record(name="a", maturity_level=MaturityLevel.AD_HOC)
        engine.add_record(name="b", maturity_level=MaturityLevel.OPTIMIZED)
        res = engine.list_records(maturity_level=MaturityLevel.OPTIMIZED)
        assert len(res) == 1

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r{i}", service="s")
        assert len(engine._records) == 100

    def test_compute_maturity_score(self, engine):
        engine.add_record(
            name="m1",
            maturity_domain=MaturityDomain.MONITORING,
            maturity_level=MaturityLevel.OPTIMIZED,
            score=90.0,
            automated_pct=95.0,
            service="platform",
        )
        result = engine.compute_maturity_score()
        assert len(result) == 1
        assert result[0]["maturity_label"] == "optimized"

    def test_compute_maturity_score_ad_hoc(self, engine):
        engine.add_record(
            name="m1",
            maturity_domain=MaturityDomain.INCIDENT_MANAGEMENT,
            maturity_level=MaturityLevel.AD_HOC,
            score=10.0,
            service="platform",
        )
        result = engine.compute_maturity_score()
        assert result[0]["maturity_label"] == "ad_hoc"

    def test_compute_maturity_score_empty(self, engine):
        assert engine.compute_maturity_score() == []

    def test_identify_maturity_gaps(self, engine):
        engine.add_record(
            name="m1", maturity_level=MaturityLevel.AD_HOC, score=10.0, team="sre", service="s"
        )
        engine.add_record(
            name="m2", maturity_level=MaturityLevel.OPTIMIZED, score=90.0, team="sre", service="s"
        )
        gaps = engine.identify_maturity_gaps()
        assert len(gaps) == 1
        assert gaps[0]["maturity_level"] == "ad_hoc"

    def test_identify_maturity_gaps_repeatable(self, engine):
        engine.add_record(
            name="m1", maturity_level=MaturityLevel.REPEATABLE, score=30.0, team="sre", service="s"
        )
        gaps = engine.identify_maturity_gaps()
        assert len(gaps) == 1

    def test_identify_maturity_gaps_empty(self, engine):
        engine.add_record(name="m1", maturity_level=MaturityLevel.DEFINED, score=60.0, team="sre")
        assert engine.identify_maturity_gaps() == []

    def test_recommend_maturity_roadmap_ad_hoc(self, engine):
        engine.add_record(name="m1", maturity_level=MaturityLevel.AD_HOC, team="sre", service="s")
        recs = engine.recommend_maturity_roadmap()
        high = [r for r in recs if r["priority"] == "high"]
        assert len(high) == 1
        assert high[0]["target_level"] == "repeatable"

    def test_recommend_maturity_roadmap_low_automation(self, engine):
        engine.add_record(
            name="m1",
            maturity_level=MaturityLevel.DEFINED,
            automated_pct=10.0,
            team="sre",
            service="s",
        )
        recs = engine.recommend_maturity_roadmap()
        med = [r for r in recs if r["priority"] == "medium"]
        assert len(med) == 1

    def test_recommend_maturity_roadmap_empty(self, engine):
        engine.add_record(
            name="ok", maturity_level=MaturityLevel.OPTIMIZED, automated_pct=95.0, team="sre"
        )
        assert engine.recommend_maturity_roadmap() == []

    def test_process(self, engine):
        engine.add_record(name="m1", service="platform", score=70.0)
        result = engine.process("platform")
        assert result["count"] == 1

    def test_process_not_found(self, engine):
        result = engine.process("nope")
        assert result["status"] == "not_found"

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=30.0, service="s")
        report = engine.generate_report()
        assert report.total_records == 1
        assert report.gap_count == 1

    def test_generate_report_healthy(self, engine):
        engine.add_record(name="ok", score=90.0, service="s")
        report = engine.generate_report()
        assert "healthy" in report.recommendations[0].lower()

    def test_generate_report_empty(self, engine):
        report = engine.generate_report()
        assert report.total_records == 0

    def test_clear_data(self, engine):
        engine.add_record(name="a", service="s")
        engine.add_analysis(name="b")
        engine.clear_data()
        assert len(engine._records) == 0
        assert len(engine._analyses) == 0

    def test_get_stats(self, engine):
        engine.add_record(
            name="a", maturity_domain=MaturityDomain.SECURITY, service="s1", team="t1"
        )
        stats = engine.get_stats()
        assert stats["total_records"] == 1
        assert "security" in stats["maturity_domain_distribution"]

    def test_analyze_distribution(self, engine):
        engine.add_record(name="a", maturity_domain=MaturityDomain.AUTOMATION, score=80.0)
        dist = engine.analyze_distribution()
        assert "automation" in dist

    def test_identify_gaps(self, engine):
        engine.add_record(name="low", score=20.0, service="s")
        gaps = engine.identify_gaps()
        assert len(gaps) == 1

    def test_rank_by_score(self, engine):
        engine.add_record(name="a", service="s1", score=30.0)
        engine.add_record(name="b", service="s2", score=90.0)
        ranked = engine.rank_by_score()
        assert ranked[0]["service"] == "s1"
