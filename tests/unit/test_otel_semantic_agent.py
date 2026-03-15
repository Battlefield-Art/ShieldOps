"""Tests for the OTel Semantic Conventions agent."""

from __future__ import annotations

import pytest

from shieldops.agents.otel_semantic.models import (
    ComplianceResult,
    ConventionRule,
    ConventionScope,
    ConventionStatus,
    OTelSemanticState,
    Violation,
    ViolationSeverity,
)
from shieldops.agents.otel_semantic.tools import OTelSemanticToolkit


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------


class TestConventionScope:
    def test_values(self) -> None:
        assert ConventionScope.RESOURCE == "resource"
        assert ConventionScope.SPAN == "span"
        assert ConventionScope.METRIC == "metric"
        assert ConventionScope.LOG == "log"

    def test_all_members(self) -> None:
        assert len(ConventionScope) == 4


class TestViolationSeverity:
    def test_values(self) -> None:
        assert ViolationSeverity.ERROR == "error"
        assert ViolationSeverity.WARNING == "warning"
        assert ViolationSeverity.INFO == "info"


class TestConventionStatus:
    def test_values(self) -> None:
        assert ConventionStatus.COMPLIANT == "compliant"
        assert ConventionStatus.NON_COMPLIANT == "non_compliant"
        assert ConventionStatus.PARTIAL == "partial"
        assert ConventionStatus.UNKNOWN == "unknown"


class TestConventionRule:
    def test_defaults(self) -> None:
        rule = ConventionRule()
        assert rule.scope == ConventionScope.RESOURCE
        assert rule.attribute_name == ""
        assert rule.expected_pattern == ""
        assert rule.description == ""

    def test_creation(self) -> None:
        rule = ConventionRule(
            scope=ConventionScope.SPAN,
            attribute_name="http.request.method",
            expected_pattern=r"^(GET|POST)$",
            description="HTTP method",
        )
        assert rule.scope == ConventionScope.SPAN
        assert rule.attribute_name == "http.request.method"


class TestViolation:
    def test_defaults(self) -> None:
        v = Violation()
        assert v.service == ""
        assert v.severity == ViolationSeverity.WARNING
        assert v.fix_suggestion == ""

    def test_creation(self) -> None:
        v = Violation(
            service="api-svc",
            scope=ConventionScope.RESOURCE,
            attribute_name="service.name",
            actual_value="<missing>",
            expected="^[a-z]",
            severity=ViolationSeverity.ERROR,
            fix_suggestion="Add service.name",
        )
        assert v.service == "api-svc"
        assert v.severity == ViolationSeverity.ERROR


class TestComplianceResult:
    def test_defaults(self) -> None:
        cr = ComplianceResult()
        assert cr.service == ""
        assert cr.total_attributes == 0
        assert cr.violations == []
        assert cr.score == 0.0

    def test_with_violations(self) -> None:
        cr = ComplianceResult(
            service="web",
            total_attributes=10,
            compliant_count=8,
            violations=[Violation(service="web")],
            score=80.0,
        )
        assert cr.compliant_count == 8
        assert len(cr.violations) == 1


class TestOTelSemanticState:
    def test_defaults(self) -> None:
        state = OTelSemanticState()
        assert state.request_id == ""
        assert state.target_services == []
        assert state.rules == []
        assert state.results == []
        assert state.overall_score == 0.0
        assert state.reasoning_chain == []
        assert state.error == ""

    def test_with_services(self) -> None:
        state = OTelSemanticState(
            target_services=["svc-a", "svc-b"],
            overall_score=95.0,
        )
        assert len(state.target_services) == 2
        assert state.overall_score == 95.0


# ---------------------------------------------------------------------------
# Toolkit Tests
# ---------------------------------------------------------------------------


class TestOTelSemanticToolkit:
    def test_init_no_clients(self) -> None:
        toolkit = OTelSemanticToolkit()
        assert toolkit._telemetry_client is None
        assert toolkit._repository is None

    def test_load_all_rules(self) -> None:
        toolkit = OTelSemanticToolkit()
        rules = toolkit.load_convention_rules()
        # Should have rules for all 4 scopes
        assert len(rules) > 0
        scopes = {r.scope for r in rules}
        assert ConventionScope.RESOURCE in scopes
        assert ConventionScope.SPAN in scopes
        assert ConventionScope.METRIC in scopes
        assert ConventionScope.LOG in scopes

    def test_load_resource_rules_only(self) -> None:
        toolkit = OTelSemanticToolkit()
        rules = toolkit.load_convention_rules(scope=ConventionScope.RESOURCE)
        assert all(r.scope == ConventionScope.RESOURCE for r in rules)
        assert len(rules) == 3  # service.name, service.version, deployment.environment

    def test_load_span_rules_only(self) -> None:
        toolkit = OTelSemanticToolkit()
        rules = toolkit.load_convention_rules(scope=ConventionScope.SPAN)
        assert all(r.scope == ConventionScope.SPAN for r in rules)
        assert len(rules) == 3

    def test_load_metric_rules_only(self) -> None:
        toolkit = OTelSemanticToolkit()
        rules = toolkit.load_convention_rules(scope=ConventionScope.METRIC)
        assert all(r.scope == ConventionScope.METRIC for r in rules)
        assert len(rules) == 3

    def test_load_log_rules_only(self) -> None:
        toolkit = OTelSemanticToolkit()
        rules = toolkit.load_convention_rules(scope=ConventionScope.LOG)
        assert all(r.scope == ConventionScope.LOG for r in rules)
        assert len(rules) == 2

    @pytest.mark.asyncio
    async def test_scan_service_simulated(self) -> None:
        toolkit = OTelSemanticToolkit()
        rules = toolkit.load_convention_rules()
        result = await toolkit.scan_service("test-service", rules)
        assert result.service == "test-service"
        assert result.total_attributes > 0
        assert result.score >= 0.0

    @pytest.mark.asyncio
    async def test_scan_service_compliance_score(self) -> None:
        toolkit = OTelSemanticToolkit()
        rules = toolkit.load_convention_rules()
        result = await toolkit.scan_service("my-app", rules)
        # Simulated data should be mostly compliant
        assert result.score > 0.0
        assert result.compliant_count <= result.total_attributes

    def test_suggest_fixes_empty(self) -> None:
        toolkit = OTelSemanticToolkit()
        fixes = toolkit.suggest_fixes([])
        assert fixes == []

    def test_suggest_fixes_deprecated(self) -> None:
        toolkit = OTelSemanticToolkit()
        violation = Violation(
            service="web-svc",
            scope=ConventionScope.SPAN,
            attribute_name="http.request.method",
            actual_value="[deprecated] http.method=GET",
            expected=r"^(GET|POST)$",
            severity=ViolationSeverity.WARNING,
            fix_suggestion="Rename http.method to http.request.method",
        )
        fixes = toolkit.suggest_fixes([violation])
        assert len(fixes) == 1
        assert "processor_config" in fixes[0]
        assert "transform" in fixes[0]["processor_config"]

    def test_suggest_fixes_missing(self) -> None:
        toolkit = OTelSemanticToolkit()
        violation = Violation(
            service="web-svc",
            scope=ConventionScope.RESOURCE,
            attribute_name="service.name",
            actual_value="<missing>",
            expected=r"^[a-z]",
            severity=ViolationSeverity.ERROR,
            fix_suggestion="Add service.name",
        )
        fixes = toolkit.suggest_fixes([violation])
        assert len(fixes) == 1
        assert "sdk_config" in fixes[0]

    @pytest.mark.asyncio
    async def test_apply_processor_fix_simulated(self) -> None:
        toolkit = OTelSemanticToolkit()
        result = await toolkit.apply_processor_fix(
            service="web-svc",
            fix_config={"transform": {"trace_statements": []}},
        )
        assert result["status"] == "simulated"
        assert result["service"] == "web-svc"

    def test_suggest_fixes_multiple_violations(self) -> None:
        toolkit = OTelSemanticToolkit()
        violations = [
            Violation(
                service="svc-a",
                scope=ConventionScope.RESOURCE,
                attribute_name="service.name",
                actual_value="<missing>",
                expected=r"^[a-z]",
                severity=ViolationSeverity.ERROR,
                fix_suggestion="Add service.name",
            ),
            Violation(
                service="svc-a",
                scope=ConventionScope.SPAN,
                attribute_name="http.request.method",
                actual_value="[deprecated] http.method=POST",
                expected=r"^(GET|POST)$",
                severity=ViolationSeverity.WARNING,
                fix_suggestion="Rename attribute",
            ),
        ]
        fixes = toolkit.suggest_fixes(violations)
        assert len(fixes) == 2
