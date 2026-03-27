"""Tests for shieldops.agents.otel_semantic."""

from __future__ import annotations

from shieldops.agents.otel_semantic.models import (
    ConventionScope,
    ConventionStatus,
    OTelSemanticState,
    ViolationSeverity,
)


class TestEnums:
    def test_conventionscope_resource(self):
        assert ConventionScope.RESOURCE == "resource"

    def test_conventionscope_span(self):
        assert ConventionScope.SPAN == "span"

    def test_conventionscope_metric(self):
        assert ConventionScope.METRIC == "metric"

    def test_conventionscope_log(self):
        assert ConventionScope.LOG == "log"

    def test_violationseverity_error(self):
        assert ViolationSeverity.ERROR == "error"

    def test_violationseverity_warning(self):
        assert ViolationSeverity.WARNING == "warning"

    def test_violationseverity_info(self):
        assert ViolationSeverity.INFO == "info"

    def test_conventionstatus_compliant(self):
        assert ConventionStatus.COMPLIANT == "compliant"

    def test_conventionstatus_non_compliant(self):
        assert ConventionStatus.NON_COMPLIANT == "non_compliant"

    def test_conventionstatus_partial(self):
        assert ConventionStatus.PARTIAL == "partial"

    def test_conventionstatus_unknown(self):
        assert ConventionStatus.UNKNOWN == "unknown"


class TestModels:
    def test_state_defaults(self):
        s = OTelSemanticState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.otel_semantic.graph import (
            create_otel_semantic_graph,
        )

        sg = create_otel_semantic_graph()
        assert sg.compile() is not None
