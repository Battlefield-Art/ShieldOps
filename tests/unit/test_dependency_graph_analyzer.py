"""Tests for dependency_graph_analyzer."""

from __future__ import annotations

from shieldops.agents.dependency_graph_analyzer.models import (
    DependencyGraphAnalyzerState,
    GraphStage,
    HealthStatus,
    NodeType,
)


class TestEnums:
    def test_graphstage(self) -> None:
        assert GraphStage.BUILD_GRAPH == "build_graph"
        assert len(GraphStage) >= 3

    def test_healthstatus(self) -> None:
        assert HealthStatus.HEALTHY == "healthy"
        assert len(HealthStatus) >= 3

    def test_nodetype(self) -> None:
        assert NodeType.DIRECT == "direct"
        assert len(NodeType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = DependencyGraphAnalyzerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = DependencyGraphAnalyzerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
