"""Tests for Cost Agent production-readiness (issue #185).

Covers:
- LLM FinOps recommendations with fallback
- OPA policy evaluation for cost-modifying actions
- Graph compilation
- Persistence (persist_agent_run + write_audit_log)
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.cost.graph import create_cost_graph
from shieldops.agents.cost.models import (
    CostAnalysisState,
    OptimizationRecommendation,
)
from shieldops.agents.cost.nodes import (
    _evaluate_cost_action,
    recommend_optimizations,
    set_toolkit,
)
from shieldops.agents.cost.tools import CostToolkit
from shieldops.models.base import Environment
from shieldops.policy.engine import Decision, PolicyDecision

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def stub_toolkit() -> CostToolkit:
    """A CostToolkit with no external dependencies (uses stubs)."""
    return CostToolkit()


@pytest.fixture()
def sample_state() -> CostAnalysisState:
    """Minimal state with resource costs for testing optimization node."""
    from shieldops.agents.cost.models import ResourceCost

    return CostAnalysisState(
        analysis_id="test-001",
        analysis_type="full",
        target_environment=Environment.DEVELOPMENT,
        period="30d",
        total_monthly_spend=10275.0,
        total_daily_spend=342.50,
        spend_by_service={"compute": 4800, "database": 2400},
        resource_costs=[
            ResourceCost(
                resource_id="i-web-001",
                resource_type="instance",
                service="compute",
                environment=Environment.DEVELOPMENT,
                provider="aws",
                daily_cost=48.0,
                monthly_cost=1440.0,
                usage_percent=35.0,
            ),
            ResourceCost(
                resource_id="pod-worker-001",
                resource_type="pod",
                service="kubernetes",
                environment=Environment.DEVELOPMENT,
                provider="kubernetes",
                daily_cost=30.0,
                monthly_cost=900.0,
                usage_percent=15.0,
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Graph compilation
# ---------------------------------------------------------------------------


class TestGraphCompiles:
    """The cost graph must compile without errors."""

    def test_graph_compiles(self) -> None:
        graph = create_cost_graph()
        app = graph.compile()
        assert app is not None

    def test_graph_has_expected_nodes(self) -> None:
        graph = create_cost_graph()
        node_names = set(graph.nodes.keys())
        assert "gather_costs" in node_names
        assert "detect_anomalies" in node_names
        assert "recommend_optimizations" in node_names
        assert "synthesize_savings" in node_names


# ---------------------------------------------------------------------------
# LLM FinOps recommendations with fallback
# ---------------------------------------------------------------------------


class TestLLMRecommendationsWithFallback:
    """The toolkit.generate_recommendations must use LLM and fall back to heuristics."""

    @pytest.mark.asyncio()
    async def test_llm_recommendations_success(self, stub_toolkit: CostToolkit) -> None:
        """When LLM succeeds, returns LLM-generated recommendations."""
        from shieldops.agents.cost.tools import CostRecommendationOutput

        mock_output = CostRecommendationOutput(
            recommendations=[
                {
                    "category": "reserved_instances",
                    "resource_id": "i-api-001",
                    "description": "Purchase 1-year RI for stable workload",
                    "monthly_savings": 500.0,
                    "confidence": 0.9,
                    "effort": "medium",
                    "implementation_steps": ["Analyze usage", "Purchase RI"],
                }
            ],
            total_estimated_savings=500.0,
            executive_summary="RI opportunity identified",
        )

        with patch(
            "shieldops.agents.cost.tools.llm_structured",
            new_callable=AsyncMock,
            return_value=mock_output,
        ):
            result = await stub_toolkit.generate_recommendations(
                {"total_monthly": 10000, "resource_costs": []}
            )
        assert len(result) == 1
        assert result[0]["category"] == "reserved_instances"

    @pytest.mark.asyncio()
    async def test_llm_recommendations_fallback(self, stub_toolkit: CostToolkit) -> None:
        """When LLM fails, falls back to heuristic recommendations."""
        cost_data: dict[str, Any] = {
            "total_monthly": 10000,
            "resource_costs": [
                {
                    "resource_id": "idle-box",
                    "usage_percent": 5,
                    "monthly_cost": 200,
                },
            ],
        }

        with patch(
            "shieldops.agents.cost.tools.llm_structured",
            new_callable=AsyncMock,
            side_effect=RuntimeError("LLM unavailable"),
        ):
            result = await stub_toolkit.generate_recommendations(cost_data)

        # Heuristic should detect the idle resource
        assert len(result) >= 1
        assert result[0]["category"] == "unused_resources"
        assert result[0]["resource_id"] == "idle-box"

    @pytest.mark.asyncio()
    async def test_recommend_optimizations_node_calls_generate_recommendations(
        self,
        stub_toolkit: CostToolkit,
        sample_state: CostAnalysisState,
    ) -> None:
        """The recommend_optimizations node calls toolkit.generate_recommendations."""
        set_toolkit(stub_toolkit)

        with (
            patch.object(
                stub_toolkit,
                "generate_recommendations",
                new_callable=AsyncMock,
                return_value=[],
            ) as mock_gen,
            patch(
                "shieldops.agents.cost.nodes.llm_structured",
                new_callable=AsyncMock,
                side_effect=RuntimeError("skip"),
            ),
            patch(
                "shieldops.agents.cost.nodes.policy_evaluate",
                new_callable=AsyncMock,
                return_value=PolicyDecision(
                    allowed=True,
                    decision=Decision.APPROVED,
                    reason="auto-approved",
                ),
            ),
        ):
            result = await recommend_optimizations(sample_state)

        mock_gen.assert_awaited_once()
        assert "optimization_recommendations" in result


# ---------------------------------------------------------------------------
# OPA policy evaluation for cost-modifying actions
# ---------------------------------------------------------------------------


class TestOPAPolicyEvaluation:
    """Cost-modifying recommendations must be evaluated against OPA policy."""

    @pytest.mark.asyncio()
    async def test_policy_called_for_rightsizing(self) -> None:
        """Rightsizing recommendations trigger OPA evaluation."""
        rec = OptimizationRecommendation(
            id="opt-test1",
            category="rightsizing",
            resource_id="i-web-001",
            service="compute",
            current_monthly_cost=1440,
            projected_monthly_cost=864,
            monthly_savings=576,
            confidence=0.8,
            effort="low",
            description="Downsize instance",
        )

        with patch(
            "shieldops.agents.cost.nodes.policy_evaluate",
            new_callable=AsyncMock,
            return_value=PolicyDecision(
                allowed=True,
                decision=Decision.APPROVED,
                reason="auto-approved",
            ),
        ) as mock_policy:
            result = await _evaluate_cost_action(rec, "development")

        mock_policy.assert_awaited_once()
        assert result["allowed"] is True
        assert result["decision"] == "approved"

    @pytest.mark.asyncio()
    async def test_policy_called_for_unused_resources(self) -> None:
        """Unused resource termination recommendations trigger OPA evaluation."""
        rec = OptimizationRecommendation(
            id="opt-test2",
            category="unused_resources",
            resource_id="pod-idle",
            service="kubernetes",
            current_monthly_cost=900,
            projected_monthly_cost=0,
            monthly_savings=900,
            confidence=0.7,
            effort="low",
            description="Terminate idle pod",
        )

        with patch(
            "shieldops.agents.cost.nodes.policy_evaluate",
            new_callable=AsyncMock,
            return_value=PolicyDecision(
                allowed=False,
                decision=Decision.REQUIRES_APPROVAL,
                reason="Risk score requires human approval",
            ),
        ) as mock_policy:
            result = await _evaluate_cost_action(rec, "production")

        mock_policy.assert_awaited_once()
        assert result["allowed"] is False
        assert result["decision"] == "requires_approval"

    @pytest.mark.asyncio()
    async def test_policy_skipped_for_readonly_category(self) -> None:
        """Non-modifying categories (e.g., 'architecture') skip OPA."""
        rec = OptimizationRecommendation(
            id="opt-test3",
            category="architecture",
            resource_id="vpc-001",
            service="network",
            current_monthly_cost=500,
            projected_monthly_cost=300,
            monthly_savings=200,
            confidence=0.6,
            effort="high",
            description="Consolidate VPCs",
        )

        with patch(
            "shieldops.agents.cost.nodes.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            result = await _evaluate_cost_action(rec, "production")

        mock_policy.assert_not_awaited()
        assert result["allowed"] is True
        assert result["decision"] == "skipped"

    @pytest.mark.asyncio()
    async def test_policy_decisions_populated_in_state(
        self,
        stub_toolkit: CostToolkit,
        sample_state: CostAnalysisState,
    ) -> None:
        """The recommend_optimizations node populates policy_decisions in state."""
        set_toolkit(stub_toolkit)

        with (
            patch(
                "shieldops.agents.cost.nodes.llm_structured",
                new_callable=AsyncMock,
                side_effect=RuntimeError("skip"),
            ),
            patch.object(
                stub_toolkit,
                "generate_recommendations",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "shieldops.agents.cost.nodes.policy_evaluate",
                new_callable=AsyncMock,
                return_value=PolicyDecision(
                    allowed=True,
                    decision=Decision.APPROVED,
                    reason="auto-approved",
                ),
            ),
        ):
            result = await recommend_optimizations(sample_state)

        assert "policy_decisions" in result
        assert isinstance(result["policy_decisions"], list)


# ---------------------------------------------------------------------------
# Persistence (persist_agent_run + write_audit_log)
# ---------------------------------------------------------------------------


class TestPersistence:
    """Runner must call persist_agent_run and write_audit_log after execution."""

    @pytest.mark.asyncio()
    async def test_persistence_called_on_success(self) -> None:
        """Successful analysis persists run and writes audit log."""
        with (
            patch(
                "shieldops.agents.cost.runner.persist_agent_run",
                new_callable=AsyncMock,
                return_value="run-123",
            ) as mock_persist,
            patch(
                "shieldops.agents.cost.runner.write_audit_log",
                new_callable=AsyncMock,
                return_value="audit-456",
            ) as mock_audit,
            patch(
                "shieldops.agents.cost.nodes.llm_structured",
                new_callable=AsyncMock,
                side_effect=RuntimeError("skip"),
            ),
            patch(
                "shieldops.agents.cost.nodes.policy_evaluate",
                new_callable=AsyncMock,
                return_value=PolicyDecision(
                    allowed=True,
                    decision=Decision.APPROVED,
                    reason="auto-approved",
                ),
            ),
        ):
            from shieldops.agents.cost.runner import CostRunner

            runner = CostRunner(org_id="org-test")
            result = await runner.analyze(
                environment=Environment.DEVELOPMENT,
                analysis_type="full",
            )

        assert result.error == ""
        mock_persist.assert_awaited_once()
        persist_kwargs = mock_persist.call_args
        assert persist_kwargs.kwargs["agent_name"] == "cost"
        assert persist_kwargs.kwargs["org_id"] == "org-test"

        mock_audit.assert_awaited_once()
        audit_kwargs = mock_audit.call_args
        assert audit_kwargs.kwargs["action"] == "cost_analysis_completed"
        assert audit_kwargs.kwargs["actor"] == "cost_agent"

    @pytest.mark.asyncio()
    async def test_persistence_called_on_failure(self) -> None:
        """Failed analysis persists error run and writes failure audit log."""
        with (
            patch(
                "shieldops.agents.cost.runner.persist_agent_run",
                new_callable=AsyncMock,
                return_value="run-err",
            ) as mock_persist,
            patch(
                "shieldops.agents.cost.runner.write_audit_log",
                new_callable=AsyncMock,
                return_value="audit-err",
            ) as mock_audit,
        ):
            from shieldops.agents.cost.runner import CostRunner

            runner = CostRunner(org_id="org-test")
            # Force the compiled app to raise
            runner._app = MagicMock()
            runner._app.ainvoke = AsyncMock(side_effect=RuntimeError("boom"))

            result = await runner.analyze(
                environment=Environment.PRODUCTION,
                analysis_type="full",
            )

        assert result.error == "boom"
        assert result.current_step == "failed"
        mock_persist.assert_awaited_once()
        assert mock_persist.call_args.kwargs["error_message"] == "boom"

        mock_audit.assert_awaited_once()
        assert mock_audit.call_args.kwargs["action"] == "cost_analysis_failed"
        assert mock_audit.call_args.kwargs["result"] == "failure"
