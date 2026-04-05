"""Behavioral tests for the Cost Agent CostToolkit.

Tests cover:
- Cost analysis with mocked AWS connector
- LLM recommendation generation with mock
- Fallback when connector/LLM unavailable
- Result structure validation
"""

from unittest.mock import AsyncMock, patch

import pytest

from shieldops.agents.cost.tools import CostRecommendationOutput, CostToolkit
from shieldops.connectors.base import ConnectorRouter
from shieldops.models.base import Environment, Resource

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def toolkit() -> CostToolkit:
    """Plain toolkit with no external dependencies."""
    return CostToolkit()


@pytest.fixture
def mock_aws_connector() -> AsyncMock:
    """Mock AWS connector that returns resource inventory."""
    connector = AsyncMock()
    connector.provider = "aws"
    connector.list_resources.return_value = [
        Resource(
            id="i-web-001",
            name="web-server-1",
            resource_type="instance",
            environment=Environment.PRODUCTION,
            provider="aws",
            labels={"monthly_cost": "1440", "usage_percent": "35"},
        ),
        Resource(
            id="i-api-001",
            name="api-server-1",
            resource_type="instance",
            environment=Environment.PRODUCTION,
            provider="aws",
            labels={"monthly_cost": "2880", "usage_percent": "72"},
        ),
        Resource(
            id="rds-main",
            name="main-db",
            resource_type="database",
            environment=Environment.PRODUCTION,
            provider="aws",
            labels={"monthly_cost": "2400", "usage_percent": "55"},
        ),
    ]
    return connector


@pytest.fixture
def router_with_aws(mock_aws_connector: AsyncMock) -> ConnectorRouter:
    """ConnectorRouter with a mocked AWS connector registered."""
    router = ConnectorRouter()
    router.register(mock_aws_connector)
    return router


@pytest.fixture
def toolkit_with_aws(router_with_aws: ConnectorRouter) -> CostToolkit:
    """CostToolkit wired to a mocked AWS connector."""
    return CostToolkit(connector_router=router_with_aws)


@pytest.fixture
def sample_cost_data() -> dict:
    """Sample billing data used for recommendation tests."""
    return {
        "total_monthly": 10275.00,
        "resource_costs": [
            {
                "resource_id": "i-web-001",
                "service": "compute",
                "daily_cost": 48.00,
                "monthly_cost": 1440.00,
                "usage_percent": 35.0,
            },
            {
                "resource_id": "pod-idle-001",
                "service": "kubernetes",
                "daily_cost": 30.00,
                "monthly_cost": 900.00,
                "usage_percent": 5.0,
            },
            {
                "resource_id": "i-api-001",
                "service": "compute",
                "daily_cost": 96.00,
                "monthly_cost": 2880.00,
                "usage_percent": 72.0,
            },
        ],
    }


# ===========================================================================
# Cost analysis with mocked AWS connector
# ===========================================================================


class TestCostAnalysisWithAWSConnector:
    """Test billing queries routed through the AWS connector."""

    @pytest.mark.asyncio
    async def test_query_billing_uses_aws_connector(
        self, toolkit_with_aws: CostToolkit, mock_aws_connector: AsyncMock
    ) -> None:
        """When no billing source is configured but AWS connector exists,
        billing should be derived from the connector's resource inventory."""
        result = await toolkit_with_aws.query_billing(
            environment=Environment.PRODUCTION, period="30d"
        )

        mock_aws_connector.list_resources.assert_awaited_once()
        assert "resource_costs" in result
        assert len(result["resource_costs"]) == 3
        assert result["total_monthly"] > 0

    @pytest.mark.asyncio
    async def test_query_billing_resource_costs_structure(
        self, toolkit_with_aws: CostToolkit
    ) -> None:
        """Each resource cost entry should have required fields."""
        result = await toolkit_with_aws.query_billing(environment=Environment.PRODUCTION)

        for rc in result["resource_costs"]:
            assert "resource_id" in rc
            assert "monthly_cost" in rc
            assert "daily_cost" in rc
            assert "usage_percent" in rc
            assert rc["monthly_cost"] >= 0
            assert rc["daily_cost"] >= 0

    @pytest.mark.asyncio
    async def test_query_billing_explicit_source_takes_priority(
        self, router_with_aws: ConnectorRouter
    ) -> None:
        """An explicit billing source should be used before the AWS connector."""
        billing_source = AsyncMock()
        billing_source.query.return_value = {
            "total_daily": 500.0,
            "total_monthly": 15000.0,
            "by_service": {"compute": 10000.0},
            "by_environment": {"production": 15000.0},
            "resource_costs": [
                {"resource_id": "custom-1", "daily_cost": 500.0, "monthly_cost": 15000.0}
            ],
        }
        toolkit = CostToolkit(connector_router=router_with_aws, billing_sources=[billing_source])

        result = await toolkit.query_billing(environment=Environment.PRODUCTION)

        billing_source.query.assert_awaited_once()
        assert result["total_monthly"] == 15000.0

    @pytest.mark.asyncio
    async def test_resource_inventory_uses_connector(
        self, toolkit_with_aws: CostToolkit, mock_aws_connector: AsyncMock
    ) -> None:
        """Resource inventory should query through the connector router."""
        result = await toolkit_with_aws.get_resource_inventory(environment=Environment.PRODUCTION)

        mock_aws_connector.list_resources.assert_awaited_once()
        assert result["total_count"] == 3
        assert "aws" in result["providers"]


# ===========================================================================
# LLM recommendation generation
# ===========================================================================


class TestLLMRecommendations:
    """Test LLM-powered cost recommendation generation."""

    @pytest.mark.asyncio
    async def test_generate_recommendations_with_llm(
        self, toolkit: CostToolkit, sample_cost_data: dict
    ) -> None:
        """When the LLM is available, recommendations should come from it."""
        mock_output = CostRecommendationOutput(
            recommendations=[
                {
                    "category": "rightsizing",
                    "resource_id": "i-web-001",
                    "description": "Downsize i-web-001 from m5.xlarge to m5.large",
                    "monthly_savings": 576.0,
                    "confidence": 0.85,
                    "effort": "low",
                    "implementation_steps": ["Verify workload", "Resize instance"],
                },
                {
                    "category": "unused_resources",
                    "resource_id": "pod-idle-001",
                    "description": "Terminate idle pod pod-idle-001",
                    "monthly_savings": 900.0,
                    "confidence": 0.9,
                    "effort": "low",
                    "implementation_steps": ["Confirm no dependents", "Terminate"],
                },
            ],
            total_estimated_savings=1476.0,
            executive_summary="Identified 2 optimizations saving $1,476/mo.",
        )

        with patch(
            "shieldops.agents.cost.tools.llm_structured",
            new_callable=AsyncMock,
            return_value=mock_output,
        ):
            recs = await toolkit.generate_recommendations(sample_cost_data)

        assert len(recs) == 2
        assert recs[0]["category"] == "rightsizing"
        assert recs[1]["monthly_savings"] == 900.0

    @pytest.mark.asyncio
    async def test_generate_recommendations_dict_result(
        self, toolkit: CostToolkit, sample_cost_data: dict
    ) -> None:
        """When llm_structured returns a dict, recommendations should be extracted."""
        mock_dict = {
            "recommendations": [
                {"category": "scheduling", "resource_id": "dev-1", "monthly_savings": 200.0}
            ],
            "total_estimated_savings": 200.0,
            "executive_summary": "Schedule dev resources off-hours.",
        }

        with patch(
            "shieldops.agents.cost.tools.llm_structured",
            new_callable=AsyncMock,
            return_value=mock_dict,
        ):
            recs = await toolkit.generate_recommendations(sample_cost_data)

        assert len(recs) == 1
        assert recs[0]["category"] == "scheduling"


# ===========================================================================
# Fallback when connector/LLM unavailable
# ===========================================================================


class TestFallbackBehavior:
    """Test graceful degradation when external dependencies are unavailable."""

    @pytest.mark.asyncio
    async def test_billing_fallback_without_connector(self, toolkit: CostToolkit) -> None:
        """Without any billing source or connector, stub data should be returned."""
        result = await toolkit.query_billing(environment=Environment.PRODUCTION)

        assert result["total_monthly"] == 10275.00
        assert len(result["resource_costs"]) == 5
        assert "by_service" in result

    @pytest.mark.asyncio
    async def test_billing_fallback_when_connector_fails(self) -> None:
        """When the AWS connector raises, billing should fall back to stub."""
        failing_connector = AsyncMock()
        failing_connector.provider = "aws"
        failing_connector.list_resources.side_effect = RuntimeError("Connection refused")

        router = ConnectorRouter()
        router.register(failing_connector)
        toolkit = CostToolkit(connector_router=router)

        result = await toolkit.query_billing(environment=Environment.PRODUCTION)

        # Should get stub data, not raise
        assert result["total_monthly"] == 10275.00

    @pytest.mark.asyncio
    async def test_billing_fallback_when_source_fails(self) -> None:
        """When an explicit billing source fails, subsequent sources should be tried."""
        failing_source = AsyncMock()
        failing_source.query.side_effect = ConnectionError("Timeout")

        toolkit = CostToolkit(billing_sources=[failing_source])
        result = await toolkit.query_billing(environment=Environment.PRODUCTION)

        # Should fall through to stub
        assert result["total_monthly"] == 10275.00

    @pytest.mark.asyncio
    async def test_resource_inventory_fallback(self, toolkit: CostToolkit) -> None:
        """Without a connector, resource inventory returns stub data."""
        result = await toolkit.get_resource_inventory(environment=Environment.PRODUCTION)

        assert result["total_count"] == 5
        assert any(r["resource_id"] == "i-web-001" for r in result["resources"])

    @pytest.mark.asyncio
    async def test_generate_recommendations_llm_fallback(
        self, toolkit: CostToolkit, sample_cost_data: dict
    ) -> None:
        """When the LLM fails, heuristic recommendations should be generated."""
        with patch(
            "shieldops.agents.cost.tools.llm_structured",
            new_callable=AsyncMock,
            side_effect=RuntimeError("LLM unavailable"),
        ):
            recs = await toolkit.generate_recommendations(sample_cost_data)

        # pod-idle-001 has 5% usage and $900/mo -> unused_resources
        # i-web-001 has 35% usage and $1440/mo -> rightsizing
        assert len(recs) >= 2
        categories = {r["category"] for r in recs}
        assert "unused_resources" in categories
        assert "rightsizing" in categories

    @pytest.mark.asyncio
    async def test_heuristic_recommendations_skip_well_utilized(self, toolkit: CostToolkit) -> None:
        """Heuristic recommendations should skip well-utilized resources."""
        cost_data = {
            "resource_costs": [
                {
                    "resource_id": "healthy-1",
                    "monthly_cost": 5000.0,
                    "usage_percent": 80.0,
                },
            ],
        }
        recs = toolkit._heuristic_recommendations(cost_data)
        assert len(recs) == 0


# ===========================================================================
# Result structure validation
# ===========================================================================


class TestResultStructure:
    """Test that toolkit methods return well-structured data."""

    @pytest.mark.asyncio
    async def test_detect_anomalies_structure(self, toolkit: CostToolkit) -> None:
        """Anomaly detection results should have required keys and types."""
        resource_costs = [
            {"resource_id": "r-1", "service": "compute", "daily_cost": 100, "usage_percent": 10},
            {"resource_id": "r-2", "service": "storage", "daily_cost": 5, "usage_percent": 90},
        ]
        result = await toolkit.detect_anomalies(resource_costs)

        assert "anomalies" in result
        assert "total_anomalies" in result
        assert "critical_count" in result
        assert isinstance(result["anomalies"], list)
        assert result["total_anomalies"] == len(result["anomalies"])

        for anomaly in result["anomalies"]:
            assert "resource_id" in anomaly
            assert "anomaly_type" in anomaly
            assert "severity" in anomaly
            assert "actual_daily_cost" in anomaly
            assert anomaly["severity"] in ("critical", "high", "medium", "low")

    @pytest.mark.asyncio
    async def test_optimization_opportunities_structure(self, toolkit: CostToolkit) -> None:
        """Optimization results should have required keys."""
        resource_costs = [
            {
                "resource_id": "r-1",
                "service": "compute",
                "monthly_cost": 1500,
                "usage_percent": 20,
            },
        ]
        result = await toolkit.get_optimization_opportunities(resource_costs)

        assert "recommendations" in result
        assert "total_recommendations" in result
        assert "total_potential_monthly_savings" in result
        assert result["total_recommendations"] == len(result["recommendations"])

        for rec in result["recommendations"]:
            assert "category" in rec
            assert "resource_id" in rec
            assert "monthly_savings" in rec
            assert "implementation_steps" in rec
            assert isinstance(rec["implementation_steps"], list)

    @pytest.mark.asyncio
    async def test_automation_savings_structure(self, toolkit: CostToolkit) -> None:
        """Automation savings should return expected fields."""
        result = await toolkit.get_automation_savings(period="7d")

        assert result["period"] == "7d"
        assert "total_hours_saved" in result
        assert "automation_savings_usd" in result
        assert result["automation_savings_usd"] > 0

    @pytest.mark.asyncio
    async def test_anomaly_detection_low_usage_high_cost(self, toolkit: CostToolkit) -> None:
        """A resource with low usage and high cost should be flagged as unused anomaly."""
        resource_costs = [
            {"resource_id": "idle-1", "service": "compute", "daily_cost": 60, "usage_percent": 5},
        ]
        result = await toolkit.detect_anomalies(resource_costs)

        anomaly_types = [a["anomaly_type"] for a in result["anomalies"]]
        assert "unused" in anomaly_types

    @pytest.mark.asyncio
    async def test_no_anomalies_for_normal_resources(self, toolkit: CostToolkit) -> None:
        """Well-utilized, moderately priced resources should produce no anomalies."""
        resource_costs = [
            {"resource_id": "ok-1", "service": "compute", "daily_cost": 10, "usage_percent": 70},
        ]
        result = await toolkit.detect_anomalies(resource_costs)

        # daily_cost=10 is below 20, so no "unused" anomaly
        # 10 > 7*1.3 = 9.1 so there may be a spike anomaly (borderline)
        # The key point: no "unused" anomaly should fire
        unused = [a for a in result["anomalies"] if a["anomaly_type"] == "unused"]
        assert len(unused) == 0

    def test_parse_period_days(self) -> None:
        """Period string parser should handle common formats."""
        assert CostToolkit._parse_period_days("30d") == 30
        assert CostToolkit._parse_period_days("7d") == 7
        assert CostToolkit._parse_period_days("90d") == 90
        assert CostToolkit._parse_period_days("invalid") == 30  # default

    def test_cost_recommendation_output_model(self) -> None:
        """CostRecommendationOutput model should validate correctly."""
        output = CostRecommendationOutput(
            recommendations=[{"category": "rightsizing", "resource_id": "x"}],
            total_estimated_savings=500.0,
            executive_summary="Test summary",
        )
        assert len(output.recommendations) == 1
        assert output.total_estimated_savings == 500.0
