"""Security Data Mesh Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DataProduct,
    FederatedQuery,
    ReasoningStep,
    SDMStage,
    SecurityDomain,
)
from .tools import SecurityDataMeshToolkit

logger = structlog.get_logger()

_toolkit: SecurityDataMeshToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: SecurityDataMeshToolkit) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> SecurityDataMeshToolkit:
    assert _toolkit is not None, "Toolkit not initialised"
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Domains
# ------------------------------------------------------------------


async def discover_domains(
    state: dict[str, Any],
    toolkit: SecurityDataMeshToolkit,
) -> dict[str, Any]:
    """Discover security data domains in the mesh."""
    logger.info("sdm.node.discover_domains")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    domains = await toolkit.discover_domains(tenant_id)
    data = [d.model_dump() for d in domains]

    note = f"Discovered {len(domains)} security data domains"

    return {
        "stage": SDMStage.MAP_DATA_PRODUCTS.value,
        "security_domains": data,
        "total_domains": len(domains),
        "current_step": "discover_domains",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="discover_domains",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Map Data Products
# ------------------------------------------------------------------


async def map_data_products(
    state: dict[str, Any],
    toolkit: SecurityDataMeshToolkit,
) -> dict[str, Any]:
    """Map data products within each domain."""
    logger.info("sdm.node.map_data_products")
    state = _to_dict(state)

    domains = [SecurityDomain(**d) for d in state.get("security_domains", [])]
    products = await toolkit.map_data_products(domains)
    data = [p.model_dump() for p in products]

    note = f"Mapped {len(products)} data products across {len(domains)} domains"

    try:
        from .prompts import SYSTEM_ANALYZE, DomainInsight

        ctx = json.dumps(
            {
                "domains": [
                    {
                        "name": d.name,
                        "status": d.status.value,
                        "products": d.data_product_count,
                        "freshness": d.freshness_minutes,
                    }
                    for d in domains[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            DomainInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Data mesh domains:\n{ctx}",
                schema=DomainInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sdm",
            node="map_data_products",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sdm",
            node="map_data_products",
        )

    return {
        "stage": SDMStage.ASSESS_QUALITY.value,
        "data_products": data,
        "total_products": len(products),
        "current_step": "map_data_products",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="map_data_products",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Assess Quality
# ------------------------------------------------------------------


async def assess_quality(
    state: dict[str, Any],
    toolkit: SecurityDataMeshToolkit,
) -> dict[str, Any]:
    """Assess quality of each data product."""
    logger.info("sdm.node.assess_quality")
    state = _to_dict(state)

    products = [DataProduct(**p) for p in state.get("data_products", [])]
    assessments = await toolkit.assess_quality(products)
    data = [a.model_dump() for a in assessments]

    poor = sum(1 for a in assessments if a.grade.value in ("poor", "failing"))
    note = f"Assessed {len(assessments)} products, {poor} below threshold"

    return {
        "stage": SDMStage.FEDERATE_QUERIES.value,
        "quality_assessments": data,
        "current_step": "assess_quality",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_quality",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Federate Queries
# ------------------------------------------------------------------


async def federate_queries(
    state: dict[str, Any],
    toolkit: SecurityDataMeshToolkit,
) -> dict[str, Any]:
    """Run federated queries across security domains."""
    logger.info("sdm.node.federate_queries")
    state = _to_dict(state)

    domains = [SecurityDomain(**d) for d in state.get("security_domains", [])]
    queries = await toolkit.federate_queries(domains)
    data = [q.model_dump() for q in queries]

    total_records = sum(q.records_returned for q in queries)
    note = f"Executed {len(queries)} federated queries, {total_records} records"

    return {
        "stage": SDMStage.GENERATE_INSIGHTS.value,
        "federated_queries": data,
        "current_step": "federate_queries",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="federate_queries",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Generate Insights
# ------------------------------------------------------------------


async def generate_insights(
    state: dict[str, Any],
    toolkit: SecurityDataMeshToolkit,
) -> dict[str, Any]:
    """Generate cross-domain security insights."""
    logger.info("sdm.node.generate_insights")
    state = _to_dict(state)

    queries = [FederatedQuery(**q) for q in state.get("federated_queries", [])]
    insights = await toolkit.generate_insights(queries)
    data = [i.model_dump() for i in insights]

    critical = sum(1 for i in insights if i.severity == "critical")
    note = f"Generated {len(insights)} insights, {critical} critical"

    return {
        "stage": SDMStage.REPORT.value,
        "mesh_insights": data,
        "current_step": "generate_insights",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="generate_insights",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: SecurityDataMeshToolkit,
) -> dict[str, Any]:
    """Compile the final security data mesh report."""
    logger.info("sdm.node.report")
    state = _to_dict(state)

    total_domains = state.get("total_domains", 0)
    total_products = state.get("total_products", 0)
    quality_count = len(state.get("quality_assessments", []))
    insight_count = len(state.get("mesh_insights", []))

    lines = [
        "# Security Data Mesh Report",
        "",
        f"**Domains discovered:** {total_domains}",
        f"**Data products mapped:** {total_products}",
        f"**Quality assessments:** {quality_count}",
        f"**Cross-domain insights:** {insight_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_domains": total_domains,
                "total_products": total_products,
                "quality_count": quality_count,
                "insights": insight_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Data mesh report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sdm",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sdm",
            node="report",
        )

    return {
        "stage": SDMStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
