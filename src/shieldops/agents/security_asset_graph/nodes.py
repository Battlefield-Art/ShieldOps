"""Node implementations for the Security Asset Graph
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_asset_graph.models import (
    ReasoningStep,
    SAGStage,
    SecurityAssetGraphState,
)
from shieldops.agents.security_asset_graph.prompts import (
    SYSTEM_CRITICAL_PATH,
    SYSTEM_DEPENDENCIES,
    SYSTEM_IMPACT,
    SYSTEM_REPORT,
    AssetGraphReportOutput,
    CriticalPathOutput,
    DependencyMappingOutput,
    ImpactAnalysisOutput,
)
from shieldops.agents.security_asset_graph.tools import (
    SecurityAssetGraphToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityAssetGraphToolkit | None = None


def set_toolkit(
    toolkit: SecurityAssetGraphToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityAssetGraphToolkit:
    if _toolkit is None:
        return SecurityAssetGraphToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: discover_assets
# ------------------------------------------------------------------


async def discover_assets(
    state: SecurityAssetGraphState,
) -> dict[str, Any]:
    """Discover assets in the target environment."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.discover_assets(
        environment=state.target_environment,
        asset_types=state.asset_types,
        scope=state.scope,
    )

    assets: list[dict[str, Any]] = list(results)

    step = _step(
        state.reasoning_chain,
        "discover_assets",
        (f"Env: {state.target_environment}, types={len(state.asset_types)}"),
        f"Discovered {len(assets)} assets",
        start,
        "cmdb_scanner",
    )

    return {
        "assets": assets,
        "total_assets": len(assets),
        "stage": SAGStage.DISCOVER_ASSETS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_assets",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: map_dependencies
# ------------------------------------------------------------------


async def map_dependencies(
    state: SecurityAssetGraphState,
) -> dict[str, Any]:
    """Map dependency relationships between discovered
    assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    deps = await toolkit.map_dependencies(
        assets=state.assets,
        depth_limit=state.depth_limit,
    )

    dependencies: list[dict[str, Any]] = list(deps)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "asset_count": len(state.assets),
                "asset_sample": state.assets[:5],
                "depth_limit": state.depth_limit,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DEPENDENCIES,
            user_prompt=f"Map dependencies:\n{ctx}",
            schema=DependencyMappingOutput,
        )
        if llm_out.dependencies:  # type: ignore[union-attr]
            dependencies = [
                *dependencies,
                *llm_out.dependencies,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="map_dependencies",
            count=len(
                llm_out.dependencies  # type: ignore[union-attr]
            ),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_dependencies",
        )

    step = _step(
        state.reasoning_chain,
        "map_dependencies",
        f"Mapping {len(state.assets)} assets",
        f"Found {len(dependencies)} dependencies",
        start,
        "dependency_mapper",
    )

    return {
        "dependencies": dependencies,
        "total_dependencies": len(dependencies),
        "stage": SAGStage.MAP_DEPENDENCIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_dependencies",
    }


# ------------------------------------------------------------------
# Node: analyze_impact
# ------------------------------------------------------------------


async def analyze_impact(
    state: SecurityAssetGraphState,
) -> dict[str, Any]:
    """Analyze blast radius for asset failures."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_impact(
        assets=state.assets,
        dependencies=state.dependencies,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "asset_count": len(state.assets),
                "dependency_count": len(state.dependencies),
                "dependency_sample": state.dependencies[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_IMPACT,
            user_prompt=f"Analyze impact:\n{ctx}",
            schema=ImpactAnalysisOutput,
        )
        if llm_out.cascading_failures:  # type: ignore[union-attr]
            _rand = random.randint(1000, 9999)  # noqa: S311
            analyses.append(
                {
                    "analysis_id": f"llm-{_rand}",
                    "blast_radius": (
                        llm_out.blast_radius  # type: ignore[union-attr]
                    ),
                    "cascading_failures": (
                        llm_out.cascading_failures  # type: ignore[union-attr]
                    ),
                    "risk_score": (
                        llm_out.risk_score  # type: ignore[union-attr]
                    ),
                    "summary": (
                        llm_out.summary  # type: ignore[union-attr]
                    ),
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_impact",
            failures=len(
                llm_out.cascading_failures  # type: ignore[union-attr]
            ),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_impact",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_impact",
        (f"Analyzing {len(state.assets)} assets, {len(state.dependencies)} deps"),
        f"Produced {len(analyses)} impact analyses",
        start,
        "impact_analyzer",
    )

    return {
        "impact_analyses": analyses,
        "stage": SAGStage.ANALYZE_IMPACT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_impact",
    }


# ------------------------------------------------------------------
# Node: identify_critical_paths
# ------------------------------------------------------------------


async def identify_critical_paths(
    state: SecurityAssetGraphState,
) -> dict[str, Any]:
    """Identify critical dependency paths with single
    points of failure."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    paths: list[dict[str, Any]] = []

    raw_paths = await toolkit.identify_critical_paths(
        dependencies=state.dependencies,
        impact_analyses=state.impact_analyses,
    )

    for pat in raw_paths:
        # LLM validation per path
        try:
            ctx = _json.dumps(
                {
                    "path": pat,
                    "impact_analyses": (state.impact_analyses[:5]),
                },
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_CRITICAL_PATH,
                user_prompt=f"Validate critical path:\n{ctx}",
                schema=CriticalPathOutput,
            )
            pat = {
                "validated": (
                    llm_out.validated  # type: ignore[union-attr]
                ),
                "single_points_of_failure": (
                    llm_out.single_points_of_failure  # type: ignore[union-attr]
                ),
                "redundancy_score": (
                    llm_out.redundancy_score  # type: ignore[union-attr]
                ),
                "mitigation": (
                    llm_out.mitigation  # type: ignore[union-attr]
                ),
                "affected_services": (
                    llm_out.affected_services  # type: ignore[union-attr]
                ),
            }
            logger.info(
                "llm_enhanced",
                node="identify_critical_paths",
                validated=llm_out.validated,  # type: ignore[union-attr]
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="identify_critical_paths",
            )

        paths.append(pat)

    step = _step(
        state.reasoning_chain,
        "identify_critical_paths",
        (f"Analyzing {len(state.dependencies)} dependencies"),
        f"Found {len(paths)} critical paths",
        start,
        "path_finder",
    )

    return {
        "critical_paths": paths,
        "critical_path_count": len(paths),
        "stage": SAGStage.IDENTIFY_CRITICAL_PATHS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_critical_paths",
    }


# ------------------------------------------------------------------
# Node: score_risk
# ------------------------------------------------------------------


async def score_risk(
    state: SecurityAssetGraphState,
) -> dict[str, Any]:
    """Score risk for assets and critical paths."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    risk_scores = await toolkit.score_risk(
        critical_paths=state.critical_paths,
        impact_analyses=state.impact_analyses,
    )

    # Compute overall risk
    if risk_scores:
        scores = [item.get("risk_score", 0.0) for item in risk_scores]
        overall = sum(scores) / len(scores) if scores else 0.0
    else:
        overall = 0.0

    step = _step(
        state.reasoning_chain,
        "score_risk",
        (f"Scoring {len(state.critical_paths)} paths, {len(state.impact_analyses)} analyses"),
        (f"{len(risk_scores)} scores, overall={overall:.2f}"),
        start,
        "risk_scorer",
    )

    return {
        "risk_scores": risk_scores,
        "overall_risk": overall,
        "stage": SAGStage.SCORE_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "score_risk",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityAssetGraphState,
) -> dict[str, Any]:
    """Generate the final asset graph analysis report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_assets": state.total_assets,
        "total_dependencies": state.total_dependencies,
        "critical_path_count": state.critical_path_count,
        "overall_risk": state.overall_risk,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "environment": state.target_environment,
                "total_assets": state.total_assets,
                "total_dependencies": state.total_dependencies,
                "critical_paths": state.critical_paths[:5],
                "risk_scores": state.risk_scores[:5],
                "impact_analyses": state.impact_analyses[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate asset graph report:\n{ctx}",
            schema=AssetGraphReportOutput,
        )
        if isinstance(llm_out, AssetGraphReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "top_risks": llm_out.top_risks,
                    "recommendations": (llm_out.recommendations),
                    "resilience_rating": (llm_out.resilience_rating),
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Track metrics
    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "total_assets": state.total_assets,
            "total_dependencies": state.total_dependencies,
            "critical_path_count": state.critical_path_count,
            "overall_risk": state.overall_risk,
        },
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_assets} assets, {state.critical_path_count} critical paths"),
        (f"Report generated, risk={state.overall_risk:.2f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SAGStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
