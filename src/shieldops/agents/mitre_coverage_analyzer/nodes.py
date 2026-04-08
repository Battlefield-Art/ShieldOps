"""MITRE Coverage Analyzer Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    CoverageGap,
    CoverageMatrix,
    CoverageStage,
    DetectionRule,
    MITREMapping,
)
from .prompts import (
    SYSTEM_IDENTIFY_GAPS,
    SYSTEM_MAP_MITRE,
    SYSTEM_RECOMMEND_RULES,
    SYSTEM_REPORT,
    CoverageReportOutput,
    GapAnalysisOutput,
    MappingAnalysisOutput,
    RuleRecommendationOutput,
)
from .tools import MITRECoverageAnalyzerToolkit

logger = structlog.get_logger()

_toolkit: MITRECoverageAnalyzerToolkit | None = None


def _get_toolkit() -> MITRECoverageAnalyzerToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = MITRECoverageAnalyzerToolkit()
    return _toolkit


async def inventory_detections(
    state: dict[str, Any],
    toolkit: MITRECoverageAnalyzerToolkit,
) -> dict[str, Any]:
    """Collect detection rules from SIEM/EDR sources."""
    logger.info("mitre_coverage.node.inventory_detections")

    tenant_id = state.get("tenant_id", "")
    rules = await toolkit.inventory_detections(tenant_id)
    rules_data = [r.model_dump() for r in rules]

    return {
        "current_stage": CoverageStage.INVENTORY_DETECTIONS.value,
        "detections_inventoried": rules_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Inventoried {len(rules)} detection rules"],
    }


async def map_to_mitre(
    state: dict[str, Any],
    toolkit: MITRECoverageAnalyzerToolkit,
) -> dict[str, Any]:
    """Map detection rules to MITRE ATT&CK techniques."""
    logger.info("mitre_coverage.node.map_to_mitre")

    raw_rules = state.get("detections_inventoried", [])
    rules = [DetectionRule(**r) for r in raw_rules]
    mappings = await toolkit.map_to_mitre(rules)

    # LLM enhancement for unmapped rules
    for i, mapping in enumerate(mappings):
        if mapping.technique_id == "unknown":
            rule = rules[i] if i < len(rules) else None
            if rule is None:
                continue
            try:
                result = await llm_structured(
                    system_prompt=SYSTEM_MAP_MITRE,
                    user_prompt=(
                        f"Rule: {rule.name}\n"
                        f"Query: {rule.query}\n"
                        f"Source: {rule.source}\n"
                        f"Data sources: "
                        f"{', '.join(rule.data_sources)}"
                    ),
                    output_schema=MappingAnalysisOutput,
                )
                mapping.technique_id = result.technique_id
                mapping.technique_name = result.technique_name
                mapping.confidence = result.confidence
            except Exception:
                logger.debug(
                    "mitre_coverage.llm_map_fallback",
                    rule_id=rule.id,
                )

    mappings_data = [m.model_dump() for m in mappings]

    return {
        "current_stage": CoverageStage.MAP_TO_MITRE.value,
        "mappings": mappings_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Mapped {len(mappings)} rules to MITRE ATT&CK techniques"],
    }


async def calculate_coverage(
    state: dict[str, Any],
    toolkit: MITRECoverageAnalyzerToolkit,
) -> dict[str, Any]:
    """Calculate coverage matrix per tactic/technique."""
    logger.info("mitre_coverage.node.calculate_coverage")

    raw_mappings = state.get("mappings", [])
    mappings = [MITREMapping(**m) for m in raw_mappings]
    matrix = await toolkit.calculate_coverage(mappings)
    matrix_data = [e.model_dump() for e in matrix]

    total = len(matrix)
    covered = sum(1 for e in matrix if e.coverage != "none")
    coverage_pct = round(covered / total * 100, 1) if total else 0.0
    tactics = len({e.tactic for e in matrix if e.coverage != "none"})

    return {
        "current_stage": (CoverageStage.CALCULATE_COVERAGE.value),
        "coverage_matrix": matrix_data,
        "overall_coverage_pct": coverage_pct,
        "tactics_covered": tactics,
        "techniques_total": total,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Coverage: {coverage_pct}% ({covered}/{total} techniques)"],
    }


async def identify_gaps(
    state: dict[str, Any],
    toolkit: MITRECoverageAnalyzerToolkit,
) -> dict[str, Any]:
    """Identify uncovered MITRE techniques."""
    logger.info("mitre_coverage.node.identify_gaps")

    raw_matrix = state.get("coverage_matrix", [])
    matrix = [CoverageMatrix(**e) for e in raw_matrix]
    gaps = await toolkit.identify_gaps(matrix)

    # LLM enhancement for gap prioritization
    try:
        context = json.dumps(
            [
                {
                    "id": g.technique_id,
                    "name": g.technique_name,
                    "tactic": g.tactic,
                    "risk": g.risk_score,
                }
                for g in gaps[:15]
            ],
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY_GAPS,
            user_prompt=(
                f"Coverage gaps:\n{context}\n\n"
                f"Overall coverage: "
                f"{state.get('overall_coverage_pct', 0)}%"
            ),
            output_schema=GapAnalysisOutput,
        )
        reasoning = f"LLM gap analysis: {result.risk_rationale}"
    except Exception:
        logger.debug("mitre_coverage.llm_gaps_fallback")
        reasoning = f"Identified {len(gaps)} coverage gaps"

    gaps_data = [g.model_dump() for g in gaps]

    return {
        "current_stage": (CoverageStage.IDENTIFY_GAPS.value),
        "gaps": gaps_data,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def recommend_rules(
    state: dict[str, Any],
    toolkit: MITRECoverageAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate detection rule recommendations."""
    logger.info("mitre_coverage.node.recommend_rules")

    raw_gaps = state.get("gaps", [])
    gaps = [CoverageGap(**g) for g in raw_gaps]
    recs = await toolkit.recommend_rules(gaps)

    # LLM enhancement for rule quality
    for rec in recs:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_RECOMMEND_RULES,
                user_prompt=(
                    f"Technique: {rec.gap_technique_id} "
                    f"- {rec.gap_technique_name}\n"
                    f"Generate a detection rule."
                ),
                output_schema=RuleRecommendationOutput,
            )
            rec.recommended_rule_name = result.rule_name
            rec.recommended_query = result.query_logic
            rec.data_sources_needed = result.data_sources
            rec.estimated_effort = result.effort
            rec.priority = result.priority
        except Exception:
            logger.debug(
                "mitre_coverage.llm_rule_fallback",
                technique=rec.gap_technique_id,
            )

    recs_data = [r.model_dump() for r in recs]

    return {
        "current_stage": (CoverageStage.RECOMMEND_RULES.value),
        "recommendations": recs_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Generated {len(recs)} rule recommendations"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: MITRECoverageAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate final MITRE coverage report."""
    logger.info("mitre_coverage.node.generate_report")

    try:
        context = json.dumps(
            {
                "overall_coverage_pct": state.get(
                    "overall_coverage_pct",
                    0,
                ),
                "tactics_covered": state.get(
                    "tactics_covered",
                    0,
                ),
                "techniques_total": state.get(
                    "techniques_total",
                    0,
                ),
                "gap_count": len(state.get("gaps", [])),
                "recommendation_count": len(
                    state.get("recommendations", []),
                ),
                "top_gaps": state.get("gaps", [])[:5],
            },
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"MITRE coverage analysis:\n{context}"),
            output_schema=CoverageReportOutput,
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("mitre_coverage.llm_report_fallback")
        pct = state.get("overall_coverage_pct", 0)
        gaps = len(state.get("gaps", []))
        summary = f"MITRE ATT&CK coverage at {pct}%. {gaps} gaps identified."

    return {
        "current_stage": CoverageStage.REPORT.value,
        "reasoning_chain": state.get("reasoning_chain", []) + [f"Report: {summary[:120]}"],
    }
