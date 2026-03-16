"""OTel Semantic Conventions Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import ComplianceResult, ConventionRule, Violation
from .tools import OTelSemanticToolkit

logger = structlog.get_logger()


async def load_rules(
    state: dict[str, Any],
    toolkit: OTelSemanticToolkit,
) -> dict[str, Any]:
    """Load OTel semantic convention rules for all scopes."""
    logger.info("otel_semantic.node.load_rules")

    rules = toolkit.load_convention_rules(scope=None)

    reasoning = [
        f"Loaded {len(rules)} semantic convention rules across all scopes",
        "Scopes covered: resource, span, metric, log",
    ]

    return {
        "rules": [r.model_dump() for r in rules],
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def scan_services(
    state: dict[str, Any],
    toolkit: OTelSemanticToolkit,
) -> dict[str, Any]:
    """Scan all target services for semantic convention compliance."""
    logger.info("otel_semantic.node.scan_services")

    target_services = state.get("target_services", [])
    raw_rules = state.get("rules", [])
    rules = [ConventionRule(**r) if isinstance(r, dict) else r for r in raw_rules]

    results: list[dict[str, Any]] = []
    total_violations = 0

    for service in target_services:
        result = await toolkit.scan_service(service, rules)
        results.append(result.model_dump())
        total_violations += len(result.violations)

    reasoning = [
        f"Scanned {len(target_services)} service(s)",
        f"Found {total_violations} total violation(s)",
    ]

    return {
        "results": results,
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def analyze_violations(
    state: dict[str, Any],
    toolkit: OTelSemanticToolkit,
) -> dict[str, Any]:
    """Analyze violations across all scanned services and compute overall score."""
    logger.info("otel_semantic.node.analyze_violations")

    raw_results = state.get("results", [])
    results = [ComplianceResult(**r) if isinstance(r, dict) else r for r in raw_results]

    total_attrs = 0
    total_compliant = 0
    all_violations: list[Violation] = []

    for result in results:
        total_attrs += result.total_attributes
        total_compliant += result.compliant_count
        all_violations.extend(result.violations)

    overall_score = (total_compliant / total_attrs * 100.0) if total_attrs > 0 else 0.0

    # Group violations by severity
    errors = [v for v in all_violations if v.severity == "error"]
    warnings = [v for v in all_violations if v.severity == "warning"]
    infos = [v for v in all_violations if v.severity == "info"]

    reasoning = [
        f"Overall compliance score: {overall_score:.1f}%",
        f"Violations breakdown: {len(errors)} error(s), "
        f"{len(warnings)} warning(s), {len(infos)} info(s)",
    ]

    # LLM enhancement: deeper violation analysis
    try:
        from .prompts import SYSTEM_ANALYZE_VIOLATIONS, ViolationAnalysisResult

        violation_context = json.dumps(
            {
                "overall_score": round(overall_score, 2),
                "total_violations": len(all_violations),
                "errors": len(errors),
                "warnings": len(warnings),
                "infos": len(infos),
                "sample_violations": [
                    {"attribute": v.attribute, "severity": v.severity, "rule": v.rule_name}  # type: ignore[attr-defined]
                    for v in all_violations[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ViolationAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE_VIOLATIONS,
                user_prompt=f"Violation analysis context:\n{violation_context}",
                schema=ViolationAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="otel_semantic", node="analyze_violations")
        reasoning.append(f"LLM analysis: {llm_result.summary}")
        reasoning.extend(llm_result.common_patterns)
    except Exception:
        logger.debug("llm_fallback", agent="otel_semantic", node="analyze_violations")

    return {
        "overall_score": round(overall_score, 2),
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def generate_fixes(
    state: dict[str, Any],
    toolkit: OTelSemanticToolkit,
) -> dict[str, Any]:
    """Generate fix suggestions for all violations found."""
    logger.info("otel_semantic.node.generate_fixes")

    raw_results = state.get("results", [])
    results = [ComplianceResult(**r) if isinstance(r, dict) else r for r in raw_results]

    all_violations: list[Violation] = []
    for result in results:
        all_violations.extend(result.violations)

    fixes = toolkit.suggest_fixes(all_violations)

    reasoning = [
        f"Generated {len(fixes)} fix suggestion(s) for {len(all_violations)} violation(s)",
    ]

    if fixes:
        processor_fixes = [f for f in fixes if "processor_config" in f]
        sdk_fixes = [f for f in fixes if "sdk_config" in f]
        reasoning.append(
            f"Fix types: {len(processor_fixes)} processor config(s), {len(sdk_fixes)} SDK config(s)"
        )

    return {
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }
