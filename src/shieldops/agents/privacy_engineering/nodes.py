"""Privacy Engineering Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import AnonymizationFinding, DataPipeline
from .tools import PrivacyEngineeringToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def scan_pipelines(
    state: dict[str, Any],
    toolkit: PrivacyEngineeringToolkit,
) -> dict[str, Any]:
    """Discover data pipelines that process personal or sensitive data."""
    logger.info("privacy_engineering.node.scan_pipelines")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    session_start = time.time()

    pipeline_configs = state.get("pipelines", [])
    pipelines = await toolkit.scan_pipelines(
        tenant_id=tenant_id,
        pipeline_configs=pipeline_configs if pipeline_configs else None,
    )
    pipeline_dicts = [p.model_dump() for p in pipelines]

    return {
        "pipelines": pipeline_dicts,
        "session_start": session_start,
        "current_step": "scan_pipelines",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned {len(pipelines)} data pipelines for tenant {tenant_id}"],
    }


async def assess_anonymization(
    state: dict[str, Any],
    toolkit: PrivacyEngineeringToolkit,
) -> dict[str, Any]:
    """Assess anonymization quality across discovered pipelines."""
    logger.info("privacy_engineering.node.assess_anonymization")
    state = _to_dict(state)
    pipeline_dicts = state.get("pipelines", [])
    pipelines = [DataPipeline(**p) for p in pipeline_dicts]

    anonymization_configs = state.get("anonymization_configs", {})
    findings = await toolkit.assess_anonymization(
        pipelines=pipelines,
        anonymization_configs=anonymization_configs if anonymization_configs else None,
    )
    finding_dicts = [f.model_dump() for f in findings]

    # LLM enhancement: privacy analysis
    reasoning_note = f"Assessed anonymization for {len(findings)} pipeline findings"
    try:
        from .prompts import SYSTEM_ANALYZE, PrivacyAnalysisResult

        context = json.dumps(
            {
                "pipeline_count": len(pipelines),
                "findings": finding_dicts[:30],
                "techniques": list({f.technique_used.value for f in findings}),
                "risk_levels": list({f.risk_level.value for f in findings}),
            },
            default=str,
        )
        llm_result = cast(
            PrivacyAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Privacy engineering findings:\n{context}",
                schema=PrivacyAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="privacy_engineering",
            node="assess_anonymization",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="privacy_engineering",
            node="assess_anonymization",
        )

    return {
        "anonymization_findings": finding_dicts,
        "current_step": "assess_anonymization",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def validate_differential_privacy(
    state: dict[str, Any],
    toolkit: PrivacyEngineeringToolkit,
) -> dict[str, Any]:
    """Validate differential privacy parameters and update findings."""
    logger.info("privacy_engineering.node.validate_differential_privacy")
    state = _to_dict(state)
    finding_dicts = state.get("anonymization_findings", [])
    findings = [AnonymizationFinding(**f) for f in finding_dicts]

    validated = await toolkit.validate_differential_privacy(findings)
    validated_dicts = [f.model_dump() for f in validated]

    dp_count = sum(1 for f in validated if f.technique_used.value == "differential_privacy")
    non_compliant = sum(1 for f in validated if not f.compliant)

    return {
        "anonymization_findings": validated_dicts,
        "current_step": "validate_differential_privacy",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Validated {dp_count} differential privacy implementations; "
            f"{non_compliant} non-compliant findings"
        ],
    }


async def audit_pets(
    state: dict[str, Any],
    toolkit: PrivacyEngineeringToolkit,
) -> dict[str, Any]:
    """Audit Privacy Enhancing Technology implementations."""
    logger.info("privacy_engineering.node.audit_pets")
    state = _to_dict(state)
    pipeline_dicts = state.get("pipelines", [])
    pipelines = [DataPipeline(**p) for p in pipeline_dicts]

    pet_configs = state.get("pet_configs", {})
    implementations = await toolkit.audit_pet_implementations(
        pipelines=pipelines,
        pet_configs=pet_configs if pet_configs else None,
    )
    pet_dicts = [p.model_dump() for p in implementations]

    valid_count = sum(1 for p in implementations if p.validated)
    error_count = sum(len(p.validation_errors) for p in implementations)

    return {
        "pet_implementations": pet_dicts,
        "current_step": "audit_pets",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Audited {len(implementations)} PET implementations; "
            f"{valid_count} valid, {error_count} total errors"
        ],
    }


async def check_compliance(
    state: dict[str, Any],
    toolkit: PrivacyEngineeringToolkit,
) -> dict[str, Any]:
    """Map privacy findings to regulatory requirements."""
    logger.info("privacy_engineering.node.check_compliance")
    state = _to_dict(state)
    finding_dicts = state.get("anonymization_findings", [])
    pipeline_dicts = state.get("pipelines", [])

    findings = [AnonymizationFinding(**f) for f in finding_dicts]
    pipelines = [DataPipeline(**p) for p in pipeline_dicts]

    mappings = await toolkit.check_compliance(findings, pipelines)
    mapping_dicts = [m.model_dump() for m in mappings]

    gaps = [m for m in mappings if not m.compliant]
    reasoning_note = f"Mapped {len(mappings)} regulatory requirements; {len(gaps)} compliance gaps"

    # LLM enhancement: compliance gap analysis
    try:
        from .prompts import SYSTEM_ANALYZE, PrivacyAnalysisResult

        context = json.dumps(
            {
                "total_mappings": len(mapping_dicts),
                "gaps": [m.model_dump() for m in gaps[:20]],
                "regulations_affected": list({m.regulation for m in gaps}),
            },
            default=str,
        )
        llm_result = cast(
            PrivacyAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Privacy compliance mapping results:\n{context}",
                schema=PrivacyAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="privacy_engineering",
            node="check_compliance",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="privacy_engineering",
            node="check_compliance",
        )

    return {
        "compliance_mappings": mapping_dicts,
        "current_step": "check_compliance",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def report(
    state: dict[str, Any],
    toolkit: PrivacyEngineeringToolkit,
) -> dict[str, Any]:
    """Generate final privacy engineering report with stats."""
    logger.info("privacy_engineering.node.report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    pipelines = state.get("pipelines", [])
    findings = state.get("anonymization_findings", [])
    pets = state.get("pet_implementations", [])
    mappings = state.get("compliance_mappings", [])

    # Build stats
    risk_counts: dict[str, int] = {}
    technique_counts: dict[str, int] = {}
    for f in findings:
        risk = f.get("risk_level", "unknown")
        tech = f.get("technique_used", "unknown")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        technique_counts[tech] = technique_counts.get(tech, 0) + 1

    gaps = [m for m in mappings if not m.get("compliant", True)]
    total_mappings = len(mappings)
    compliance_ratio = (total_mappings - len(gaps)) / total_mappings if total_mappings else 1.0

    pet_valid = sum(1 for p in pets if p.get("validated", False))
    pet_errors = sum(len(p.get("validation_errors", [])) for p in pets)

    avg_re_id = 0.0
    if findings:
        avg_re_id = sum(f.get("re_identification_risk", 0.0) for f in findings) / len(findings)

    stats = {
        "pipelines_scanned": len(pipelines),
        "pii_pipelines": sum(1 for p in pipelines if p.get("contains_pii", False)),
        "findings_count": len(findings),
        "risk_breakdown": risk_counts,
        "technique_breakdown": technique_counts,
        "avg_re_identification_risk": round(avg_re_id, 4),
        "pet_implementations": len(pets),
        "pet_valid": pet_valid,
        "pet_errors": pet_errors,
        "regulatory_mappings": total_mappings,
        "compliance_gaps": len(gaps),
        "compliance_ratio": round(compliance_ratio, 3),
    }

    # LLM enhancement: executive report
    reasoning_note = (
        f"Report: {stats['pipelines_scanned']} pipelines, "
        f"{stats['findings_count']} findings, "
        f"{stats['compliance_gaps']} gaps, "
        f"compliance={stats['compliance_ratio']:.1%}"
    )
    try:
        from .prompts import SYSTEM_REPORT, PrivacyReportResult

        context = json.dumps(stats, default=str)
        llm_result = cast(
            PrivacyReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Privacy engineering stats:\n{context}",
                schema=PrivacyReportResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="privacy_engineering",
            node="report",
        )
        reasoning_note = f"{llm_result.executive_summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="privacy_engineering",
            node="report",
        )

    return {
        "stats": stats,
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }
