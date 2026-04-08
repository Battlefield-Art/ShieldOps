"""Model Security Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BackdoorIndicator,
    IntegrityAssessment,
    ModelRecord,
    ProvenanceRecord,
    SecurityStage,
)
from .tools import ModelSecurityToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: ModelSecurityToolkit | None = None


def _get_toolkit() -> ModelSecurityToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = ModelSecurityToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def scan_models(state: dict[str, Any], toolkit: ModelSecurityToolkit) -> dict[str, Any]:
    """Discover and catalog model artifacts from registries."""
    logger.info("model_security.node.scan_models")
    state = _to_dict(state)

    target_models = state.get("target_models", [])
    models = await toolkit.scan_models(target_models or None)
    models_data = [m.model_dump() for m in models]

    return {
        "stage": SecurityStage.VERIFY_PROVENANCE.value,
        "models": models_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned {len(models)} model artifacts from registries"],
    }


async def verify_provenance(state: dict[str, Any], toolkit: ModelSecurityToolkit) -> dict[str, Any]:
    """Verify provenance and supply chain integrity for discovered models."""
    logger.info("model_security.node.verify_provenance")
    state = _to_dict(state)

    raw_models = state.get("models", [])
    models = [ModelRecord(**m) for m in raw_models]

    provenance = await toolkit.verify_provenance(models)
    provenance_data = [p.model_dump() for p in provenance]

    unsigned_count = sum(1 for p in provenance if not p.signature_valid)
    unverified_count = sum(1 for p in provenance if not p.supply_chain_verified)

    return {
        "stage": SecurityStage.DETECT_BACKDOORS.value,
        "provenance_records": provenance_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Verified provenance for {len(provenance)} models — "
            f"{unsigned_count} unsigned, {unverified_count} unverified supply chain"
        ],
    }


async def detect_backdoors(state: dict[str, Any], toolkit: ModelSecurityToolkit) -> dict[str, Any]:
    """Detect potential backdoor indicators in model artifacts."""
    logger.info("model_security.node.detect_backdoors")
    state = _to_dict(state)

    raw_models = state.get("models", [])
    models = [ModelRecord(**m) for m in raw_models]

    indicators = await toolkit.detect_backdoors(models)
    indicators_data = [i.model_dump() for i in indicators]

    reasoning_note = f"Detected {len(indicators)} backdoor indicators across {len(models)} models"

    # LLM enhancement: deeper analysis of scan findings
    try:
        from .prompts import SYSTEM_SCAN, ModelScanAnalysis

        scan_context = json.dumps(
            {
                "models_scanned": len(models),
                "indicators_found": len(indicators),
                "models_summary": [
                    {"id": m.model_id, "framework": m.framework, "registry": m.source_registry}
                    for m in models[:10]
                ],
                "indicators_summary": [
                    {
                        "id": i.indicator_id,
                        "type": i.indicator_type,
                        "confidence": i.confidence,
                        "threat_level": i.threat_level,
                    }
                    for i in indicators[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ModelScanAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_SCAN,
                user_prompt=f"Model security scan context:\n{scan_context}",
                schema=ModelScanAnalysis,
            ),
        )
        logger.info("llm_enhanced", agent="model_security", node="detect_backdoors")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="model_security", node="detect_backdoors")

    return {
        "stage": SecurityStage.ASSESS_INTEGRITY.value,
        "backdoor_indicators": indicators_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_integrity(state: dict[str, Any], toolkit: ModelSecurityToolkit) -> dict[str, Any]:
    """Assess integrity of each model combining provenance and backdoor data."""
    logger.info("model_security.node.assess_integrity")
    state = _to_dict(state)

    raw_models = state.get("models", [])
    models = [ModelRecord(**m) for m in raw_models]

    raw_provenance = state.get("provenance_records", [])
    provenance = [ProvenanceRecord(**p) for p in raw_provenance]

    raw_indicators = state.get("backdoor_indicators", [])
    indicators = [BackdoorIndicator(**i) for i in raw_indicators]

    assessments = await toolkit.assess_integrity(models, provenance, indicators)
    assessments_data = [a.model_dump() for a in assessments]

    compromised = sum(1 for a in assessments if a.verdict.value == "compromised")
    suspicious = sum(1 for a in assessments if a.verdict.value == "suspicious")

    return {
        "stage": SecurityStage.EVALUATE_RISKS.value,
        "integrity_assessments": assessments_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Assessed integrity for {len(assessments)} models — "
            f"{compromised} compromised, {suspicious} suspicious"
        ],
    }


async def evaluate_risks(state: dict[str, Any], toolkit: ModelSecurityToolkit) -> dict[str, Any]:
    """Evaluate overall risk and generate final report."""
    logger.info("model_security.node.evaluate_risks")
    state = _to_dict(state)

    raw_assessments = state.get("integrity_assessments", [])
    assessments = [IntegrityAssessment(**a) for a in raw_assessments]

    raw_indicators = state.get("backdoor_indicators", [])
    indicators = [BackdoorIndicator(**i) for i in raw_indicators]

    raw_provenance = state.get("provenance_records", [])
    provenance = [ProvenanceRecord(**p) for p in raw_provenance]

    overall_risk, overall_verdict, risk_factors = toolkit.evaluate_risks(
        assessments, indicators, provenance
    )

    # LLM enhancement: generate report summary
    report_summary = (
        f"Model security scan complete. Overall risk: {overall_risk}/100 "
        f"({overall_verdict.value}). {len(risk_factors)} risk factor(s) identified."
    )

    try:
        from .prompts import SYSTEM_REPORT, ModelSecurityReport

        report_context = json.dumps(
            {
                "overall_risk": overall_risk,
                "overall_verdict": overall_verdict.value,
                "risk_factors": risk_factors[:10],
                "assessment_count": len(assessments),
                "indicator_count": len(indicators),
            },
            default=str,
        )
        llm_result = cast(
            ModelSecurityReport,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Model security report context:\n{report_context}",
                schema=ModelSecurityReport,
            ),
        )
        logger.info("llm_enhanced", agent="model_security", node="evaluate_risks")
        report_summary = llm_result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="model_security", node="evaluate_risks")

    return {
        "stage": SecurityStage.REPORT.value,
        "overall_risk_score": overall_risk,
        "overall_verdict": overall_verdict.value,
        "risk_factors": risk_factors,
        "report_summary": report_summary,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Risk evaluation complete — overall risk: {overall_risk}, "
            f"verdict: {overall_verdict.value}, {len(risk_factors)} risk factors"
        ],
    }
