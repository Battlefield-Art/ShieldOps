"""Data Resilience Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DataAsset,
    ProtectionAssessment,
    ProtectionLevel,
    ReasoningStep,
    ResilienceStage,
)
from .tools import DataResilienceToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# -----------------------------------------------------------
# Node 1: Inventory Data Assets
# -----------------------------------------------------------


async def inventory_data_assets(
    state: dict[str, Any],
    toolkit: DataResilienceToolkit,
) -> dict[str, Any]:
    """Discover data assets across cloud providers."""
    logger.info("data_resilience.node.inventory")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    assets = await toolkit.inventory_data_assets(tenant_id)
    assets_data = [a.model_dump() for a in assets]

    note = f"Inventoried {len(assets)} data assets for tenant '{tenant_id}'"

    try:
        from .prompts import (
            SYSTEM_INVENTORY,
            InventoryAnalysisResult,
        )

        ctx = json.dumps(
            {
                "total_assets": len(assets),
                "assets": [
                    {
                        "name": a.name,
                        "type": a.asset_type.value,
                        "provider": a.cloud_provider,
                        "size_gb": a.size_gb,
                        "classification": (a.classification),
                    }
                    for a in assets[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            InventoryAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_INVENTORY,
                user_prompt=(f"Data asset inventory:\n{ctx}"),
                schema=InventoryAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_resilience",
            node="inventory",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_resilience",
            node="inventory",
        )

    return {
        "stage": ResilienceStage.ASSESS_PROTECTION.value,
        "assets_inventoried": assets_data,
        "total_assets": len(assets),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="inventory_data_assets",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# -----------------------------------------------------------
# Node 2: Assess Protection
# -----------------------------------------------------------


async def assess_protection(
    state: dict[str, Any],
    toolkit: DataResilienceToolkit,
) -> dict[str, Any]:
    """Assess protection levels for inventoried assets."""
    logger.info("data_resilience.node.assess_protection")
    state = _to_dict(state)

    raw_assets = state.get("assets_inventoried", [])
    assets = [DataAsset(**a) for a in raw_assets]

    assessments = await toolkit.assess_protection(assets)
    assessments_data = [a.model_dump() for a in assessments]

    unprotected = sum(1 for a in assessments if a.protection_level == ProtectionLevel.UNPROTECTED)
    note = f"Assessed {len(assessments)} assets, {unprotected} unprotected"

    try:
        from .prompts import (
            SYSTEM_PROTECTION,
            ProtectionInsight,
        )

        ctx = json.dumps(
            {
                "total": len(assessments),
                "unprotected": unprotected,
                "assessments": [
                    {
                        "asset_id": a.asset_id,
                        "level": a.protection_level.value,
                        "gaps": a.gaps,
                        "risk": a.risk_score,
                    }
                    for a in assessments[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ProtectionInsight,
            await llm_structured(
                system_prompt=SYSTEM_PROTECTION,
                user_prompt=(f"Protection assessments:\n{ctx}"),
                schema=ProtectionInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_resilience",
            node="assess_protection",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_resilience",
            node="assess_protection",
        )

    return {
        "stage": ResilienceStage.DETECT_ANOMALIES.value,
        "protection_assessments": assessments_data,
        "unprotected_count": unprotected,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="assess_protection",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# -----------------------------------------------------------
# Node 3: Detect Anomalies
# -----------------------------------------------------------


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: DataResilienceToolkit,
) -> dict[str, Any]:
    """Detect anomalies and ransomware indicators."""
    logger.info("data_resilience.node.detect_anomalies")
    state = _to_dict(state)

    raw_assets = state.get("assets_inventoried", [])
    assets = [DataAsset(**a) for a in raw_assets]

    anomalies = await toolkit.detect_anomalies(assets)
    anomalies_data = [a.model_dump() for a in anomalies]

    ransomware_count = sum(1 for a in anomalies if a.is_ransomware_indicator)
    note = f"Detected {len(anomalies)} anomalies ({ransomware_count} ransomware indicators)"

    try:
        from .prompts import (
            SYSTEM_ANOMALY,
            AnomalyAssessment,
        )

        ctx = json.dumps(
            {
                "anomaly_count": len(anomalies),
                "ransomware_count": ransomware_count,
                "anomalies": [
                    {
                        "asset_id": a.asset_id,
                        "type": a.anomaly_type,
                        "severity": a.severity,
                        "description": a.description,
                        "ransomware": (a.is_ransomware_indicator),
                    }
                    for a in anomalies[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            AnomalyAssessment,
            await llm_structured(
                system_prompt=SYSTEM_ANOMALY,
                user_prompt=(f"Anomaly analysis:\n{ctx}"),
                schema=AnomalyAssessment,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_resilience",
            node="detect_anomalies",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_resilience",
            node="detect_anomalies",
        )

    return {
        "stage": (ResilienceStage.ENFORCE_IMMUTABILITY.value),
        "anomalies_detected": anomalies_data,
        "anomaly_count": len(anomalies),
        "ransomware_indicators": ransomware_count,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="detect_anomalies",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# -----------------------------------------------------------
# Node 4: Enforce Immutability
# -----------------------------------------------------------


async def enforce_immutability(
    state: dict[str, Any],
    toolkit: DataResilienceToolkit,
) -> dict[str, Any]:
    """Enforce immutability controls on unprotected assets."""
    logger.info("data_resilience.node.enforce_immutability")
    state = _to_dict(state)

    raw_assets = state.get("assets_inventoried", [])
    raw_assessments = state.get("protection_assessments", [])
    assets = [DataAsset(**a) for a in raw_assets]
    assessments = [ProtectionAssessment(**a) for a in raw_assessments]

    enforcements = await toolkit.enforce_immutability(assets, assessments)
    enforcements_data = [e.model_dump() for e in enforcements]

    note = f"Applied {len(enforcements)} immutability enforcements"

    try:
        from .prompts import (
            SYSTEM_ENFORCEMENT,
            EnforcementReview,
        )

        ctx = json.dumps(
            {
                "enforcement_count": len(enforcements),
                "enforcements": [
                    {
                        "asset_id": e.asset_id,
                        "action": e.action,
                        "mechanism": e.mechanism,
                        "retention_days": (e.retention_days),
                    }
                    for e in enforcements[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            EnforcementReview,
            await llm_structured(
                system_prompt=SYSTEM_ENFORCEMENT,
                user_prompt=(f"Enforcement actions:\n{ctx}"),
                schema=EnforcementReview,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_resilience",
            node="enforce_immutability",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_resilience",
            node="enforce_immutability",
        )

    return {
        "stage": (ResilienceStage.VALIDATE_RECOVERY.value),
        "enforcements_applied": enforcements_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="enforce_immutability",
                detail=note,
                confidence=0.87,
            ).model_dump()
        ],
    }


# -----------------------------------------------------------
# Node 5: Validate Recovery
# -----------------------------------------------------------


async def validate_recovery(
    state: dict[str, Any],
    toolkit: DataResilienceToolkit,
) -> dict[str, Any]:
    """Validate recovery capabilities via test restores."""
    logger.info("data_resilience.node.validate_recovery")
    state = _to_dict(state)

    raw_assets = state.get("assets_inventoried", [])
    raw_assessments = state.get("protection_assessments", [])
    assets = [DataAsset(**a) for a in raw_assets]
    assessments = [ProtectionAssessment(**a) for a in raw_assessments]

    validations = await toolkit.validate_recovery(assets, assessments)
    validations_data = [v.model_dump() for v in validations]

    passed = sum(1 for v in validations if v.status == "passed")
    failed = sum(1 for v in validations if v.status == "failed")
    note = f"Recovery validated: {passed} passed, {failed} failed out of {len(validations)}"

    try:
        from .prompts import (
            SYSTEM_RECOVERY,
            RecoveryInsight,
        )

        ctx = json.dumps(
            {
                "total_tests": len(validations),
                "passed": passed,
                "failed": failed,
                "validations": [
                    {
                        "asset_id": v.asset_id,
                        "type": v.test_type,
                        "rto_s": v.recovery_time_seconds,
                        "rpo_h": (v.recovery_point_age_hours),
                        "integrity": (v.data_integrity_verified),
                        "status": v.status,
                    }
                    for v in validations[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RecoveryInsight,
            await llm_structured(
                system_prompt=SYSTEM_RECOVERY,
                user_prompt=(f"Recovery validations:\n{ctx}"),
                schema=RecoveryInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_resilience",
            node="validate_recovery",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_resilience",
            node="validate_recovery",
        )

    return {
        "stage": ResilienceStage.REPORT.value,
        "recovery_validated": validations_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="validate_recovery",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# -----------------------------------------------------------
# Node 6: Generate Report
# -----------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: DataResilienceToolkit,
) -> dict[str, Any]:
    """Compile the final data resilience report."""
    logger.info("data_resilience.node.generate_report")
    state = _to_dict(state)

    total = state.get("total_assets", 0)
    unprotected = state.get("unprotected_count", 0)
    anomaly_ct = state.get("anomaly_count", 0)
    ransomware_ct = state.get("ransomware_indicators", 0)
    enforcements = state.get("enforcements_applied", [])
    validations = state.get("recovery_validated", [])

    passed = sum(1 for v in validations if isinstance(v, dict) and v.get("status") == "passed")
    failed = sum(1 for v in validations if isinstance(v, dict) and v.get("status") == "failed")

    # Calculate resilience score (0-100)
    if total == 0:
        score = 0.0
    else:
        protection_pct = (total - unprotected) / total * 40
        anomaly_penalty = min(20, anomaly_ct * 5)
        ransomware_penalty = min(20, ransomware_ct * 10)
        recovery_bonus = (passed / max(1, len(validations))) * 30
        enforcement_bonus = min(10, len(enforcements) * 2)
        score = round(
            max(
                0.0,
                min(
                    100.0,
                    protection_pct
                    - anomaly_penalty
                    - ransomware_penalty
                    + recovery_bonus
                    + enforcement_bonus,
                ),
            ),
            1,
        )

    # Build recommendations
    recommendations: list[str] = []
    if unprotected > 0:
        recommendations.append(f"URGENT: {unprotected} assets lack immutability protection")
    if ransomware_ct > 0:
        recommendations.append(
            f"CRITICAL: {ransomware_ct} ransomware indicators require investigation"
        )
    if failed > 0:
        recommendations.append(f"WARNING: {failed} recovery tests failed — remediate backup gaps")
    if anomaly_ct > 0:
        recommendations.append(f"Review {anomaly_ct} data anomalies for tampering indicators")
    recommendations.append("Schedule quarterly recovery validation drills for all critical assets")

    lines = [
        "# Data Resilience Report",
        "",
        f"**Resilience Score:** {score}/100",
        f"**Total Assets:** {total}",
        f"**Unprotected:** {unprotected}",
        f"**Anomalies:** {anomaly_ct} ({ransomware_ct} ransomware)",
        f"**Enforcements Applied:** {len(enforcements)}",
        f"**Recovery Tests:** {passed} passed, {failed} failed",
        "",
        "## Recommendations",
    ]
    for i, rec in enumerate(recommendations, 1):
        lines.append(f"{i}. {rec}")

    report = "\n".join(lines)

    return {
        "stage": ResilienceStage.REPORT.value,
        "report": report,
        "resilience_score": score,
        "recommendations": recommendations,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="generate_report",
                detail=(f"Final report compiled. Resilience score: {score}/100"),
                confidence=0.95,
            ).model_dump()
        ],
    }
