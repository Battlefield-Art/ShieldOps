"""Credential Exposure Scanner Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CESStage,
    CredentialClassification,
    DetectedCredential,
    ExposureAssessment,
    ReasoningStep,
    ScanSource,
)
from .tools import CredentialExposureScannerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Scan Sources
# ------------------------------------------------------------------


async def scan_sources(
    state: dict[str, Any],
    toolkit: CredentialExposureScannerToolkit,
) -> dict[str, Any]:
    """Scan configured sources for credential exposure."""
    logger.info("ces.node.scan_sources")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    sources = await toolkit.scan_sources(tenant_id)
    data = [s.model_dump() for s in sources]

    note = f"Scanned {len(sources)} sources"

    return {
        "stage": CESStage.DETECT_CREDENTIALS.value,
        "scan_sources": data,
        "total_sources_scanned": len(sources),
        "current_step": "scan_sources",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="scan_sources",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Detect Credentials
# ------------------------------------------------------------------


async def detect_credentials(
    state: dict[str, Any],
    toolkit: CredentialExposureScannerToolkit,
) -> dict[str, Any]:
    """Detect credentials across scanned sources."""
    logger.info("ces.node.detect_credentials")
    state = _to_dict(state)

    sources = [ScanSource(**s) for s in state.get("scan_sources", [])]
    credentials = await toolkit.detect_credentials(sources)
    data = [c.model_dump() for c in credentials]

    note = f"Detected {len(credentials)} credentials across {len(sources)} sources"

    try:
        from .prompts import SYSTEM_SCAN, ScanInsight

        ctx = json.dumps(
            {
                "credentials": [
                    {
                        "source": c.source_id,
                        "entropy": c.entropy_score,
                        "file": c.file_path,
                    }
                    for c in credentials[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ScanInsight,
            await llm_structured(
                system_prompt=SYSTEM_SCAN,
                user_prompt=f"Credential detections:\n{ctx}",
                schema=ScanInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ces",
            node="detect_credentials",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ces",
            node="detect_credentials",
        )

    return {
        "stage": CESStage.CLASSIFY_TYPE.value,
        "detected_credentials": data,
        "credentials_detected": len(credentials),
        "current_step": "detect_credentials",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_credentials",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Classify Type
# ------------------------------------------------------------------


async def classify_type(
    state: dict[str, Any],
    toolkit: CredentialExposureScannerToolkit,
) -> dict[str, Any]:
    """Classify detected credentials by type."""
    logger.info("ces.node.classify_type")
    state = _to_dict(state)

    credentials = [DetectedCredential(**c) for c in state.get("detected_credentials", [])]
    classifications = await toolkit.classify_type(credentials)
    data = [c.model_dump() for c in classifications]

    active = sum(1 for c in classifications if c.is_active)
    note = f"Classified {len(classifications)} credentials, {active} active"

    return {
        "stage": CESStage.ASSESS_EXPOSURE.value,
        "classifications": data,
        "current_step": "classify_type",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="classify_type",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Assess Exposure
# ------------------------------------------------------------------


async def assess_exposure(
    state: dict[str, Any],
    toolkit: CredentialExposureScannerToolkit,
) -> dict[str, Any]:
    """Assess exposure severity for credentials."""
    logger.info("ces.node.assess_exposure")
    state = _to_dict(state)

    classifications = [CredentialClassification(**c) for c in state.get("classifications", [])]
    assessments = await toolkit.assess_exposure(classifications)
    data = [a.model_dump() for a in assessments]

    critical = sum(1 for a in assessments if a.severity.value == "critical")
    note = f"Assessed {len(assessments)} exposures, {critical} critical"

    return {
        "stage": CESStage.TRIGGER_ROTATION.value,
        "exposure_assessments": data,
        "current_step": "assess_exposure",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_exposure",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Trigger Rotation
# ------------------------------------------------------------------


async def trigger_rotation(
    state: dict[str, Any],
    toolkit: CredentialExposureScannerToolkit,
) -> dict[str, Any]:
    """Trigger credential rotation for exposed credentials."""
    logger.info("ces.node.trigger_rotation")
    state = _to_dict(state)

    assessments = [ExposureAssessment(**a) for a in state.get("exposure_assessments", [])]
    classifications = [CredentialClassification(**c) for c in state.get("classifications", [])]
    actions = await toolkit.trigger_rotation(assessments, classifications)
    data = [a.model_dump() for a in actions]

    rotated = sum(1 for a in actions if a.status == "completed")
    note = f"Triggered {rotated}/{len(actions)} credential rotations"

    return {
        "stage": CESStage.REPORT.value,
        "rotation_actions": data,
        "current_step": "trigger_rotation",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="trigger_rotation",
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
    toolkit: CredentialExposureScannerToolkit,
) -> dict[str, Any]:
    """Compile the final credential exposure report."""
    logger.info("ces.node.report")
    state = _to_dict(state)

    total_sources = state.get("total_sources_scanned", 0)
    cred_count = state.get("credentials_detected", 0)
    rotation_count = len(state.get("rotation_actions", []))
    rotated = sum(1 for a in state.get("rotation_actions", []) if a.get("status") == "completed")

    lines = [
        "# Credential Exposure Scan Report",
        "",
        f"**Sources scanned:** {total_sources}",
        f"**Credentials detected:** {cred_count}",
        f"**Rotation actions:** {rotation_count}",
        f"**Rotations completed:** {rotated}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "sources": total_sources,
                "credentials": cred_count,
                "rotations": rotation_count,
                "completed": rotated,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Credential exposure report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ces",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ces",
            node="report",
        )

    return {
        "stage": CESStage.REPORT.value,
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
