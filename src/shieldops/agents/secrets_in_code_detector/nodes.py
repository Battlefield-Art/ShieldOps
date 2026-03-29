"""Secrets in Code Detector Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import DetectionStage, SecretFinding
from .tools import SecretsInCodeDetectorToolkit

logger = structlog.get_logger()

_toolkit: SecretsInCodeDetectorToolkit | None = None


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_repositories(
    state: dict[str, Any],
    toolkit: SecretsInCodeDetectorToolkit,
) -> dict[str, Any]:
    """Discover repositories to scan."""
    logger.info("secrets_detector.node.discover_repos")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    targets = state.get("scan_targets", [])
    session_start = time.time()

    repos = await toolkit.discover_repositories(
        tenant_id=tenant_id,
        targets=targets,
    )
    repo_dicts = [r.model_dump() for r in repos]

    return {
        "repositories": repo_dicts,
        "total_repos": len(repos),
        "stage": DetectionStage.DISCOVER_REPOSITORIES.value,
        "session_start": session_start,
        "current_step": "discover_repositories",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(repos)} repositories"],
    }


async def scan_patterns(
    state: dict[str, Any],
    toolkit: SecretsInCodeDetectorToolkit,
) -> dict[str, Any]:
    """Scan for secret patterns."""
    logger.info("secrets_detector.node.scan_patterns")
    state = _to_dict(state)
    targets = state.get("scan_targets", [])
    raw_repos = state.get("repositories", [])
    from .models import RepositoryScan

    repos = [RepositoryScan(**r) if isinstance(r, dict) else r for r in raw_repos]

    findings = await toolkit.scan_patterns(repos, targets)
    finding_dicts = [f.model_dump() for f in findings]

    return {
        "raw_findings": finding_dicts,
        "stage": DetectionStage.SCAN_PATTERNS.value,
        "current_step": "scan_patterns",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Pattern scan: {len(findings)} secrets detected"],
    }


async def verify_secrets(
    state: dict[str, Any],
    toolkit: SecretsInCodeDetectorToolkit,
) -> dict[str, Any]:
    """Verify detected secrets."""
    logger.info("secrets_detector.node.verify")
    state = _to_dict(state)
    raw = state.get("raw_findings", [])
    findings = [SecretFinding(**f) if isinstance(f, dict) else f for f in raw]

    verified = await toolkit.verify_secrets(findings)
    verified_dicts = [f.model_dump() for f in verified]
    active_count = sum(1 for f in verified if f.is_active)
    reasoning = f"Verified {len(verified)} secrets: {active_count} active"

    try:
        from .prompts import (
            SYSTEM_SECRET_VERIFICATION,
            SecretVerificationOutput,
        )

        context = json.dumps(
            {"findings": verified_dicts[:15]},
            default=str,
        )
        llm_result = cast(
            SecretVerificationOutput,
            await llm_structured(
                system_prompt=SYSTEM_SECRET_VERIFICATION,
                user_prompt=f"Secret findings:\n{context}",
                schema=SecretVerificationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="secrets_detector",
            node="verify",
        )
        reasoning = llm_result.summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="secrets_detector",
            node="verify",
        )

    return {
        "verified_findings": verified_dicts,
        "active_secrets": active_count,
        "stage": DetectionStage.VERIFY_SECRETS.value,
        "current_step": "verify_secrets",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def assess_exposure(
    state: dict[str, Any],
    toolkit: SecretsInCodeDetectorToolkit,
) -> dict[str, Any]:
    """Assess exposure risk."""
    logger.info("secrets_detector.node.assess_exposure")
    state = _to_dict(state)
    raw = state.get("verified_findings", [])
    findings = [SecretFinding(**f) if isinstance(f, dict) else f for f in raw]

    assessed = await toolkit.assess_exposure(findings)
    assessed_dicts = [f.model_dump() for f in assessed]
    reasoning = f"Exposure assessed for {len(assessed)} secrets"

    try:
        from .prompts import (
            SYSTEM_EXPOSURE_ANALYSIS,
            ExposureAnalysisOutput,
        )

        context = json.dumps(
            {"findings": assessed_dicts[:15]},
            default=str,
        )
        llm_result = cast(
            ExposureAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_EXPOSURE_ANALYSIS,
                user_prompt=f"Exposure data:\n{context}",
                schema=ExposureAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="secrets_detector",
            node="assess_exposure",
        )
        reasoning = f"{llm_result.summary} {llm_result.risk_narrative[:80]}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="secrets_detector",
            node="assess_exposure",
        )

    return {
        "exposure_assessments": assessed_dicts,
        "stage": DetectionStage.ASSESS_EXPOSURE.value,
        "current_step": "assess_exposure",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def prioritize_findings(
    state: dict[str, Any],
    toolkit: SecretsInCodeDetectorToolkit,
) -> dict[str, Any]:
    """Prioritize secret findings."""
    logger.info("secrets_detector.node.prioritize")
    state = _to_dict(state)
    raw = state.get("exposure_assessments", [])
    findings = [SecretFinding(**f) if isinstance(f, dict) else f for f in raw]

    prioritized = toolkit.prioritize(findings)
    total = len(prioritized)
    critical = sum(1 for p in prioritized if p.get("risk") == "critical")

    return {
        "prioritized": prioritized,
        "total_findings": total,
        "critical_count": critical,
        "stage": DetectionStage.PRIORITIZE.value,
        "current_step": "prioritize",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Prioritized {total}: {critical} critical"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: SecretsInCodeDetectorToolkit,
) -> dict[str, Any]:
    """Generate final secrets detection report."""
    logger.info("secrets_detector.node.report")
    state = _to_dict(state)
    prioritized = state.get("prioritized", [])
    session_start = state.get("session_start", time.time())

    duration_ms = (time.time() - session_start) * 1000
    risk_dist: dict[str, int] = {}
    for p in prioritized:
        risk = p.get("risk", "medium")
        risk_dist[risk] = risk_dist.get(risk, 0) + 1

    active = sum(1 for p in prioritized if p.get("active", False))

    stats = {
        "total_findings": len(prioritized),
        "critical_count": risk_dist.get("critical", 0),
        "active_secrets": active,
        "total_repos": state.get("total_repos", 0),
        "risk_distribution": risk_dist,
        "scan_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "total_findings": len(prioritized),
        "critical_count": risk_dist.get("critical", 0),
        "active_secrets": active,
        "stage": DetectionStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report: {len(prioritized)} findings, "
            f"{risk_dist.get('critical', 0)} critical, "
            f"{active} active"
        ],
    }
