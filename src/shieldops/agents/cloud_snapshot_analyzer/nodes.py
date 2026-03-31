"""Node implementations for the Cloud Snapshot Analyzer
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_snapshot_analyzer.models import (
    CloudSnapshotAnalyzerState,
    CSAStage,
    ReasoningStep,
)
from shieldops.agents.cloud_snapshot_analyzer.prompts import (
    SYSTEM_DISCOVER,
    SYSTEM_ENCRYPTION,
    SYSTEM_EXPOSURE,
    SYSTEM_REPORT,
    EncryptionAuditOutput,
    ExposureDetectionOutput,
    SnapshotDiscoveryOutput,
    SnapshotReportOutput,
)
from shieldops.agents.cloud_snapshot_analyzer.tools import (
    CloudSnapshotAnalyzerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudSnapshotAnalyzerToolkit | None = None


def set_toolkit(
    toolkit: CloudSnapshotAnalyzerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CloudSnapshotAnalyzerToolkit:
    if _toolkit is None:
        return CloudSnapshotAnalyzerToolkit()
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
# Node: discover_snapshots
# ------------------------------------------------------------------


async def discover_snapshots(
    state: CloudSnapshotAnalyzerState,
) -> dict[str, Any]:
    """Discover cloud snapshots across providers and
    regions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.discover_snapshots(
        provider=state.cloud_provider.value,
        regions=state.regions,
        account_ids=state.account_ids,
        max_age_days=state.max_age_days,
    )

    snapshots: list[dict[str, Any]] = list(results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "provider": state.cloud_provider.value,
                "regions": state.regions,
                "accounts": state.account_ids,
                "max_age_days": state.max_age_days,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DISCOVER,
            user_prompt=f"Discover snapshots:\n{ctx}",
            schema=SnapshotDiscoveryOutput,
        )
        if llm_out.stale_snapshots:  # type: ignore[union-attr]
            logger.info(
                "llm_enhanced",
                node="discover_snapshots",
                stale=len(llm_out.stale_snapshots),  # type: ignore[union-attr]
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="discover_snapshots",
        )

    stale = sum(1 for s in snapshots if s.get("stale", False))

    step = _step(
        state.reasoning_chain,
        "discover_snapshots",
        f"Provider: {state.cloud_provider}, regions={len(state.regions)}",
        f"Discovered {len(snapshots)} snapshots, {stale} stale",
        start,
        "cloud_api",
    )

    return {
        "snapshots": snapshots,
        "total_snapshots": len(snapshots),
        "stale_count": stale,
        "stage": CSAStage.DISCOVER_SNAPSHOTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_snapshots",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_config
# ------------------------------------------------------------------


async def analyze_config(
    state: CloudSnapshotAnalyzerState,
) -> dict[str, Any]:
    """Analyze snapshot configurations for security
    issues."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    config_analyses = await toolkit.analyze_config(
        snapshots=state.snapshots,
    )

    step = _step(
        state.reasoning_chain,
        "analyze_config",
        f"Analyzing config for {len(state.snapshots)} snapshots",
        f"Produced {len(config_analyses)} config analyses",
        start,
        "config_analyzer",
    )

    return {
        "config_analyses": config_analyses,
        "stage": CSAStage.ANALYZE_CONFIG,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_config",
    }


# ------------------------------------------------------------------
# Node: check_encryption
# ------------------------------------------------------------------


async def check_encryption(
    state: CloudSnapshotAnalyzerState,
) -> dict[str, Any]:
    """Audit encryption posture for all discovered
    snapshots."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    encryption_findings = await toolkit.check_encryption(
        snapshots=state.snapshots,
        configs=state.config_analyses,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "snapshot_count": len(state.snapshots),
                "config_sample": state.config_analyses[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ENCRYPTION,
            user_prompt=f"Audit encryption:\n{ctx}",
            schema=EncryptionAuditOutput,
        )
        rid = random.randint(1000, 9999)  # noqa: S311
        if llm_out.compliance_issues:  # type: ignore[union-attr]
            encryption_findings.append(
                {
                    "finding_id": f"llm-{rid}",
                    "unencrypted": llm_out.unencrypted_count,  # type: ignore[union-attr]
                    "weak_encryption": llm_out.weak_encryption,  # type: ignore[union-attr]
                    "compliance_issues": llm_out.compliance_issues,  # type: ignore[union-attr]
                    "recommendations": llm_out.recommendations,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="check_encryption",
            issues=len(llm_out.compliance_issues),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_encryption",
        )

    unencrypted = sum(1 for f in encryption_findings if not f.get("encrypted", True))

    step = _step(
        state.reasoning_chain,
        "check_encryption",
        f"Checking encryption for {len(state.snapshots)} snapshots",
        f"{unencrypted} unencrypted of {len(encryption_findings)} findings",
        start,
        "encryption_auditor",
    )

    return {
        "encryption_findings": encryption_findings,
        "unencrypted_count": unencrypted,
        "stage": CSAStage.CHECK_ENCRYPTION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_encryption",
    }


# ------------------------------------------------------------------
# Node: detect_exposure
# ------------------------------------------------------------------


async def detect_exposure(
    state: CloudSnapshotAnalyzerState,
) -> dict[str, Any]:
    """Detect public exposure and unauthorized sharing
    of snapshots."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    exposure_findings = await toolkit.detect_exposure(
        snapshots=state.snapshots,
        configs=state.config_analyses,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "snapshot_count": len(state.snapshots),
                "config_sample": state.config_analyses[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_EXPOSURE,
            user_prompt=f"Detect exposure:\n{ctx}",
            schema=ExposureDetectionOutput,
        )
        rid = random.randint(1000, 9999)  # noqa: S311
        if llm_out.public_snapshots:  # type: ignore[union-attr]
            exposure_findings.append(
                {
                    "finding_id": f"llm-{rid}",
                    "public_snapshots": llm_out.public_snapshots,  # type: ignore[union-attr]
                    "cross_account": llm_out.cross_account_shared,  # type: ignore[union-attr]
                    "severity": llm_out.severity,  # type: ignore[union-attr]
                    "remediation_steps": llm_out.remediation_steps,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="detect_exposure",
            public=len(llm_out.public_snapshots),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_exposure",
        )

    exposed = sum(1 for f in exposure_findings if f.get("severity", "low") in ("critical", "high"))

    step = _step(
        state.reasoning_chain,
        "detect_exposure",
        f"Scanning {len(state.snapshots)} snapshots for exposure",
        f"{exposed} high-severity exposures found",
        start,
        "exposure_scanner",
    )

    return {
        "exposure_findings": exposure_findings,
        "exposed_count": exposed,
        "stage": CSAStage.DETECT_EXPOSURE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_exposure",
    }


# ------------------------------------------------------------------
# Node: assess_risk
# ------------------------------------------------------------------


async def assess_risk(
    state: CloudSnapshotAnalyzerState,
) -> dict[str, Any]:
    """Assess overall risk for each snapshot based on
    all findings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    risk_assessments = await toolkit.assess_risk(
        snapshots=state.snapshots,
        encryption_findings=state.encryption_findings,
        exposure_findings=state.exposure_findings,
    )

    high_risk = sum(
        1 for r in risk_assessments if r.get("risk_level", "low") in ("critical", "high")
    )

    step = _step(
        state.reasoning_chain,
        "assess_risk",
        f"Assessing risk for {len(state.snapshots)} snapshots",
        f"{high_risk} high-risk snapshots identified",
        start,
        "risk_engine",
    )

    return {
        "risk_assessments": risk_assessments,
        "high_risk_count": high_risk,
        "stage": CSAStage.ASSESS_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risk",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: CloudSnapshotAnalyzerState,
) -> dict[str, Any]:
    """Generate the final snapshot analysis report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_snapshots": state.total_snapshots,
        "unencrypted": state.unencrypted_count,
        "exposed": state.exposed_count,
        "stale": state.stale_count,
        "high_risk": state.high_risk_count,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "total_snapshots": state.total_snapshots,
                "unencrypted": state.unencrypted_count,
                "exposed": state.exposed_count,
                "stale": state.stale_count,
                "high_risk": state.high_risk_count,
                "risk_sample": state.risk_assessments[:5],
                "encryption_sample": state.encryption_findings[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate snapshot report:\n{ctx}",
            schema=SnapshotReportOutput,
        )
        if isinstance(llm_out, SnapshotReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "risk_level": llm_out.risk_level,
                    "cost_savings": llm_out.cost_savings,
                    "recommendations": llm_out.recommendations,
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

    # Record metrics
    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        run_id=state.request_id,
        outcome={
            "total_snapshots": state.total_snapshots,
            "unencrypted": state.unencrypted_count,
            "exposed": state.exposed_count,
            "high_risk": state.high_risk_count,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_snapshots} snapshots",
        f"Report generated, {state.high_risk_count} high-risk",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": CSAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
