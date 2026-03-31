"""Node implementations for the Secret Sprawl Detector
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.secret_sprawl_detector.models import (
    ReasoningStep,
    SecretSprawlDetectorState,
    SSDStage,
)
from shieldops.agents.secret_sprawl_detector.prompts import (
    SYSTEM_ALERT,
    SYSTEM_CLASSIFY,
    SYSTEM_DETECT,
    SYSTEM_REPORT,
    AlertPriorityOutput,
    RiskClassificationOutput,
    SecretDetectionOutput,
    SprawlReportOutput,
)
from shieldops.agents.secret_sprawl_detector.tools import (
    SecretSprawlDetectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecretSprawlDetectorToolkit | None = None


def set_toolkit(
    toolkit: SecretSprawlDetectorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecretSprawlDetectorToolkit:
    if _toolkit is None:
        return SecretSprawlDetectorToolkit()
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
# Node: scan_repos
# ------------------------------------------------------------------


async def scan_repos(
    state: SecretSprawlDetectorState,
) -> dict[str, Any]:
    """Scan git repositories for leaked secrets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    repo_scans = await toolkit.scan_repos(
        repos=state.target_repos,
        scan_history=state.scan_git_history,
    )

    repos_scanned = len(state.target_repos)

    step = _step(
        state.reasoning_chain,
        "scan_repos",
        f"Scanning {repos_scanned} repositories",
        f"Completed {len(repo_scans)} repo scans",
        start,
        "git_scanner",
    )

    return {
        "repo_scans": repo_scans,
        "repos_scanned": repos_scanned,
        "stage": SSDStage.SCAN_REPOS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_repos",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: scan_config
# ------------------------------------------------------------------


async def scan_config(
    state: SecretSprawlDetectorState,
) -> dict[str, Any]:
    """Scan configuration files for embedded secrets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    config_scans = await toolkit.scan_config_files(
        config_paths=state.target_configs,
    )

    configs_scanned = len(state.target_configs)

    step = _step(
        state.reasoning_chain,
        "scan_config",
        f"Scanning {configs_scanned} config paths",
        f"Completed {len(config_scans)} config scans",
        start,
        "config_scanner",
    )

    return {
        "config_scans": config_scans,
        "configs_scanned": configs_scanned,
        "stage": SSDStage.SCAN_CONFIG,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_config",
    }


# ------------------------------------------------------------------
# Node: detect_secrets
# ------------------------------------------------------------------


async def detect_secrets(
    state: SecretSprawlDetectorState,
) -> dict[str, Any]:
    """Detect secrets from scan results using multiple
    detection methods."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.detect_secrets(
        repo_results=state.repo_scans,
        config_results=state.config_scans,
        entropy_threshold=state.entropy_threshold,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "repo_scan_count": len(state.repo_scans),
                "config_scan_count": len(state.config_scans),
                "repo_scans_sample": state.repo_scans[:5],
                "config_scans_sample": (state.config_scans[:5]),
                "entropy_threshold": (state.entropy_threshold),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DETECT,
            user_prompt=(f"Analyze scan results for secrets:\n{ctx}"),
            schema=SecretDetectionOutput,
        )
        if llm_out.findings:  # type: ignore[union-attr]
            findings = [
                *findings,
                *llm_out.findings,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="detect_secrets",
            count=len(llm_out.findings),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_secrets",
        )

    step = _step(
        state.reasoning_chain,
        "detect_secrets",
        (f"Analyzing {len(state.repo_scans)} repo + {len(state.config_scans)} config scans"),
        f"Detected {len(findings)} secrets",
        start,
        "secret_detector",
    )

    return {
        "findings": findings,
        "total_secrets": len(findings),
        "stage": SSDStage.DETECT_SECRETS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_secrets",
    }


# ------------------------------------------------------------------
# Node: classify_risk
# ------------------------------------------------------------------


async def classify_risk(
    state: SecretSprawlDetectorState,
) -> dict[str, Any]:
    """Classify risk level for each detected secret."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_risk(
        findings=state.findings,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_secrets": state.total_secrets,
                "findings_sample": state.findings[:10],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=(f"Classify secret risk levels:\n{ctx}"),
            schema=RiskClassificationOutput,
        )
        if llm_out.classifications:  # type: ignore[union-attr]
            classifications = [
                *classifications,
                *llm_out.classifications,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="classify_risk",
            count=len(llm_out.classifications),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_risk",
        )

    critical = sum(1 for c in classifications if c.get("risk_level") == "critical")

    step = _step(
        state.reasoning_chain,
        "classify_risk",
        f"Classifying {state.total_secrets} secrets",
        (f"Classified {len(classifications)}, {critical} critical"),
        start,
        "risk_classifier",
    )

    return {
        "classifications": classifications,
        "critical_secrets": critical,
        "stage": SSDStage.CLASSIFY_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_risk",
    }


# ------------------------------------------------------------------
# Node: alert_owners
# ------------------------------------------------------------------


async def alert_owners(
    state: SecretSprawlDetectorState,
) -> dict[str, Any]:
    """Alert secret owners based on risk classification."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    alerts = await toolkit.alert_owners(
        classifications=state.classifications,
        findings=state.findings,
    )

    # LLM enhancement for prioritization
    try:
        ctx = _json.dumps(
            {
                "total_secrets": state.total_secrets,
                "critical_secrets": state.critical_secrets,
                "classifications_sample": (state.classifications[:5]),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ALERT,
            user_prompt=(f"Prioritize owner alerts:\n{ctx}"),
            schema=AlertPriorityOutput,
        )
        if llm_out.alerts:  # type: ignore[union-attr]
            alerts = [
                *alerts,
                *llm_out.alerts,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="alert_owners",
            alert_count=len(llm_out.alerts),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="alert_owners",
        )

    step = _step(
        state.reasoning_chain,
        "alert_owners",
        (f"Alerting owners for {state.critical_secrets} critical secrets"),
        f"Sent {len(alerts)} alerts",
        start,
        "notification_service",
    )

    return {
        "alerts": alerts,
        "alerts_sent": len(alerts),
        "stage": SSDStage.ALERT_OWNERS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "alert_owners",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecretSprawlDetectorState,
) -> dict[str, Any]:
    """Generate the final sprawl detection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "scan_name": state.scan_name,
        "repos_scanned": state.repos_scanned,
        "configs_scanned": state.configs_scanned,
        "total_secrets": state.total_secrets,
        "critical_secrets": state.critical_secrets,
        "alerts_sent": state.alerts_sent,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scan_name": state.scan_name,
                "total_secrets": state.total_secrets,
                "critical_secrets": state.critical_secrets,
                "repos_scanned": state.repos_scanned,
                "configs_scanned": state.configs_scanned,
                "findings_sample": state.findings[:5],
                "classifications_sample": (state.classifications[:5]),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate sprawl report:\n{ctx}"),
            schema=SprawlReportOutput,
        )
        if isinstance(llm_out, SprawlReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "critical_findings": (llm_out.critical_findings),
                    "recommendations": (llm_out.recommendations),
                    "risk_rating": llm_out.risk_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                findings=len(llm_out.critical_findings),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    await toolkit.record_metric(
        scan_id=state.request_id,
        outcome={
            "total_secrets": state.total_secrets,
            "critical": state.critical_secrets,
            "repos": state.repos_scanned,
            "configs": state.configs_scanned,
            "alerts": state.alerts_sent,
        },
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_secrets} secrets"),
        (f"Report generated, critical={state.critical_secrets}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SSDStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
