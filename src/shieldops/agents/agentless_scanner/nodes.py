"""Node implementations for the Agentless Scanner
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.agentless_scanner.models import (
    AgentlessScannerState,
    ASStage,
    ReasoningStep,
)
from shieldops.agents.agentless_scanner.prompts import (
    SYSTEM_CONFIG,
    SYSTEM_DISCOVERY,
    SYSTEM_EXPOSURE,
    SYSTEM_REPORT,
    AssetDiscoveryOutput,
    ConfigAnalysisOutput,
    ExposureAnalysisOutput,
    ScanReportOutput,
)
from shieldops.agents.agentless_scanner.tools import (
    AgentlessScannerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AgentlessScannerToolkit | None = None


def set_toolkit(
    toolkit: AgentlessScannerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> AgentlessScannerToolkit:
    if _toolkit is None:
        return AgentlessScannerToolkit()
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
    state: AgentlessScannerState,
) -> dict[str, Any]:
    """Discover cloud assets via API enumeration across
    target providers and regions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    providers = [p.value for p in state.target_providers]
    results = await toolkit.discover_assets(
        providers=providers,
        regions=state.target_regions,
        scope=state.scan_scope,
    )

    assets: list[dict[str, Any]] = list(results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scan_name": state.scan_name,
                "providers": providers,
                "regions": state.target_regions,
                "scope": state.scan_scope,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DISCOVERY,
            user_prompt=(f"Analyze discovered assets:\n{ctx}"),
            schema=AssetDiscoveryOutput,
        )
        if llm_out.asset_summary:  # type: ignore[union-attr]
            assets = [
                *assets,
                *llm_out.asset_summary,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="discover_assets",
            count=len(llm_out.asset_summary),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="discover_assets",
        )

    step = _step(
        state.reasoning_chain,
        "discover_assets",
        f"Providers: {len(providers)}, regions={len(state.target_regions)}",
        f"Discovered {len(assets)} assets",
        start,
        "cloud_api",
    )

    return {
        "assets": assets,
        "total_assets": len(assets),
        "stage": ASStage.DISCOVER_ASSETS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_assets",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: scan_config
# ------------------------------------------------------------------


async def scan_config(
    state: AgentlessScannerState,
) -> dict[str, Any]:
    """Scan asset configurations against CIS benchmarks
    via API snapshots."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    config_findings = await toolkit.scan_config(
        assets=state.assets,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "asset_count": len(state.assets),
                "assets_sample": state.assets[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CONFIG,
            user_prompt=f"Analyze configurations:\n{ctx}",
            schema=ConfigAnalysisOutput,
        )
        if llm_out.categories:  # type: ignore[union-attr]
            config_findings.append(
                {
                    "finding_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "misconfigurations": (llm_out.misconfigurations),  # type: ignore[union-attr]
                    "categories": llm_out.categories,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="scan_config",
            categories=len(llm_out.categories),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_config",
        )

    step = _step(
        state.reasoning_chain,
        "scan_config",
        f"Scanning {len(state.assets)} assets",
        f"Found {len(config_findings)} config findings",
        start,
        "config_benchmarks",
    )

    return {
        "config_findings": config_findings,
        "stage": ASStage.SCAN_CONFIG,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_config",
    }


# ------------------------------------------------------------------
# Node: check_vulns
# ------------------------------------------------------------------


async def check_vulns(
    state: AgentlessScannerState,
) -> dict[str, Any]:
    """Check for vulnerabilities via snapshot analysis
    without deploying agents."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    vuln_findings = await toolkit.check_vulns(
        assets=state.assets,
    )

    step = _step(
        state.reasoning_chain,
        "check_vulns",
        f"Checking {len(state.assets)} assets for vulns",
        f"Found {len(vuln_findings)} vulnerabilities",
        start,
        "vuln_database",
    )

    return {
        "vuln_findings": vuln_findings,
        "stage": ASStage.CHECK_VULNS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_vulns",
    }


# ------------------------------------------------------------------
# Node: analyze_exposure
# ------------------------------------------------------------------


async def analyze_exposure(
    state: AgentlessScannerState,
) -> dict[str, Any]:
    """Analyze exposure and attack surface for
    discovered assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    all_findings = [*state.config_findings, *state.vuln_findings]
    exposure_results = await toolkit.analyze_exposure(
        assets=state.assets,
        findings=all_findings,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "asset_count": len(state.assets),
                "config_findings": len(state.config_findings),
                "vuln_findings": len(state.vuln_findings),
                "findings_sample": all_findings[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_EXPOSURE,
            user_prompt=f"Analyze exposure:\n{ctx}",
            schema=ExposureAnalysisOutput,
        )
        if llm_out.attack_vectors:  # type: ignore[union-attr]
            exposure_results.append(
                {
                    "analysis_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "public_assets": (llm_out.public_assets),  # type: ignore[union-attr]
                    "attack_vectors": llm_out.attack_vectors,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "recommendations": llm_out.recommendations,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_exposure",
            vectors=len(llm_out.attack_vectors),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_exposure",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_exposure",
        f"Analyzing {len(all_findings)} findings for exposure",
        f"Produced {len(exposure_results)} exposure analyses",
        start,
        "exposure_analyzer",
    )

    return {
        "exposure_results": exposure_results,
        "stage": ASStage.ANALYZE_EXPOSURE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_exposure",
    }


# ------------------------------------------------------------------
# Node: prioritize
# ------------------------------------------------------------------


async def prioritize(
    state: AgentlessScannerState,
) -> dict[str, Any]:
    """Prioritize findings by risk context combining
    severity, exploitability, and business impact."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    all_findings = [*state.config_findings, *state.vuln_findings]
    prioritized = await toolkit.prioritize_findings(
        findings=all_findings,
        exposure=state.exposure_results,
    )

    critical_count = sum(1 for f in prioritized if f.get("adjusted_severity") == "critical")

    step = _step(
        state.reasoning_chain,
        "prioritize",
        f"Prioritizing {len(all_findings)} findings",
        f"Prioritized {len(prioritized)}, {critical_count} critical",
        start,
        "risk_scorer",
    )

    return {
        "prioritized": prioritized,
        "total_findings": len(all_findings),
        "critical_findings": critical_count,
        "stage": ASStage.PRIORITIZE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "prioritize",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: AgentlessScannerState,
) -> dict[str, Any]:
    """Generate the final agentless scan report with
    executive summary and remediation roadmap."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Compute coverage
    if state.total_assets > 0:
        coverage = min(1.0, len(state.assets) / max(state.total_assets, 1))
    else:
        coverage = 0.0

    report: dict[str, Any] = {
        "scan_name": state.scan_name,
        "total_assets": state.total_assets,
        "total_findings": state.total_findings,
        "critical_findings": state.critical_findings,
        "coverage": coverage,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "scan_name": state.scan_name,
                "total_assets": state.total_assets,
                "total_findings": state.total_findings,
                "critical_findings": state.critical_findings,
                "prioritized_sample": state.prioritized[:5],
                "exposure_sample": state.exposure_results[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate scan report:\n{ctx}"),
            schema=ScanReportOutput,
        )
        if isinstance(llm_out, ScanReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "compliance_status": llm_out.compliance_status,
                    "risk_rating": llm_out.risk_rating,
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
        scan_id=state.request_id,
        outcome={
            "total_assets": state.total_assets,
            "total_findings": state.total_findings,
            "critical_findings": state.critical_findings,
            "coverage": coverage,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_findings} findings"),
        (f"Report generated, coverage={coverage:.2f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "scan_coverage": coverage,
        "session_duration_ms": duration_ms,
        "stage": ASStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
