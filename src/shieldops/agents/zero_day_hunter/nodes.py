"""Node implementations for the Zero Day Hunter Agent
LangGraph workflow."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.agents.zero_day_hunter.models import (
    ReasoningStep,
    ZDHStage,
    ZeroDayHunterState,
)
from shieldops.agents.zero_day_hunter.prompts import (
    SYSTEM_EXPLOIT_ANALYSIS,
    SYSTEM_EXPOSURE_ASSESSMENT,
    SYSTEM_REPORT,
    SYSTEM_SIGNATURE_DEVELOPMENT,
    ExploitAnalysisOutput,
    ExposureAssessmentOutput,
    SignatureDevelopmentOutput,
    ZeroDayReportOutput,
)
from shieldops.agents.zero_day_hunter.tools import (
    ZeroDayHunterToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ZeroDayHunterToolkit | None = None


def set_toolkit(
    toolkit: ZeroDayHunterToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ZeroDayHunterToolkit:
    if _toolkit is None:
        return ZeroDayHunterToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: float,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((time.time() - start) * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: monitor_feeds
# ------------------------------------------------------------------


async def monitor_feeds(
    state: ZeroDayHunterState,
) -> dict[str, Any]:
    """Monitor threat intelligence feeds for zero-day
    disclosures."""
    start = time.time()
    toolkit = _get_toolkit()

    items = await toolkit.monitor_feeds(
        tenant_id=state.tenant_id,
    )

    step = _step(
        state.reasoning_chain,
        "monitor_feeds",
        f"Tenant: {state.tenant_id}",
        f"Found {len(items)} feed items",
        start,
        "threat_feed",
    )

    return {
        "feed_items": items,
        "zero_days_found": len(items),
        "stage": ZDHStage.MONITOR_FEEDS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_feeds",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_exploits
# ------------------------------------------------------------------


async def analyze_exploits(
    state: ZeroDayHunterState,
) -> dict[str, Any]:
    """Analyze zero-day exploits from feed data."""
    start = time.time()
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_exploits(
        feed_items=state.feed_items,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "feed_count": len(state.feed_items),
                "analyses": analyses[:5],
                "feeds_sample": state.feed_items[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_EXPLOIT_ANALYSIS,
            user_prompt=(f"Analyze zero-day exploits:\n{ctx}"),
            schema=ExploitAnalysisOutput,
        )
        logger.info(
            "llm_enhanced",
            node="analyze_exploits",
            severity=llm_out.severity,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_exploits",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_exploits",
        f"Analyzing {len(state.feed_items)} feed items",
        f"Produced {len(analyses)} analyses",
        start,
        "exploit_analyzer",
    )

    return {
        "exploit_analyses": analyses,
        "stage": ZDHStage.ANALYZE_EXPLOITS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_exploits",
    }


# ------------------------------------------------------------------
# Node: assess_exposure
# ------------------------------------------------------------------


async def assess_exposure(
    state: ZeroDayHunterState,
) -> dict[str, Any]:
    """Assess organizational exposure to zero-days."""
    start = time.time()
    toolkit = _get_toolkit()

    exposures = await toolkit.assess_exposure(
        analyses=state.exploit_analyses,
        tenant_id=state.tenant_id,
    )

    critical = sum(1 for e in exposures if e.get("business_impact") == "catastrophic")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "analyses": state.exploit_analyses[:5],
                "exposures": exposures[:5],
                "critical_count": critical,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_EXPOSURE_ASSESSMENT,
            user_prompt=(f"Assess exposure:\n{ctx}"),
            schema=ExposureAssessmentOutput,
        )
        logger.info(
            "llm_enhanced",
            node="assess_exposure",
            impact=llm_out.business_impact,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_exposure",
        )

    step = _step(
        state.reasoning_chain,
        "assess_exposure",
        (f"Assessing {len(state.exploit_analyses)} exploits"),
        (f"{len(exposures)} exposures, {critical} critical"),
        start,
        "exposure_assessor",
    )

    return {
        "exposure_results": exposures,
        "critical_exposures": critical,
        "stage": ZDHStage.ASSESS_EXPOSURE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_exposure",
    }


# ------------------------------------------------------------------
# Node: develop_signatures
# ------------------------------------------------------------------


async def develop_signatures(
    state: ZeroDayHunterState,
) -> dict[str, Any]:
    """Develop detection signatures and virtual patches."""
    start = time.time()
    toolkit = _get_toolkit()

    signatures = await toolkit.develop_signatures(
        analyses=state.exploit_analyses,
        exposures=state.exposure_results,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "analyses": state.exploit_analyses[:5],
                "signatures": signatures[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_SIGNATURE_DEVELOPMENT,
            user_prompt=(f"Develop signatures:\n{ctx}"),
            schema=SignatureDevelopmentOutput,
        )
        logger.info(
            "llm_enhanced",
            node="develop_signatures",
            created=llm_out.signatures_created,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="develop_signatures",
        )

    step = _step(
        state.reasoning_chain,
        "develop_signatures",
        (f"Developing for {len(state.exploit_analyses)} exploits"),
        f"Created {len(signatures)} signatures",
        start,
        "signature_developer",
    )

    return {
        "signatures": signatures,
        "signatures_deployed": len(signatures),
        "stage": ZDHStage.DEVELOP_SIGNATURES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "develop_signatures",
    }


# ------------------------------------------------------------------
# Node: deploy_mitigations
# ------------------------------------------------------------------


async def deploy_mitigations(
    state: ZeroDayHunterState,
) -> dict[str, Any]:
    """Deploy mitigations and virtual patches."""
    start = time.time()
    toolkit = _get_toolkit()

    mitigations = await toolkit.deploy_mitigations(
        signatures=state.signatures,
        exposures=state.exposure_results,
    )

    step = _step(
        state.reasoning_chain,
        "deploy_mitigations",
        f"Deploying {len(state.signatures)} signatures",
        f"Applied {len(mitigations)} mitigations",
        start,
        "mitigation_deployer",
    )

    return {
        "mitigations": mitigations,
        "mitigations_applied": len(mitigations),
        "stage": ZDHStage.DEPLOY_MITIGATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "deploy_mitigations",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: ZeroDayHunterState,
) -> dict[str, Any]:
    """Generate final zero-day hunt report."""
    start = time.time()
    _toolkit_ref = _get_toolkit()

    duration_ms = int((time.time() - state.session_start) * 1000)

    report: dict[str, Any] = {
        "zero_days_found": state.zero_days_found,
        "critical_exposures": state.critical_exposures,
        "signatures_deployed": state.signatures_deployed,
        "mitigations_applied": state.mitigations_applied,
        "duration_ms": duration_ms,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "feed_items": state.feed_items[:5],
                "analyses": state.exploit_analyses[:5],
                "exposures": state.exposure_results[:5],
                "signatures": state.signatures[:5],
                "mitigations": state.mitigations[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate zero-day hunt report:\n{ctx}"),
            schema=ZeroDayReportOutput,
        )
        if isinstance(llm_out, ZeroDayReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "threat_level": llm_out.threat_level,
                    "key_findings": llm_out.key_findings,
                    "recommendations": (llm_out.recommendations),
                    "mitre_coverage": (llm_out.mitre_coverage),
                }
            )
        logger.info(
            "llm_enhanced",
            node="generate_report",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    await _toolkit_ref.record_metric(
        "zdh.run_completed",
        1.0,
        {"tenant_id": state.tenant_id},
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.zero_days_found} zero-days"),
        "Report generated",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": ZDHStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
