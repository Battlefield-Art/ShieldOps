"""Endpoint Hardening Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BaselineCheck,
    Deviation,
    EHAStage,
    EndpointScan,
    HardeningFix,
    ReasoningStep,
)
from .tools import EndpointHardeningAgentToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Scan Endpoints
# ------------------------------------------------------------------


async def scan_endpoints(
    state: dict[str, Any],
    toolkit: EndpointHardeningAgentToolkit,
) -> dict[str, Any]:
    """Scan endpoints for current security posture."""
    logger.info("eha.node.scan_endpoints")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    scans = await toolkit.scan_endpoints(tenant_id)
    data = [s.model_dump() for s in scans]

    note = f"Scanned {len(scans)} endpoints"

    return {
        "stage": EHAStage.CHECK_BASELINE.value,
        "scans": data,
        "total_endpoints": len(scans),
        "current_step": "scan_endpoints",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="scan_endpoints",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Check Baseline
# ------------------------------------------------------------------


async def check_baseline(
    state: dict[str, Any],
    toolkit: EndpointHardeningAgentToolkit,
) -> dict[str, Any]:
    """Check endpoints against CIS benchmark baselines."""
    logger.info("eha.node.check_baseline")
    state = _to_dict(state)

    scans = [EndpointScan(**s) for s in state.get("scans", [])]
    baselines = await toolkit.check_baseline(scans)
    data = [b.model_dump() for b in baselines]

    avg_score = round(
        sum(b.score_pct for b in baselines) / max(len(baselines), 1),
        1,
    )
    note = f"Baseline check: avg score {avg_score}% across {len(baselines)} endpoints"

    try:
        from .prompts import SYSTEM_BASELINE, BaselineInsight

        ctx = json.dumps(
            {
                "baselines": [
                    {
                        "hostname": b.hostname,
                        "benchmark": b.benchmark.value,
                        "score": b.score_pct,
                        "failing": b.failing,
                    }
                    for b in baselines[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            BaselineInsight,
            await llm_structured(
                system_prompt=SYSTEM_BASELINE,
                user_prompt=f"Baseline results:\n{ctx}",
                schema=BaselineInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="eha",
            node="check_baseline",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="eha",
            node="check_baseline",
        )

    return {
        "stage": EHAStage.DETECT_DEVIATIONS.value,
        "baselines": data,
        "current_step": "check_baseline",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="check_baseline",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Deviations
# ------------------------------------------------------------------


async def detect_deviations(
    state: dict[str, Any],
    toolkit: EndpointHardeningAgentToolkit,
) -> dict[str, Any]:
    """Detect deviations from security baselines."""
    logger.info("eha.node.detect_deviations")
    state = _to_dict(state)

    baselines = [BaselineCheck(**b) for b in state.get("baselines", [])]
    deviations = await toolkit.detect_deviations(baselines)
    data = [d.model_dump() for d in deviations]

    critical = sum(1 for d in deviations if d.severity.value == "critical")
    note = f"Found {len(deviations)} deviations, {critical} critical"

    return {
        "stage": EHAStage.GENERATE_FIXES.value,
        "deviations": data,
        "deviations_found": len(deviations),
        "current_step": "detect_deviations",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_deviations",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Generate Fixes
# ------------------------------------------------------------------


async def generate_fixes(
    state: dict[str, Any],
    toolkit: EndpointHardeningAgentToolkit,
) -> dict[str, Any]:
    """Generate hardening fixes for detected deviations."""
    logger.info("eha.node.generate_fixes")
    state = _to_dict(state)

    deviations = [Deviation(**d) for d in state.get("deviations", [])]
    fixes = await toolkit.generate_fixes(deviations)
    data = [f.model_dump() for f in fixes]

    reboot_count = sum(1 for f in fixes if f.requires_reboot)
    note = f"Generated {len(fixes)} fixes, {reboot_count} require reboot"

    return {
        "stage": EHAStage.APPLY_HARDENING.value,
        "fixes": data,
        "current_step": "generate_fixes",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="generate_fixes",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Apply Hardening
# ------------------------------------------------------------------


async def apply_hardening(
    state: dict[str, Any],
    toolkit: EndpointHardeningAgentToolkit,
) -> dict[str, Any]:
    """Apply hardening fixes to endpoints."""
    logger.info("eha.node.apply_hardening")
    state = _to_dict(state)

    fixes = [HardeningFix(**f) for f in state.get("fixes", [])]
    results = await toolkit.apply_hardening(fixes)
    data = [r.model_dump() for r in results]

    applied = sum(1 for r in results if r.applied)
    note = f"Applied {applied}/{len(results)} hardening fixes"

    return {
        "stage": EHAStage.REPORT.value,
        "hardening_results": data,
        "current_step": "apply_hardening",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="apply_hardening",
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
    toolkit: EndpointHardeningAgentToolkit,
) -> dict[str, Any]:
    """Compile the final endpoint hardening report."""
    logger.info("eha.node.report")
    state = _to_dict(state)

    total_ep = state.get("total_endpoints", 0)
    dev_count = state.get("deviations_found", 0)
    fix_count = len(state.get("fixes", []))
    result_count = len(state.get("hardening_results", []))

    lines = [
        "# Endpoint Hardening Report",
        "",
        f"**Endpoints scanned:** {total_ep}",
        f"**Deviations found:** {dev_count}",
        f"**Fixes generated:** {fix_count}",
        f"**Fixes applied:** {result_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_endpoints": total_ep,
                "deviations": dev_count,
                "fixes": fix_count,
                "applied": result_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Hardening report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="eha",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="eha",
            node="report",
        )

    return {
        "stage": EHAStage.REPORT.value,
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
