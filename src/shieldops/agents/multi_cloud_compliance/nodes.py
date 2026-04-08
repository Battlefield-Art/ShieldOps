"""Multi-Cloud Compliance Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BenchmarkControl,
    CloudConfig,
    ComplianceGap,
    ComplianceStage,
    ComplianceStatus,
)
from .tools import MultiCloudComplianceToolkit

logger = structlog.get_logger()

_toolkit: MultiCloudComplianceToolkit | None = None


def _get_toolkit() -> MultiCloudComplianceToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = MultiCloudComplianceToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def collect_configs(
    state: dict[str, Any],
    toolkit: MultiCloudComplianceToolkit,
) -> dict[str, Any]:
    """Collect cloud configurations."""
    logger.info("mcc.node.collect")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    providers = state.get("providers", ["aws", "gcp", "azure"])

    configs = await toolkit.collect_configs(tenant_id, providers)
    configs_data = [c.model_dump() for c in configs]

    return {
        "stage": ComplianceStage.EVALUATE_BENCHMARKS.value,
        "cloud_configs": configs_data,
        "current_step": "collect_configs",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(configs)} configs from {', '.join(providers)}"],
    }


async def evaluate_benchmarks(
    state: dict[str, Any],
    toolkit: MultiCloudComplianceToolkit,
) -> dict[str, Any]:
    """Evaluate CIS benchmarks against configs."""
    logger.info("mcc.node.evaluate")
    state = _to_dict(state)

    raw_configs = state.get("cloud_configs", [])
    configs = [CloudConfig(**c) for c in raw_configs]
    frameworks = state.get("frameworks", ["cis_aws"])

    controls = await toolkit.evaluate_benchmarks(configs, frameworks)
    controls_data = [c.model_dump() for c in controls]

    passing = sum(1 for c in controls if c.status == ComplianceStatus.COMPLIANT)
    total = len(controls)
    rate = round((passing / total * 100) if total else 0.0, 1)

    reasoning_note = f"Evaluated {total} controls: {passing} compliant ({rate}%)"

    try:
        from .prompts import (
            SYSTEM_BENCHMARK_EVAL,
            BenchmarkEvalOutput,
        )

        context = json.dumps(
            {
                "total": total,
                "passing": passing,
                "rate": rate,
                "frameworks": frameworks,
            },
            default=str,
        )
        llm_result = cast(
            BenchmarkEvalOutput,
            await llm_structured(
                system_prompt=SYSTEM_BENCHMARK_EVAL,
                user_prompt=f"Benchmark context:\n{context}",
                schema=BenchmarkEvalOutput,
            ),
        )
        logger.info("llm_enhanced", agent="mcc", node="evaluate")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="mcc", node="evaluate")

    return {
        "stage": ComplianceStage.IDENTIFY_GAPS.value,
        "benchmark_controls": controls_data,
        "compliance_score": rate,
        "current_step": "evaluate_benchmarks",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def identify_gaps(
    state: dict[str, Any],
    toolkit: MultiCloudComplianceToolkit,
) -> dict[str, Any]:
    """Identify compliance gaps."""
    logger.info("mcc.node.gaps")
    state = _to_dict(state)

    raw_controls = state.get("benchmark_controls", [])
    controls = [BenchmarkControl(**c) for c in raw_controls]

    gaps = await toolkit.identify_gaps(controls)
    gaps_data = [g.model_dump() for g in gaps]

    reasoning_note = f"Identified {len(gaps)} compliance gaps"

    try:
        from .prompts import (
            SYSTEM_GAP_ANALYSIS,
            GapAnalysisOutput,
        )

        context = json.dumps(
            {
                "gaps": len(gaps),
                "critical": sum(1 for g in gaps if g.severity == "critical"),
                "providers": list({p for g in gaps for p in g.providers_affected}),
            },
            default=str,
        )
        llm_result = cast(
            GapAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_GAP_ANALYSIS,
                user_prompt=f"Gap context:\n{context}",
                schema=GapAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="mcc", node="gaps")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="mcc", node="gaps")

    return {
        "stage": ComplianceStage.GENERATE_REMEDIATION.value,
        "compliance_gaps": gaps_data,
        "current_step": "identify_gaps",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_remediation(
    state: dict[str, Any],
    toolkit: MultiCloudComplianceToolkit,
) -> dict[str, Any]:
    """Generate remediation tasks for gaps."""
    logger.info("mcc.node.remediation")
    state = _to_dict(state)

    raw_gaps = state.get("compliance_gaps", [])
    gaps = [ComplianceGap(**g) for g in raw_gaps]

    tasks = await toolkit.generate_remediation_tasks(gaps)
    tasks_data = [t.model_dump() for t in tasks]

    return {
        "stage": ComplianceStage.TRACK_PROGRESS.value,
        "remediation_tasks": tasks_data,
        "current_step": "generate_remediation",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Generated {len(tasks)} remediation tasks"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: MultiCloudComplianceToolkit,
) -> dict[str, Any]:
    """Generate final compliance report."""
    logger.info("mcc.node.report")
    state = _to_dict(state)

    raw_configs = state.get("cloud_configs", [])
    raw_controls = state.get("benchmark_controls", [])
    raw_gaps = state.get("compliance_gaps", [])
    raw_tasks = state.get("remediation_tasks", [])
    compliance_score = state.get("compliance_score", 0.0)

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "configs_collected": len(raw_configs),
        "controls_evaluated": len(raw_controls),
        "compliance_gaps": len(raw_gaps),
        "remediation_tasks": len(raw_tasks),
        "compliance_score": compliance_score,
        "providers": state.get("providers", []),
    }

    report_summary = (
        f"Compliance score: {compliance_score}%. {len(raw_gaps)} gaps, {len(raw_tasks)} tasks."
    )

    try:
        from .prompts import (
            SYSTEM_COMPLIANCE_REPORT,
            ComplianceReportOutput,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            ComplianceReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_COMPLIANCE_REPORT,
                user_prompt=f"Compliance context:\n{context}",
                schema=ComplianceReportOutput,
            ),
        )
        logger.info("llm_enhanced", agent="mcc", node="report")
        report_summary = llm_result.summary
    except Exception:
        logger.debug("llm_fallback", agent="mcc", node="report")

    return {
        "stage": ComplianceStage.REPORT.value,
        "stats": stats,
        "session_duration_ms": elapsed,
        "current_step": "generate_report",
        "reasoning_chain": state.get("reasoning_chain", []) + [report_summary],
    }
