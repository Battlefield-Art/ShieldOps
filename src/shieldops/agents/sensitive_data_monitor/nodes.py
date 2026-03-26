"""Sensitive Data Monitor Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    Classification,
    DataSource,
    ExposureAssessment,
    SensitiveDataHit,
)
from .tools import SensitiveDataMonitorToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_data_sources(
    state: dict[str, Any],
    toolkit: SensitiveDataMonitorToolkit,
) -> dict[str, Any]:
    """Discover data sources across databases, storage, and AI pipelines."""
    logger.info("sensitive_data_monitor.node.discover")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    session_start = time.time()

    source_configs = state.get("sources_scanned", [])
    include_ai = state.get("include_ai_pipelines", True)
    sources = await toolkit.discover_data_sources(
        tenant_id=tenant_id,
        source_configs=(source_configs if source_configs else None),
        include_ai_pipelines=include_ai,
    )
    source_dicts = [s.model_dump() for s in sources]

    ai_count = sum(1 for s in sources if s.is_ai_pipeline)
    return {
        "sources_scanned": source_dicts,
        "session_start": session_start,
        "current_step": "discover_data_sources",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Discovered {len(sources)} data sources "
            f"({ai_count} AI pipelines) for "
            f"tenant {tenant_id}"
        ],
    }


async def scan_for_sensitive(
    state: dict[str, Any],
    toolkit: SensitiveDataMonitorToolkit,
) -> dict[str, Any]:
    """Scan discovered sources for sensitive data."""
    logger.info("sensitive_data_monitor.node.scan")
    state = _to_dict(state)
    source_dicts = state.get("sources_scanned", [])
    sources = [DataSource(**s) for s in source_dicts]

    sample_data = state.get("sample_data", {})
    hits = await toolkit.scan_for_sensitive(
        sources=sources,
        sample_data=(sample_data if sample_data else None),
    )
    hit_dicts = [h.model_dump() for h in hits]

    # LLM enhancement: sensitive data analysis
    reasoning_note = f"Detected {len(hits)} sensitive data hits"
    try:
        from .prompts import (
            SYSTEM_SENSITIVE_DATA_ANALYSIS,
            SensitiveDataAnalysisResult,
        )

        ai_hits = [h for h in hit_dicts if h.get("data_lineage", []) and len(h["data_lineage"]) > 1]
        context = json.dumps(
            {
                "source_count": len(sources),
                "total_hits": len(hit_dicts),
                "hits_sample": hit_dicts[:30],
                "ai_pipeline_hits": len(ai_hits),
                "categories": list({h.get("data_category", "") for h in hit_dicts}),
            },
            default=str,
        )
        llm_result = cast(
            SensitiveDataAnalysisResult,
            await llm_structured(
                system_prompt=(SYSTEM_SENSITIVE_DATA_ANALYSIS),
                user_prompt=(f"Sensitive data scan results:\n{context}"),
                schema=SensitiveDataAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sensitive_data_monitor",
            node="scan_for_sensitive",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sensitive_data_monitor",
            node="scan_for_sensitive",
        )

    return {
        "sensitive_hits": hit_dicts,
        "current_step": "scan_for_sensitive",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def classify_data(
    state: dict[str, Any],
    toolkit: SensitiveDataMonitorToolkit,
) -> dict[str, Any]:
    """Classify sensitive hits with exposure and regulation mapping."""
    logger.info("sensitive_data_monitor.node.classify")
    state = _to_dict(state)
    hit_dicts = state.get("sensitive_hits", [])
    hits = [SensitiveDataHit(**h) for h in hit_dicts]

    classifications = await toolkit.classify_hits(hits)
    cls_dicts = [c.model_dump() for c in classifications]

    # Compound risk: promote items with 3+ regulations
    for c in cls_dicts:
        regs = c.get("regulations", [])
        if len(regs) >= 3:
            c["risk_score"] = min(c.get("risk_score", 0) * 1.5, 10.0)

    encryption_needed = sum(1 for c in cls_dicts if c.get("requires_encryption"))
    return {
        "classifications": cls_dicts,
        "current_step": "classify_data",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Classified {len(cls_dicts)} items; {encryption_needed} require encryption"],
    }


async def assess_exposure(
    state: dict[str, Any],
    toolkit: SensitiveDataMonitorToolkit,
) -> dict[str, Any]:
    """Assess exposure risk for classified data."""
    logger.info("sensitive_data_monitor.node.assess_exposure")
    state = _to_dict(state)
    cls_dicts = state.get("classifications", [])
    source_dicts = state.get("sources_scanned", [])
    classifications = [Classification(**c) for c in cls_dicts]
    sources = [DataSource(**s) for s in source_dicts]

    assessments = await toolkit.assess_exposure(classifications, sources)
    assessment_dicts = [a.model_dump() for a in assessments]

    # LLM enhancement: exposure analysis
    reasoning_note = f"Assessed {len(assessments)} exposures"
    try:
        from .prompts import (
            SYSTEM_EXPOSURE_ANALYSIS,
            ExposureAnalysisResult,
        )

        public_count = sum(1 for a in assessments if a.is_publicly_accessible)
        context = json.dumps(
            {
                "total_assessments": len(assessments),
                "public_exposures": public_count,
                "assessments_sample": (assessment_dicts[:20]),
                "avg_risk": (
                    round(
                        sum(a.risk_score for a in assessments) / max(len(assessments), 1),
                        2,
                    )
                ),
            },
            default=str,
        )
        llm_result = cast(
            ExposureAnalysisResult,
            await llm_structured(
                system_prompt=(SYSTEM_EXPOSURE_ANALYSIS),
                user_prompt=(f"Exposure assessment results:\n{context}"),
                schema=ExposureAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sensitive_data_monitor",
            node="assess_exposure",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sensitive_data_monitor",
            node="assess_exposure",
        )

    return {
        "exposures": assessment_dicts,
        "current_step": "assess_exposure",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def enforce_controls(
    state: dict[str, Any],
    toolkit: SensitiveDataMonitorToolkit,
) -> dict[str, Any]:
    """Enforce data protection controls."""
    logger.info("sensitive_data_monitor.node.enforce_controls")
    state = _to_dict(state)
    exposure_dicts = state.get("exposures", [])
    source_dicts = state.get("sources_scanned", [])
    assessments = [ExposureAssessment(**e) for e in exposure_dicts]
    sources = [DataSource(**s) for s in source_dicts]

    enforcements = await toolkit.enforce_controls(assessments, sources)
    enforcement_dicts = [e.model_dump() for e in enforcements]

    success_count = sum(1 for e in enforcements if e.success)
    return {
        "controls_enforced": enforcement_dicts,
        "current_step": "enforce_controls",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Enforced {len(enforcements)} controls; {success_count} successful"],
    }


async def report(
    state: dict[str, Any],
    toolkit: SensitiveDataMonitorToolkit,
) -> dict[str, Any]:
    """Generate final monitoring report with stats and compliance coverage."""
    logger.info("sensitive_data_monitor.node.report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    hits = state.get("sensitive_hits", [])
    cls_dicts = state.get("classifications", [])
    exposure_dicts = state.get("exposures", [])
    enforcements = state.get("controls_enforced", [])
    source_dicts = state.get("sources_scanned", [])

    # Compliance coverage
    classifications = [Classification(**c) for c in cls_dicts]
    assessments = [ExposureAssessment(**e) for e in exposure_dicts]
    compliance_coverage = await toolkit.compute_compliance_coverage(classifications, assessments)

    # Category breakdown
    cat_counts: dict[str, int] = {}
    for h in hits:
        cat = h.get("data_category", "unknown")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    # Exposure breakdown
    exp_counts: dict[str, int] = {}
    for e in exposure_dicts:
        lvl = e.get("exposure_level", "unknown")
        exp_counts[lvl] = exp_counts.get(lvl, 0) + 1

    ai_sources = sum(1 for s in source_dicts if s.get("is_ai_pipeline"))
    avg_risk = round(
        sum(e.get("risk_score", 0) for e in exposure_dicts) / max(len(exposure_dicts), 1),
        2,
    )

    stats = {
        "sources_scanned": len(source_dicts),
        "ai_pipeline_sources": ai_sources,
        "sensitive_hits": len(hits),
        "category_breakdown": cat_counts,
        "exposure_breakdown": exp_counts,
        "classifications_count": len(cls_dicts),
        "average_risk_score": avg_risk,
        "controls_enforced": len(enforcements),
        "controls_successful": sum(1 for e in enforcements if e.get("success", False)),
        "compliance_coverage": compliance_coverage,
    }

    # LLM enhancement: executive report
    reasoning_note = (
        f"Report: {stats['sources_scanned']} sources, "
        f"{stats['sensitive_hits']} hits, "
        f"avg_risk={avg_risk}, "
        f"{stats['controls_enforced']} controls"
    )
    try:
        from .prompts import (
            SYSTEM_MONITOR_REPORT,
            MonitorReportResult,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            MonitorReportResult,
            await llm_structured(
                system_prompt=SYSTEM_MONITOR_REPORT,
                user_prompt=(f"Monitoring stats:\n{context}"),
                schema=MonitorReportResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sensitive_data_monitor",
            node="report",
        )
        reasoning_note = f"{llm_result.executive_summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sensitive_data_monitor",
            node="report",
        )

    return {
        "stats": stats,
        "compliance_coverage": compliance_coverage,
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }
