"""Data Classification Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import DataAsset, SensitiveDataFinding
from .tools import DataClassificationToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def scan_sources(
    state: dict[str, Any],
    toolkit: DataClassificationToolkit,
) -> dict[str, Any]:
    """Discover and catalog data assets across the tenant environment."""
    logger.info("data_classification.node.scan_sources")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    session_start = time.time()

    source_configs = state.get("data_assets", [])
    assets = await toolkit.scan_data_sources(
        tenant_id=tenant_id,
        source_configs=source_configs if source_configs else None,
    )
    asset_dicts = [a.model_dump() for a in assets]

    return {
        "data_assets": asset_dicts,
        "session_start": session_start,
        "current_step": "scan_sources",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned {len(assets)} data assets for tenant {tenant_id}"],
    }


async def detect_sensitive(
    state: dict[str, Any],
    toolkit: DataClassificationToolkit,
) -> dict[str, Any]:
    """Run sensitive data detection across discovered assets."""
    logger.info("data_classification.node.detect_sensitive")
    state = _to_dict(state)
    asset_dicts = state.get("data_assets", [])
    assets = [DataAsset(**a) for a in asset_dicts]

    sample_data = state.get("sample_data", {})
    findings = await toolkit.detect_sensitive_data(
        assets=assets,
        sample_data=sample_data if sample_data else None,
    )
    finding_dicts = [f.model_dump() for f in findings]

    # LLM enhancement: sensitivity analysis
    reasoning_note = f"Detected {len(findings)} sensitive data findings"
    try:
        from .prompts import SYSTEM_SENSITIVITY_ANALYSIS, SensitivityAnalysisResult

        context = json.dumps(
            {
                "asset_count": len(assets),
                "findings": finding_dicts[:30],
                "categories": list({f.data_category.value for f in findings}),
            },
            default=str,
        )
        llm_result = cast(
            SensitivityAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_SENSITIVITY_ANALYSIS,
                user_prompt=f"Data classification findings:\n{context}",
                schema=SensitivityAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_classification",
            node="detect_sensitive",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_classification",
            node="detect_sensitive",
        )

    return {
        "sensitive_findings": finding_dicts,
        "current_step": "detect_sensitive",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def classify_level(
    state: dict[str, Any],
    toolkit: DataClassificationToolkit,
) -> dict[str, Any]:
    """Assign final sensitivity levels to findings (refine defaults)."""
    logger.info("data_classification.node.classify_level")
    state = _to_dict(state)
    findings = state.get("sensitive_findings", [])

    # Promote sensitivity for assets with multiple categories
    asset_categories: dict[str, set[str]] = {}
    for f in findings:
        aid = f.get("asset_id", "")
        cat = f.get("data_category", "")
        asset_categories.setdefault(aid, set()).add(cat)

    updated: list[dict[str, Any]] = []
    for f in findings:
        f_copy = dict(f)
        aid = f_copy.get("asset_id", "")
        cats = asset_categories.get(aid, set())
        # Compound risk: 3+ categories → promote to top_secret
        if len(cats) >= 3 and f_copy.get("sensitivity_level") != "top_secret":
            f_copy["sensitivity_level"] = "top_secret"
        # Low-confidence findings stay at internal minimum
        if f_copy.get("confidence", 0) < 0.5:
            f_copy["sensitivity_level"] = "internal"
        updated.append(f_copy)

    return {
        "sensitive_findings": updated,
        "current_step": "classify_level",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Classified {len(updated)} findings; "
            f"{len([a for a in asset_categories.values() if len(a) >= 3])} "
            f"assets with compound risk"
        ],
    }


async def map_regulations(
    state: dict[str, Any],
    toolkit: DataClassificationToolkit,
) -> dict[str, Any]:
    """Map findings to regulatory requirements and identify gaps."""
    logger.info("data_classification.node.map_regulations")
    state = _to_dict(state)
    finding_dicts = state.get("sensitive_findings", [])
    findings = [SensitiveDataFinding(**f) for f in finding_dicts]

    mappings = await toolkit.map_to_regulations(findings)
    mapping_dicts = [m.model_dump() for m in mappings]

    gaps = [m for m in mappings if not m.compliant]
    reasoning_note = (
        f"Mapped {len(mappings)} regulatory requirements; {len(gaps)} compliance gaps identified"
    )

    # LLM enhancement: regulatory gap analysis
    try:
        from .prompts import SYSTEM_REGULATORY_GAP, RegulatoryGapResult

        context = json.dumps(
            {
                "total_mappings": len(mapping_dicts),
                "gaps": [m.model_dump() for m in gaps[:20]],
                "regulations_affected": list({m.regulation for m in gaps}),
            },
            default=str,
        )
        llm_result = cast(
            RegulatoryGapResult,
            await llm_structured(
                system_prompt=SYSTEM_REGULATORY_GAP,
                user_prompt=f"Regulatory mapping results:\n{context}",
                schema=RegulatoryGapResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_classification",
            node="map_regulations",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_classification",
            node="map_regulations",
        )

    return {
        "regulatory_mappings": mapping_dicts,
        "current_step": "map_regulations",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def enforce_labels(
    state: dict[str, Any],
    toolkit: DataClassificationToolkit,
) -> dict[str, Any]:
    """Apply classification labels to data assets."""
    logger.info("data_classification.node.enforce_labels")
    state = _to_dict(state)
    asset_dicts = state.get("data_assets", [])
    finding_dicts = state.get("sensitive_findings", [])

    assets = [DataAsset(**a) for a in asset_dicts]
    findings = [SensitiveDataFinding(**f) for f in finding_dicts]

    enforcements = await toolkit.enforce_labels(assets=assets, findings=findings)
    enforcement_dicts = [e.model_dump() for e in enforcements]

    success_count = sum(1 for e in enforcements if e.success)
    return {
        "label_enforcements": enforcement_dicts,
        "current_step": "enforce_labels",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Applied labels to {len(enforcements)} assets; {success_count} successful"],
    }


async def report(
    state: dict[str, Any],
    toolkit: DataClassificationToolkit,
) -> dict[str, Any]:
    """Generate final classification report with stats."""
    logger.info("data_classification.node.report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    findings = state.get("sensitive_findings", [])
    mappings = state.get("regulatory_mappings", [])
    enforcements = state.get("label_enforcements", [])

    # Build stats
    category_counts: dict[str, int] = {}
    level_counts: dict[str, int] = {}
    for f in findings:
        cat = f.get("data_category", "unknown")
        lvl = f.get("sensitivity_level", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        level_counts[lvl] = level_counts.get(lvl, 0) + 1

    gaps = [m for m in mappings if not m.get("compliant", True)]
    total_mappings = len(mappings)
    compliance_ratio = (total_mappings - len(gaps)) / total_mappings if total_mappings else 1.0

    stats = {
        "assets_scanned": len(state.get("data_assets", [])),
        "findings_count": len(findings),
        "category_breakdown": category_counts,
        "sensitivity_breakdown": level_counts,
        "regulatory_mappings": total_mappings,
        "compliance_gaps": len(gaps),
        "compliance_ratio": round(compliance_ratio, 3),
        "labels_applied": len(enforcements),
        "labels_successful": sum(1 for e in enforcements if e.get("success", False)),
    }

    # LLM enhancement: executive report
    reasoning_note = (
        f"Report: {stats['assets_scanned']} assets, "
        f"{stats['findings_count']} findings, "
        f"{stats['compliance_gaps']} gaps, "
        f"compliance={stats['compliance_ratio']:.1%}"
    )
    try:
        from .prompts import (
            SYSTEM_CLASSIFICATION_REPORT,
            ClassificationReportResult,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            ClassificationReportResult,
            await llm_structured(
                system_prompt=SYSTEM_CLASSIFICATION_REPORT,
                user_prompt=f"Classification stats:\n{context}",
                schema=ClassificationReportResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_classification",
            node="report",
        )
        reasoning_note = f"{llm_result.executive_summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_classification",
            node="report",
        )

    return {
        "stats": stats,
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }
