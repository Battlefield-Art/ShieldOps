"""Shadow API Detector Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    EndpointProfile,
    ReasoningStep,
    SADStage,
    ShadowAPI,
    TrafficRecord,
)
from .tools import ShadowAPIDetectorToolkit

logger = structlog.get_logger()

_toolkit: ShadowAPIDetectorToolkit | None = None  # noqa: PLW0603


def _get_toolkit() -> ShadowAPIDetectorToolkit:
    assert _toolkit is not None, "Toolkit not initialised"
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Traffic
# ------------------------------------------------------------------


async def discover_traffic(
    state: dict[str, Any],
    toolkit: ShadowAPIDetectorToolkit,
) -> dict[str, Any]:
    """Discover API traffic from gateways and proxies."""
    logger.info("sad.node.discover_traffic")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    records = await toolkit.discover_traffic(tenant_id)
    data = [r.model_dump() for r in records]

    note = f"Discovered {len(records)} traffic records"

    return {
        "stage": SADStage.ANALYZE_ENDPOINTS.value,
        "traffic_records": data,
        "total_endpoints_scanned": len(records),
        "current_step": "discover_traffic",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="discover_traffic",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Analyze Endpoints
# ------------------------------------------------------------------


async def analyze_endpoints(
    state: dict[str, Any],
    toolkit: ShadowAPIDetectorToolkit,
) -> dict[str, Any]:
    """Analyze traffic to build endpoint profiles."""
    logger.info("sad.node.analyze_endpoints")
    state = _to_dict(state)

    records = [TrafficRecord(**r) for r in state.get("traffic_records", [])]
    profiles = await toolkit.analyze_endpoints(records)
    data = [p.model_dump() for p in profiles]

    note = f"Profiled {len(profiles)} unique endpoints"

    try:
        from .prompts import SYSTEM_ANALYZE, TrafficInsight

        ctx = json.dumps(
            {
                "endpoints": [
                    {
                        "method": p.method,
                        "path": p.path,
                        "requests": p.request_count,
                        "auth": p.has_auth,
                        "documented": p.documented,
                    }
                    for p in profiles[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            TrafficInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"API endpoints:\n{ctx}",
                schema=TrafficInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sad",
            node="analyze_endpoints",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sad",
            node="analyze_endpoints",
        )

    return {
        "stage": SADStage.DETECT_SHADOW.value,
        "endpoint_profiles": data,
        "current_step": "analyze_endpoints",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_endpoints",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Shadow APIs
# ------------------------------------------------------------------


async def detect_shadow(
    state: dict[str, Any],
    toolkit: ShadowAPIDetectorToolkit,
) -> dict[str, Any]:
    """Detect shadow and undocumented APIs."""
    logger.info("sad.node.detect_shadow")
    state = _to_dict(state)

    profiles = [EndpointProfile(**p) for p in state.get("endpoint_profiles", [])]
    shadows = await toolkit.detect_shadow_apis(profiles)
    data = [s.model_dump() for s in shadows]

    note = f"Detected {len(shadows)} shadow APIs from {len(profiles)} endpoints"

    return {
        "stage": SADStage.CLASSIFY_RISK.value,
        "shadow_apis": data,
        "shadow_apis_found": len(shadows),
        "current_step": "detect_shadow",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_shadow",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Classify Risk
# ------------------------------------------------------------------


async def classify_risk(
    state: dict[str, Any],
    toolkit: ShadowAPIDetectorToolkit,
) -> dict[str, Any]:
    """Classify risk for each shadow API."""
    logger.info("sad.node.classify_risk")
    state = _to_dict(state)

    shadows = [ShadowAPI(**s) for s in state.get("shadow_apis", [])]
    classifications = await toolkit.classify_risk(shadows)
    data = [c.model_dump() for c in classifications]

    critical = sum(1 for c in classifications if c.risk_level.value == "critical")
    note = f"Classified {len(classifications)} APIs, {critical} critical"

    return {
        "stage": SADStage.DOCUMENT.value,
        "risk_classifications": data,
        "current_step": "classify_risk",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="classify_risk",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Auto-Document
# ------------------------------------------------------------------


async def auto_document(
    state: dict[str, Any],
    toolkit: ShadowAPIDetectorToolkit,
) -> dict[str, Any]:
    """Auto-generate documentation for shadow APIs."""
    logger.info("sad.node.auto_document")
    state = _to_dict(state)

    shadows = [ShadowAPI(**s) for s in state.get("shadow_apis", [])]
    docs = await toolkit.auto_document(shadows)
    data = [d.model_dump() for d in docs]

    note = f"Generated documentation for {len(docs)} shadow APIs"

    return {
        "stage": SADStage.REPORT.value,
        "documentation_entries": data,
        "current_step": "auto_document",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="auto_document",
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
    toolkit: ShadowAPIDetectorToolkit,
) -> dict[str, Any]:
    """Compile the final shadow API detection report."""
    logger.info("sad.node.report")
    state = _to_dict(state)

    total_scanned = state.get("total_endpoints_scanned", 0)
    shadow_count = state.get("shadow_apis_found", 0)
    class_count = len(state.get("risk_classifications", []))
    doc_count = len(state.get("documentation_entries", []))

    lines = [
        "# Shadow API Detection Report",
        "",
        f"**Endpoints scanned:** {total_scanned}",
        f"**Shadow APIs found:** {shadow_count}",
        f"**Risk classifications:** {class_count}",
        f"**Auto-documented:** {doc_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_scanned": total_scanned,
                "shadows": shadow_count,
                "classifications": class_count,
                "documented": doc_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Shadow API report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sad",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sad",
            node="report",
        )

    return {
        "stage": SADStage.REPORT.value,
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
