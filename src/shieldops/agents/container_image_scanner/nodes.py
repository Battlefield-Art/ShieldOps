"""Container Image Scanner Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import ImageLayer, ImageScanStage, ImageVuln
from .tools import ContainerImageScannerToolkit

logger = structlog.get_logger()

_toolkit: ContainerImageScannerToolkit | None = None


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_images(
    state: dict[str, Any],
    toolkit: ContainerImageScannerToolkit,
) -> dict[str, Any]:
    """Discover container images."""
    logger.info("container_scanner.node.discover_images")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    image_refs = state.get("image_refs", [])
    session_start = time.time()

    images = await toolkit.discover_images(
        tenant_id=tenant_id,
        image_refs=image_refs,
    )
    return {
        "discovered_images": images,
        "total_images": len(images),
        "stage": ImageScanStage.DISCOVER_IMAGES.value,
        "session_start": session_start,
        "current_step": "discover_images",
        "reasoning_chain": state.get("reasoning_chain", []) + [f"Discovered {len(images)} images"],
    }


async def analyze_layers(
    state: dict[str, Any],
    toolkit: ContainerImageScannerToolkit,
) -> dict[str, Any]:
    """Analyze image layers."""
    logger.info("container_scanner.node.analyze_layers")
    state = _to_dict(state)
    images = state.get("discovered_images", [])

    layers = await toolkit.analyze_layers(images)
    layer_dicts = [layer.model_dump() for layer in layers]
    reasoning = f"Analyzed {len(layers)} layers"

    try:
        from .prompts import (
            SYSTEM_LAYER_ANALYSIS,
            LayerAnalysisOutput,
        )

        context = json.dumps(
            {"layers": layer_dicts[:15]},
            default=str,
        )
        llm_result = cast(
            LayerAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_LAYER_ANALYSIS,
                user_prompt=f"Layer data:\n{context}",
                schema=LayerAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="container_scanner",
            node="analyze_layers",
        )
        reasoning = llm_result.summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="container_scanner",
            node="analyze_layers",
        )

    return {
        "layers": layer_dicts,
        "stage": ImageScanStage.ANALYZE_LAYERS.value,
        "current_step": "analyze_layers",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def scan_vulnerabilities(
    state: dict[str, Any],
    toolkit: ContainerImageScannerToolkit,
) -> dict[str, Any]:
    """Scan for image vulnerabilities."""
    logger.info("container_scanner.node.scan_vulns")
    state = _to_dict(state)
    images = state.get("discovered_images", [])
    raw_layers = state.get("layers", [])
    layers = [ImageLayer(**item) if isinstance(item, dict) else item for item in raw_layers]

    vulns = await toolkit.scan_vulnerabilities(images, layers)
    vuln_dicts = [v.model_dump() for v in vulns]

    return {
        "vulnerabilities": vuln_dicts,
        "stage": ImageScanStage.SCAN_VULNERABILITIES.value,
        "current_step": "scan_vulnerabilities",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Found {len(vulns)} vulnerabilities"],
    }


async def check_compliance(
    state: dict[str, Any],
    toolkit: ContainerImageScannerToolkit,
) -> dict[str, Any]:
    """Check compliance benchmarks."""
    logger.info("container_scanner.node.check_compliance")
    state = _to_dict(state)
    images = state.get("discovered_images", [])
    raw_layers = state.get("layers", [])
    layers = [ImageLayer(**item) if isinstance(item, dict) else item for item in raw_layers]

    results = await toolkit.check_compliance(images, layers)
    reasoning = f"Compliance: {len(results)} checks"

    try:
        from .prompts import (
            SYSTEM_COMPLIANCE_ANALYSIS,
            ComplianceAnalysisOutput,
        )

        context = json.dumps(
            {"results": results[:15]},
            default=str,
        )
        llm_result = cast(
            ComplianceAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_COMPLIANCE_ANALYSIS,
                user_prompt=f"Compliance data:\n{context}",
                schema=ComplianceAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="container_scanner",
            node="check_compliance",
        )
        reasoning = llm_result.summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="container_scanner",
            node="check_compliance",
        )

    return {
        "compliance_results": results,
        "stage": ImageScanStage.CHECK_COMPLIANCE.value,
        "current_step": "check_compliance",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def prioritize_findings(
    state: dict[str, Any],
    toolkit: ContainerImageScannerToolkit,
) -> dict[str, Any]:
    """Prioritize all container findings."""
    logger.info("container_scanner.node.prioritize")
    state = _to_dict(state)
    raw_vulns = state.get("vulnerabilities", [])
    vulns = [ImageVuln(**v) if isinstance(v, dict) else v for v in raw_vulns]
    compliance = state.get("compliance_results", [])

    prioritized = toolkit.prioritize(vulns, compliance)
    total = len(prioritized)
    critical = sum(1 for p in prioritized if p.get("severity") == "critical")

    return {
        "prioritized": prioritized,
        "total_findings": total,
        "critical_count": critical,
        "stage": ImageScanStage.PRIORITIZE.value,
        "current_step": "prioritize",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Prioritized {total}: {critical} critical"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: ContainerImageScannerToolkit,
) -> dict[str, Any]:
    """Generate final container scan report."""
    logger.info("container_scanner.node.report")
    state = _to_dict(state)
    prioritized = state.get("prioritized", [])
    session_start = state.get("session_start", time.time())

    duration_ms = (time.time() - session_start) * 1000
    sev_dist: dict[str, int] = {}
    for p in prioritized:
        sev = p.get("severity", "medium")
        sev_dist[sev] = sev_dist.get(sev, 0) + 1

    stats = {
        "total_findings": len(prioritized),
        "critical_count": sev_dist.get("critical", 0),
        "total_images": state.get("total_images", 0),
        "severity_distribution": sev_dist,
        "scan_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "total_findings": len(prioritized),
        "critical_count": sev_dist.get("critical", 0),
        "stage": ImageScanStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Report: {len(prioritized)} findings, {sev_dist.get('critical', 0)} critical"],
    }
