"""SAST Scanner Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import SASTStage, ScanFinding
from .tools import SASTScannerToolkit

logger = structlog.get_logger()

_toolkit: SASTScannerToolkit | None = None


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_files(
    state: dict[str, Any],
    toolkit: SASTScannerToolkit,
) -> dict[str, Any]:
    """Discover source files to scan."""
    logger.info("sast_scanner.node.discover_files")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    targets = state.get("scan_targets", [])
    session_start = time.time()

    files = await toolkit.discover_files(
        tenant_id=tenant_id,
        targets=targets,
    )
    return {
        "discovered_files": files,
        "total_files": len(files),
        "stage": SASTStage.DISCOVER_FILES.value,
        "session_start": session_start,
        "current_step": "discover_files",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(files)} files to scan"],
    }


async def parse_ast(
    state: dict[str, Any],
    toolkit: SASTScannerToolkit,
) -> dict[str, Any]:
    """Parse AST for source files."""
    logger.info("sast_scanner.node.parse_ast")
    state = _to_dict(state)
    files = state.get("discovered_files", [])

    ast_results = await toolkit.parse_ast(files)
    return {
        "ast_results": ast_results,
        "stage": SASTStage.PARSE_AST.value,
        "current_step": "parse_ast",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Parsed AST for {len(ast_results)} files"],
    }


async def scan_patterns(
    state: dict[str, Any],
    toolkit: SASTScannerToolkit,
) -> dict[str, Any]:
    """Scan for vulnerability patterns."""
    logger.info("sast_scanner.node.scan_patterns")
    state = _to_dict(state)
    targets = state.get("scan_targets", [])

    findings = await toolkit.scan_patterns(targets)
    finding_dicts = [f.model_dump() for f in findings]
    reasoning = f"Pattern scan: {len(findings)} findings"

    try:
        from .prompts import SYSTEM_AST_ANALYSIS, ASTAnalysisOutput

        context = json.dumps(
            {
                "finding_count": len(findings),
                "findings_sample": finding_dicts[:15],
            },
            default=str,
        )
        llm_result = cast(
            ASTAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_AST_ANALYSIS,
                user_prompt=f"SAST findings:\n{context}",
                schema=ASTAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sast_scanner",
            node="scan_patterns",
        )
        reasoning = f"{llm_result.summary} Logic flaws: {len(llm_result.logic_flaws)}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sast_scanner",
            node="scan_patterns",
        )

    return {
        "findings": finding_dicts,
        "stage": SASTStage.SCAN_PATTERNS.value,
        "current_step": "scan_patterns",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def analyze_dataflow(
    state: dict[str, Any],
    toolkit: SASTScannerToolkit,
) -> dict[str, Any]:
    """Analyze dataflow for taint propagation."""
    logger.info("sast_scanner.node.analyze_dataflow")
    state = _to_dict(state)
    targets = state.get("scan_targets", [])
    raw = state.get("findings", [])
    findings = [ScanFinding(**f) if isinstance(f, dict) else f for f in raw]

    enriched = await toolkit.analyze_dataflow(findings, targets)
    enriched_dicts = [f.model_dump() for f in enriched]

    return {
        "dataflow_findings": enriched_dicts,
        "stage": SASTStage.ANALYZE_DATAFLOW.value,
        "current_step": "analyze_dataflow",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Dataflow analysis on {len(enriched)} findings"],
    }


async def prioritize(
    state: dict[str, Any],
    toolkit: SASTScannerToolkit,
) -> dict[str, Any]:
    """Prioritize findings by severity."""
    logger.info("sast_scanner.node.prioritize")
    state = _to_dict(state)
    raw = state.get("dataflow_findings", []) or state.get(
        "findings",
        [],
    )
    findings = [ScanFinding(**f) if isinstance(f, dict) else f for f in raw]

    prioritized = toolkit.prioritize(findings)
    prioritized_dicts = [f.model_dump() for f in prioritized]
    total = len(prioritized)
    critical = sum(1 for f in prioritized if f.severity == "critical")
    reasoning = f"Prioritized {total}: {critical} critical"

    try:
        from .prompts import (
            SYSTEM_PRIORITIZATION,
            PrioritizationOutput,
        )

        context = json.dumps(
            {
                "total": total,
                "critical": critical,
                "top_findings": prioritized_dicts[:20],
            },
            default=str,
        )
        llm_result = cast(
            PrioritizationOutput,
            await llm_structured(
                system_prompt=SYSTEM_PRIORITIZATION,
                user_prompt=f"Prioritization:\n{context}",
                schema=PrioritizationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sast_scanner",
            node="prioritize",
        )
        reasoning = f"{llm_result.summary} {llm_result.risk_narrative[:80]}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sast_scanner",
            node="prioritize",
        )

    return {
        "prioritized": prioritized_dicts,
        "total_findings": total,
        "critical_count": critical,
        "stage": SASTStage.PRIORITIZE.value,
        "current_step": "prioritize",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: SASTScannerToolkit,
) -> dict[str, Any]:
    """Generate final scan report."""
    logger.info("sast_scanner.node.report")
    state = _to_dict(state)
    prioritized = state.get("prioritized", [])
    session_start = state.get("session_start", time.time())

    sev_dist: dict[str, int] = {}
    for p in prioritized:
        sev = p.get("severity", "medium")
        sev_dist[sev] = sev_dist.get(sev, 0) + 1

    duration_ms = (time.time() - session_start) * 1000
    stats = {
        "total_findings": len(prioritized),
        "critical_count": sev_dist.get("critical", 0),
        "high_count": sev_dist.get("high", 0),
        "severity_distribution": sev_dist,
        "scan_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "total_findings": len(prioritized),
        "critical_count": sev_dist.get("critical", 0),
        "stage": SASTStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Report: {len(prioritized)} findings, {sev_dist.get('critical', 0)} critical"],
    }
