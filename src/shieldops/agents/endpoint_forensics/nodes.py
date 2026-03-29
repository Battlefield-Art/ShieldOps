"""Endpoint Forensics Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import ForensicsStage
from .prompts import (
    SYSTEM_MEMORY,
    SYSTEM_REPORT,
    ForensicsReportResult,
    MemoryAnalysisResult,
)
from .tools import EndpointForensicsToolkit

logger = structlog.get_logger()

_toolkit: EndpointForensicsToolkit | None = None


def set_toolkit(tk: EndpointForensicsToolkit) -> None:
    global _toolkit
    _toolkit = tk


async def collect_artifacts(
    state: dict[str, Any], toolkit: EndpointForensicsToolkit
) -> dict[str, Any]:
    """Collect forensic artifacts."""
    logger.info("forensics.node.collect")
    eid = state.get("endpoint_id", "")
    case_id = state.get("case_id", "")
    artifacts = await toolkit.collect_artifacts(eid, case_id)
    return {
        "stage": ForensicsStage.ANALYZE_MEMORY.value,
        "artifacts": artifacts,
        "total_artifacts": len(artifacts),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(artifacts)} artifacts from {eid}"],
    }


async def analyze_memory(
    state: dict[str, Any], toolkit: EndpointForensicsToolkit
) -> dict[str, Any]:
    """Analyze memory dump."""
    logger.info("forensics.node.memory")
    artifacts = state.get("artifacts", [])
    findings, injected = await toolkit.analyze_memory(artifacts)

    reasoning = f"Memory analysis: {len(findings)} findings, {injected} injected processes"

    if findings:
        try:
            ctx = json.dumps(
                {"findings": findings[:10], "injected": injected},
                default=str,
            )
            result = cast(
                MemoryAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_MEMORY,
                    user_prompt=f"Memory analysis:\n{ctx}",
                    schema=MemoryAnalysisResult,
                ),
            )
            reasoning = f"{result.summary}. {reasoning}"
        except Exception:
            logger.debug("llm_fallback", agent="forensics", node="memory")

    return {
        "stage": ForensicsStage.INVESTIGATE_PROCESSES.value,
        "memory_findings": findings,
        "injected_processes": injected,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def investigate_processes(
    state: dict[str, Any], toolkit: EndpointForensicsToolkit
) -> dict[str, Any]:
    """Investigate suspicious processes."""
    logger.info("forensics.node.processes")
    artifacts = state.get("artifacts", [])
    suspicious, tree = await toolkit.investigate_processes(artifacts)
    return {
        "stage": ForensicsStage.CARVE_FILES.value,
        "suspicious_processes": suspicious,
        "process_tree": tree,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Found {len(suspicious)} suspicious processes"],
    }


async def carve_files(state: dict[str, Any], toolkit: EndpointForensicsToolkit) -> dict[str, Any]:
    """Carve deleted files."""
    logger.info("forensics.node.carve")
    artifacts = state.get("artifacts", [])
    carved, malware = await toolkit.carve_files(artifacts)
    return {
        "stage": ForensicsStage.RECONSTRUCT_TIMELINE.value,
        "carved_files": carved,
        "malware_found": malware,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Carved {len(carved)} files, {malware} malware"],
    }


async def reconstruct_timeline(
    state: dict[str, Any], toolkit: EndpointForensicsToolkit
) -> dict[str, Any]:
    """Reconstruct attack timeline."""
    logger.info("forensics.node.timeline")
    memory = state.get("memory_findings", [])
    procs = state.get("suspicious_processes", [])
    files = state.get("carved_files", [])
    timeline = await toolkit.reconstruct_timeline(memory, procs, files)
    return {
        "stage": ForensicsStage.REPORT.value,
        "timeline": timeline,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Reconstructed timeline with {len(timeline)} events"],
    }


async def generate_report(
    state: dict[str, Any], toolkit: EndpointForensicsToolkit
) -> dict[str, Any]:
    """Generate forensics report."""
    logger.info("forensics.node.report")
    artifacts = state.get("total_artifacts", 0)
    injected = state.get("injected_processes", 0)
    malware = state.get("malware_found", 0)
    timeline_count = len(state.get("timeline", []))

    iocs: list[str] = []
    for f in state.get("memory_findings", []):
        iocs.extend(f.get("indicators", []))
    for f in state.get("carved_files", []):
        if f.get("is_malware"):
            iocs.append(f.get("hash_sha256", ""))

    summary = (
        f"Forensics: {artifacts} artifacts, {injected} injected procs, "
        f"{malware} malware, {timeline_count} timeline events, "
        f"{len(iocs)} IOCs"
    )

    try:
        ctx = json.dumps(
            {
                "artifacts": artifacts,
                "injected_processes": injected,
                "malware_found": malware,
                "timeline_events": timeline_count,
                "iocs": iocs[:20],
                "findings": state.get("memory_findings", [])[:5],
            },
            default=str,
        )
        result = cast(
            ForensicsReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Forensics report:\n{ctx}",
                schema=ForensicsReportResult,
            ),
        )
        summary = result.executive_summary
        iocs = result.iocs
    except Exception:
        logger.debug("llm_fallback", agent="forensics", node="report")

    return {
        "stage": ForensicsStage.REPORT.value,
        "summary": summary,
        "ioc_list": iocs,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
