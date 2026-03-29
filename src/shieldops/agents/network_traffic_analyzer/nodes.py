"""Node implementations for the Network Traffic Analyzer Agent."""

from __future__ import annotations

import json as _json
import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.network_traffic_analyzer.models import (
    AnalysisStage,
    NetworkTrafficAnalyzerState,
)
from shieldops.agents.network_traffic_analyzer.prompts import (
    SYSTEM_ANALYZE_PROTOCOLS,
    SYSTEM_CLASSIFY_THREATS,
    SYSTEM_DETECT_ANOMALIES,
    SYSTEM_REPORT,
    AnomalyOutput,
    ProtocolOutput,
    ReportOutput,
    ThreatOutput,
)
from shieldops.agents.network_traffic_analyzer.tools import (
    NetworkTrafficAnalyzerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: NetworkTrafficAnalyzerToolkit | None = None


def set_toolkit(toolkit: NetworkTrafficAnalyzerToolkit) -> None:
    """Set the shared toolkit instance for all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> NetworkTrafficAnalyzerToolkit:
    if _toolkit is None:
        return NetworkTrafficAnalyzerToolkit()
    return _toolkit


async def ingest_flows(
    state: NetworkTrafficAnalyzerState,
) -> dict[str, Any]:
    """Ingest and normalize raw network flow records."""
    start = time.time()
    toolkit = _get_toolkit()

    flows = await toolkit.ingest_flows(state.raw_flows)

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "network_traffic.ingest_done",
        request_id=state.request_id,
        flows=len(flows),
    )

    return {
        "flows": flows,
        "stage": AnalysisStage.DETECT_ANOMALIES,
        "current_step": "ingest_flows",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Ingested {len(flows)} network flows",
        ],
        "session_start": (start if state.session_start == 0.0 else state.session_start),
        "stats": {**state.stats, "ingest_ms": elapsed},
    }


async def detect_anomalies(
    state: NetworkTrafficAnalyzerState,
) -> dict[str, Any]:
    """Detect anomalous patterns in network flows."""
    start = time.time()
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_anomalies(state.flows)

    # LLM enhancement
    try:
        flow_summary = {
            "total_flows": len(state.flows),
            "protocols": list({f.protocol.value for f in state.flows}),
            "unique_src_ips": len({f.src_ip for f in state.flows}),
            "unique_dst_ips": len({f.dst_ip for f in state.flows}),
            "total_bytes": sum(f.bytes_sent + f.bytes_received for f in state.flows),
            "detected_anomalies": [a.model_dump() for a in anomalies],
        }
        context = _json.dumps(flow_summary, default=str)
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT_ANOMALIES,
            user_prompt=(f"Analyze these network flows:\n{context}"),
            schema=AnomalyOutput,
        )
        if hasattr(llm_result, "description"):
            llm_desc = getattr(llm_result, "description", "")
            if llm_desc and anomalies:
                anomalies[0].description = f"{anomalies[0].description} | LLM: {llm_desc}"
        logger.info("llm_enhanced", node="detect_anomalies")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_anomalies",
        )

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "network_traffic.anomalies_done",
        request_id=state.request_id,
        anomalies=len(anomalies),
    )

    return {
        "anomalies": anomalies,
        "stage": AnalysisStage.CLASSIFY_THREATS,
        "current_step": "detect_anomalies",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Detected {len(anomalies)} anomalies across {len(state.flows)} flows",
        ],
        "stats": {
            **state.stats,
            "detect_ms": elapsed,
            "anomaly_count": len(anomalies),
        },
    }


async def classify_threats(
    state: NetworkTrafficAnalyzerState,
) -> dict[str, Any]:
    """Classify anomalies into actionable threats."""
    start = time.time()
    toolkit = _get_toolkit()

    threats = await toolkit.classify_threats(state.anomalies)

    # LLM enhancement
    for threat in threats:
        try:
            context = _json.dumps(
                threat.model_dump(),
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_CLASSIFY_THREATS,
                user_prompt=(f"Classify this threat:\n{context}"),
                schema=ThreatOutput,
            )
            llm_action = getattr(
                llm_result,
                "recommended_action",
                "",
            )
            if llm_action:
                threat.recommended_action = f"{threat.recommended_action} | LLM: {llm_action}"
            logger.info(
                "llm_enhanced",
                node="classify_threats",
                threat=threat.id,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="classify_threats",
                threat=threat.id,
            )

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "network_traffic.threats_done",
        request_id=state.request_id,
        threats=len(threats),
    )

    return {
        "threats": threats,
        "stage": AnalysisStage.ANALYZE_PROTOCOLS,
        "current_step": "classify_threats",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Classified {len(threats)} threats from {len(state.anomalies)} anomalies",
        ],
        "stats": {
            **state.stats,
            "classify_ms": elapsed,
            "threat_count": len(threats),
        },
    }


async def analyze_protocols(
    state: NetworkTrafficAnalyzerState,
) -> dict[str, Any]:
    """Analyze protocol-level traffic behavior."""
    start = time.time()
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_protocols(state.flows)

    # LLM enhancement
    for analysis in analyses:
        try:
            context = _json.dumps(
                analysis.model_dump(),
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_ANALYZE_PROTOCOLS,
                user_prompt=(f"Analyze this protocol:\n{context}"),
                schema=ProtocolOutput,
            )
            llm_findings = getattr(
                llm_result,
                "findings",
                [],
            )
            if llm_findings:
                analysis.findings.extend(llm_findings)
            logger.info(
                "llm_enhanced",
                node="analyze_protocols",
                protocol=analysis.protocol.value,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="analyze_protocols",
                protocol=analysis.protocol.value,
            )

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "network_traffic.protocols_done",
        request_id=state.request_id,
        protocols=len(analyses),
    )

    return {
        "protocol_analyses": analyses,
        "stage": AnalysisStage.CORRELATE,
        "current_step": "analyze_protocols",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Analyzed {len(analyses)} protocol types",
        ],
        "stats": {
            **state.stats,
            "protocol_ms": elapsed,
            "protocol_count": len(analyses),
        },
    }


async def correlate(
    state: NetworkTrafficAnalyzerState,
) -> dict[str, Any]:
    """Correlate anomalies, threats, and protocol findings."""
    start = time.time()

    correlations: list[dict[str, Any]] = []

    # Group threats by kill chain phase
    phase_map: dict[str, list[str]] = {}
    for t in state.threats:
        phase = t.kill_chain_phase
        if phase not in phase_map:
            phase_map[phase] = []
        phase_map[phase].append(t.threat_name)

    if len(phase_map) > 1:
        correlations.append(
            {
                "id": f"corr-{uuid4().hex[:12]}",
                "type": "kill_chain_progression",
                "phases": phase_map,
                "description": (
                    f"Multi-phase attack detected across {len(phase_map)} kill chain phases"
                ),
            }
        )

    # Cross-reference source IPs across anomalies
    ip_anomalies: dict[str, list[str]] = {}
    for a in state.anomalies:
        for ip in a.source_ips:
            if ip not in ip_anomalies:
                ip_anomalies[ip] = []
            ip_anomalies[ip].append(a.anomaly_type.value)

    multi_anomaly_ips = {ip: types for ip, types in ip_anomalies.items() if len(types) > 1}
    if multi_anomaly_ips:
        correlations.append(
            {
                "id": f"corr-{uuid4().hex[:12]}",
                "type": "multi_anomaly_source",
                "sources": multi_anomaly_ips,
                "description": (f"{len(multi_anomaly_ips)} IPs involved in multiple anomaly types"),
            }
        )

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "network_traffic.correlate_done",
        request_id=state.request_id,
        correlations=len(correlations),
    )

    return {
        "correlations": correlations,
        "stage": AnalysisStage.REPORT,
        "current_step": "correlate",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Produced {len(correlations)} correlations",
        ],
        "stats": {
            **state.stats,
            "correlate_ms": elapsed,
            "correlation_count": len(correlations),
        },
    }


async def report(
    state: NetworkTrafficAnalyzerState,
) -> dict[str, Any]:
    """Generate final network traffic analysis report."""
    start = time.time()
    total_elapsed = int((time.time() - state.session_start) * 1000)

    critical = sum(1 for t in state.threats if t.severity == "critical")
    high = sum(1 for t in state.threats if t.severity == "high")

    report_stats: dict[str, Any] = {
        "total_flows": len(state.flows),
        "anomalies_detected": len(state.anomalies),
        "threats_classified": len(state.threats),
        "protocols_analyzed": len(state.protocol_analyses),
        "correlations": len(state.correlations),
        "critical_threats": critical,
        "high_threats": high,
    }

    # LLM-generated executive summary
    try:
        context = _json.dumps(
            {
                **report_stats,
                "threats": [t.model_dump() for t in state.threats],
                "anomalies": [a.model_dump() for a in state.anomalies],
                "correlations": state.correlations,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate traffic analysis report:\n{context}"),
            schema=ReportOutput,
        )
        if hasattr(llm_result, "executive_summary"):
            report_stats["executive_summary"] = getattr(
                llm_result,
                "executive_summary",
                "",
            )
            report_stats["key_findings"] = getattr(
                llm_result,
                "key_findings",
                [],
            )
            report_stats["risk_assessment"] = getattr(
                llm_result,
                "risk_assessment",
                "",
            )
            report_stats["recommendations"] = getattr(
                llm_result,
                "recommendations",
                [],
            )
        logger.info("llm_enhanced", node="report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)

    return {
        "stage": AnalysisStage.REPORT,
        "current_step": "report",
        "stats": {
            **state.stats,
            **report_stats,
            "report_ms": elapsed,
        },
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report: {len(state.threats)} threats "
            f"({critical} critical, {high} high), "
            f"{len(state.correlations)} correlations",
        ],
        "session_duration_ms": total_elapsed,
    }
