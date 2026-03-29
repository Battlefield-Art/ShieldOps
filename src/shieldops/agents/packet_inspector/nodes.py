"""Packet Inspector Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    InspectionStage,
    PacketCapture,
    PayloadAnalysis,
    TLSCertCheck,
)
from .tools import PacketInspectorToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def capture_packets(
    state: dict[str, Any],
    toolkit: PacketInspectorToolkit,
) -> dict[str, Any]:
    """Capture and register packets for inspection."""
    logger.info("packet_inspector.node.capture_packets")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    packets_raw = state.get("packets", [])
    session_start = time.time()

    packets = await toolkit.capture_packets(
        tenant_id=tenant_id,
        packets=packets_raw,
    )
    packet_dicts = [p.model_dump() for p in packets]

    return {
        "packets": packet_dicts,
        "packets_inspected": len(packet_dicts),
        "stage": InspectionStage.CAPTURE_PACKETS.value,
        "session_start": session_start,
        "current_step": "capture_packets",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Captured {len(packets)} packets for inspection"],
    }


async def analyze_payloads(
    state: dict[str, Any],
    toolkit: PacketInspectorToolkit,
) -> dict[str, Any]:
    """Analyze packet payloads for suspicious content."""
    logger.info("packet_inspector.node.analyze_payloads")
    state = _to_dict(state)
    raw_packets = state.get("packets", [])

    packets = [PacketCapture(**p) if isinstance(p, dict) else p for p in raw_packets]

    analyses = await toolkit.analyze_payloads(packets)
    analysis_dicts = [a.model_dump() for a in analyses]

    reasoning_note = f"Analyzed {len(analyses)} packet payloads"

    # LLM enhancement: deeper payload analysis
    try:
        from .prompts import (
            SYSTEM_PAYLOAD_ANALYSIS,
            PayloadAnalysisOutput,
        )

        suspicious_count = sum(len(a.suspicious_patterns) for a in analyses)
        avg_entropy = sum(a.payload_entropy for a in analyses) / max(len(analyses), 1)
        context = json.dumps(
            {
                "packet_count": len(analyses),
                "analyses": analysis_dicts[:10],
                "total_suspicious": suspicious_count,
                "avg_entropy": round(avg_entropy, 4),
                "encrypted_count": sum(1 for a in analyses if a.is_encrypted),
            },
            default=str,
        )
        llm_result = cast(
            PayloadAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_PAYLOAD_ANALYSIS,
                user_prompt=(f"Payload analysis data:\n{context}"),
                schema=PayloadAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="packet_inspector",
            node="analyze_payloads",
        )
        reasoning_note = (
            f"{llm_result.summary} "
            f"[risk={llm_result.risk_level}, "
            f"exfil={llm_result.exfiltration_likelihood:.1%}]"
        )
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="packet_inspector",
            node="analyze_payloads",
        )

    return {
        "payload_analyses": analysis_dicts,
        "stage": InspectionStage.ANALYZE_PAYLOAD.value,
        "current_step": "analyze_payloads",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def validate_tls(
    state: dict[str, Any],
    toolkit: PacketInspectorToolkit,
) -> dict[str, Any]:
    """Validate TLS certificates and cipher suites."""
    logger.info("packet_inspector.node.validate_tls")
    state = _to_dict(state)
    raw_packets = state.get("packets", [])

    packets = [PacketCapture(**p) if isinstance(p, dict) else p for p in raw_packets]

    tls_checks = await toolkit.validate_tls(packets)
    tls_dicts = [t.model_dump() for t in tls_checks]

    reasoning_note = f"Validated TLS on {len(tls_checks)} connections"

    # LLM enhancement: TLS analysis
    try:
        from .prompts import (
            SYSTEM_TLS_VALIDATION,
            TLSValidationOutput,
        )

        valid_count = sum(1 for t in tls_checks if t.status == "valid")
        context = json.dumps(
            {
                "check_count": len(tls_checks),
                "checks": tls_dicts[:10],
                "valid_count": valid_count,
                "weak_count": sum(1 for t in tls_checks if t.status == "weak_cipher"),
            },
            default=str,
        )
        llm_result = cast(
            TLSValidationOutput,
            await llm_structured(
                system_prompt=SYSTEM_TLS_VALIDATION,
                user_prompt=(f"TLS validation data:\n{context}"),
                schema=TLSValidationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="packet_inspector",
            node="validate_tls",
        )
        reasoning_note = (
            f"{llm_result.summary} "
            f"[risk={llm_result.risk_level}, "
            f"downgrade={llm_result.downgrade_risk}]"
        )
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="packet_inspector",
            node="validate_tls",
        )

    return {
        "tls_checks": tls_dicts,
        "stage": InspectionStage.VALIDATE_TLS.value,
        "current_step": "validate_tls",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_threats(
    state: dict[str, Any],
    toolkit: PacketInspectorToolkit,
) -> dict[str, Any]:
    """Detect threats from combined analysis."""
    logger.info("packet_inspector.node.detect_threats")
    state = _to_dict(state)
    raw_packets = state.get("packets", [])
    raw_analyses = state.get("payload_analyses", [])
    raw_tls = state.get("tls_checks", [])

    packets = [PacketCapture(**p) if isinstance(p, dict) else p for p in raw_packets]
    analyses = [PayloadAnalysis(**a) if isinstance(a, dict) else a for a in raw_analyses]
    tls_checks = [TLSCertCheck(**t) if isinstance(t, dict) else t for t in raw_tls]

    threats = await toolkit.detect_threats(packets, analyses, tls_checks)
    threat_dicts = [t.model_dump() for t in threats]

    reasoning_note = f"Detected {len(threats)} threats"

    # LLM enhancement: threat correlation
    try:
        from .prompts import (
            SYSTEM_THREAT_DETECTION,
            ThreatDetectionOutput,
        )

        context = json.dumps(
            {
                "packet_count": len(packets),
                "threats": threat_dicts[:10],
                "payload_risks": [a.risk for a in analyses],
                "tls_issues": [t.status for t in tls_checks if t.status != "valid"],
            },
            default=str,
        )
        llm_result = cast(
            ThreatDetectionOutput,
            await llm_structured(
                system_prompt=SYSTEM_THREAT_DETECTION,
                user_prompt=(f"Threat detection data:\n{context}"),
                schema=ThreatDetectionOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="packet_inspector",
            node="detect_threats",
        )

        # Merge LLM-discovered MITRE techniques
        if llm_result.mitre_techniques:
            for td in threat_dicts:
                existing = td.get("mitre_technique", "")
                if not existing and llm_result.mitre_techniques:
                    td["mitre_technique"] = llm_result.mitre_techniques[0]

        reasoning_note = f"{llm_result.summary} [confidence={llm_result.confidence:.1%}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="packet_inspector",
            node="detect_threats",
        )

    return {
        "threats_detected": threat_dicts,
        "threat_count": len(threat_dicts),
        "stage": InspectionStage.DETECT_THREATS.value,
        "current_step": "detect_threats",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: PacketInspectorToolkit,
) -> dict[str, Any]:
    """Generate final inspection report."""
    logger.info("packet_inspector.node.generate_report")
    state = _to_dict(state)

    packets = state.get("packets", [])
    analyses = state.get("payload_analyses", [])
    tls_checks = state.get("tls_checks", [])
    threats = state.get("threats_detected", [])
    session_start = state.get("session_start", time.time())

    duration_ms = (time.time() - session_start) * 1000

    # Payload entropy stats
    entropies = [a.get("payload_entropy", 0.0) for a in analyses]
    avg_entropy = sum(entropies) / max(len(entropies), 1)

    # TLS stats
    tls_total = max(len(tls_checks), 1)
    tls_valid = sum(1 for t in tls_checks if t.get("status") == "valid")
    tls_valid_pct = tls_valid / tls_total

    # Risk distribution
    risk_dist: dict[str, int] = {}
    for a in analyses:
        r = a.get("risk", "benign")
        risk_dist[r] = risk_dist.get(r, 0) + 1

    # Threat types
    threat_types: dict[str, int] = {}
    mitre_all: set[str] = set()
    for t in threats:
        tt = t.get("threat_type", "unknown")
        threat_types[tt] = threat_types.get(tt, 0) + 1
        mt = t.get("mitre_technique", "")
        if mt:
            mitre_all.add(mt)

    # Protocol distribution
    protocol_dist: dict[str, int] = {}
    for a in analyses:
        proto = a.get("protocol_decoded", "unknown")
        protocol_dist[proto] = protocol_dist.get(proto, 0) + 1

    stats = {
        "total_packets": len(packets),
        "total_threats": len(threats),
        "avg_payload_entropy": round(avg_entropy, 4),
        "tls_valid_pct": round(tls_valid_pct, 4),
        "risk_distribution": risk_dist,
        "threat_types": threat_types,
        "protocol_distribution": protocol_dist,
        "mitre_techniques": sorted(mitre_all),
        "analysis_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "avg_payload_entropy": round(avg_entropy, 4),
        "tls_valid_pct": round(tls_valid_pct, 4),
        "threat_count": len(threats),
        "stage": InspectionStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report: {len(packets)} packets, "
            f"{len(threats)} threats, "
            f"{len(mitre_all)} MITRE techniques, "
            f"TLS valid {tls_valid_pct:.0%}"
        ],
    }
