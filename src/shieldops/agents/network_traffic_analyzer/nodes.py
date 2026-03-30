"""Network Traffic Analyzer Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    NetworkFlow,
    NTAStage,
    ThreatClassification,
    TrafficAnomaly,
)
from .tools import NetworkTrafficAnalyzerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def capture_flows(
    state: dict[str, Any],
    toolkit: NetworkTrafficAnalyzerToolkit,
) -> dict[str, Any]:
    """Capture and normalize raw network flows."""
    logger.info("nta.node.capture_flows")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    raw_flows = state.get("raw_flows", [])
    session_start = time.time()

    flows = await toolkit.capture_flows(
        tenant_id=tenant_id,
        raw_flows=raw_flows,
    )
    flow_dicts = [f.model_dump() for f in flows]

    return {
        "flows": flow_dicts,
        "stage": NTAStage.ANALYZE_PATTERNS.value,
        "session_start": session_start,
        "current_step": "capture_flows",
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Captured {len(flows)} network flows"]
        ),
    }


async def analyze_patterns(
    state: dict[str, Any],
    toolkit: NetworkTrafficAnalyzerToolkit,
) -> dict[str, Any]:
    """Analyze traffic patterns from captured flows."""
    logger.info("nta.node.analyze_patterns")
    state = _to_dict(state)
    raw_flows = state.get("flows", [])

    flows = [NetworkFlow(**f) if isinstance(f, dict) else f for f in raw_flows]
    patterns = await toolkit.analyze_patterns(flows)
    pattern_dicts = [p.model_dump() for p in patterns]

    reasoning = f"Analyzed {len(patterns)} traffic patterns"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_ANALYZE_PATTERNS,
            PatternAnalysisOutput,
        )

        context = json.dumps(
            {
                "flow_count": len(flows),
                "patterns": pattern_dicts[:10],
                "total_bytes": sum(f.bytes_sent + f.bytes_received for f in flows),
                "unique_src": len(
                    {f.src_ip for f in flows},
                ),
                "unique_dst": len(
                    {f.dst_ip for f in flows},
                ),
            },
            default=str,
        )
        llm_result = cast(
            PatternAnalysisOutput,
            await llm_structured(
                system_prompt=(SYSTEM_ANALYZE_PATTERNS),
                user_prompt=(f"Traffic patterns:\n{context}"),
                schema=PatternAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="nta",
            node="analyze_patterns",
        )
        reasoning = f"{llm_result.summary} [risk={llm_result.risk_level}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="nta",
            node="analyze_patterns",
        )

    return {
        "patterns": pattern_dicts,
        "stage": NTAStage.DETECT_ANOMALIES.value,
        "current_step": "analyze_patterns",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: NetworkTrafficAnalyzerToolkit,
) -> dict[str, Any]:
    """Detect anomalies in network traffic."""
    logger.info("nta.node.detect_anomalies")
    state = _to_dict(state)
    raw_flows = state.get("flows", [])
    raw_patterns = state.get("patterns", [])

    flows = [NetworkFlow(**f) if isinstance(f, dict) else f for f in raw_flows]
    from .models import TrafficPattern

    patterns = [TrafficPattern(**p) if isinstance(p, dict) else p for p in raw_patterns]

    anomalies = await toolkit.detect_anomalies(
        flows,
        patterns,
    )
    anomaly_dicts = [a.model_dump() for a in anomalies]

    reasoning = f"Detected {len(anomalies)} anomalies"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_DETECT_ANOMALIES,
            AnomalyDetectionOutput,
        )

        context = json.dumps(
            {
                "flow_count": len(flows),
                "anomalies": anomaly_dicts[:10],
                "unique_src": len(
                    {f.src_ip for f in flows},
                ),
                "total_bytes": sum(f.bytes_sent for f in flows),
            },
            default=str,
        )
        llm_result = cast(
            AnomalyDetectionOutput,
            await llm_structured(
                system_prompt=(SYSTEM_DETECT_ANOMALIES),
                user_prompt=(f"Network anomalies:\n{context}"),
                schema=AnomalyDetectionOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="nta",
            node="detect_anomalies",
        )
        reasoning = f"{llm_result.description} [severity={llm_result.severity}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="nta",
            node="detect_anomalies",
        )

    return {
        "anomalies": anomaly_dicts,
        "stage": NTAStage.CLASSIFY_THREATS.value,
        "current_step": "detect_anomalies",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def classify_threats(
    state: dict[str, Any],
    toolkit: NetworkTrafficAnalyzerToolkit,
) -> dict[str, Any]:
    """Classify anomalies into threat categories."""
    logger.info("nta.node.classify_threats")
    state = _to_dict(state)
    raw_anomalies = state.get("anomalies", [])

    anomalies = [TrafficAnomaly(**a) if isinstance(a, dict) else a for a in raw_anomalies]

    threats = await toolkit.classify_threats(
        anomalies,
    )
    threat_dicts = [t.model_dump() for t in threats]

    reasoning = f"Classified {len(threats)} threats from {len(anomalies)} anomalies"

    # LLM enhancement per threat
    try:
        from .prompts import (
            SYSTEM_CLASSIFY_THREATS,
            ThreatClassificationOutput,
        )

        for i, threat in enumerate(threats):
            context = json.dumps(
                threat.model_dump(),
                default=str,
            )
            llm_result = cast(
                ThreatClassificationOutput,
                await llm_structured(
                    system_prompt=(SYSTEM_CLASSIFY_THREATS),
                    user_prompt=(f"Classify threat:\n{context}"),
                    schema=(ThreatClassificationOutput),
                ),
            )
            threat_dicts[i]["llm_reasoning"] = llm_result.reasoning
            if llm_result.confidence > 0.5:
                threat_dicts[i]["confidence"] = llm_result.confidence
                threat_dicts[i]["recommended_action"] = llm_result.recommended_action

        logger.info(
            "llm_enhanced",
            agent="nta",
            node="classify_threats",
        )
        severities = [t.get("severity", "") for t in threat_dicts]
        reasoning = f"LLM classified {len(threat_dicts)} threats: {', '.join(severities)}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="nta",
            node="classify_threats",
        )

    return {
        "threats": threat_dicts,
        "stage": NTAStage.ENFORCE_POLICIES.value,
        "current_step": "classify_threats",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def enforce_policies(
    state: dict[str, Any],
    toolkit: NetworkTrafficAnalyzerToolkit,
) -> dict[str, Any]:
    """Enforce policies based on classified threats."""
    logger.info("nta.node.enforce_policies")
    state = _to_dict(state)
    raw_threats = state.get("threats", [])

    threats = [ThreatClassification(**t) if isinstance(t, dict) else t for t in raw_threats]

    enforcements = await toolkit.enforce_policies(
        threats,
    )
    enforcement_dicts = [e.model_dump() for e in enforcements]

    reasoning = f"Generated {len(enforcements)} policy enforcements"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_ENFORCE_POLICIES,
            PolicyEnforcementOutput,
        )

        context = json.dumps(
            {
                "threats": [t.model_dump() for t in threats],
                "enforcements": enforcement_dicts,
            },
            default=str,
        )
        llm_result = cast(
            PolicyEnforcementOutput,
            await llm_structured(
                system_prompt=(SYSTEM_ENFORCE_POLICIES),
                user_prompt=(f"Policy enforcement:\n{context}"),
                schema=PolicyEnforcementOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="nta",
            node="enforce_policies",
        )
        reasoning = f"{llm_result.justification} [priority={llm_result.priority}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="nta",
            node="enforce_policies",
        )

    return {
        "enforcements": enforcement_dicts,
        "stage": NTAStage.REPORT.value,
        "current_step": "enforce_policies",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: NetworkTrafficAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate final network traffic analysis report."""
    logger.info("nta.node.generate_report")
    state = _to_dict(state)

    flows = state.get("flows", [])
    patterns = state.get("patterns", [])
    anomalies = state.get("anomalies", [])
    threats = state.get("threats", [])
    enforcements = state.get("enforcements", [])
    session_start = state.get(
        "session_start",
        time.time(),
    )

    duration_ms = (time.time() - session_start) * 1000

    critical = sum(1 for t in threats if t.get("severity") == "critical")
    high = sum(1 for t in threats if t.get("severity") == "high")

    stats: dict[str, Any] = {
        "total_flows": len(flows),
        "patterns_found": len(patterns),
        "anomalies_detected": len(anomalies),
        "threats_classified": len(threats),
        "policies_enforced": len(enforcements),
        "critical_threats": critical,
        "high_threats": high,
        "analysis_duration_ms": round(
            duration_ms,
            2,
        ),
    }

    # LLM report generation
    try:
        from .prompts import (
            SYSTEM_REPORT,
            ReportOutput,
        )

        context = json.dumps(
            {
                **stats,
                "threats": threats[:10],
                "anomalies": anomalies[:10],
                "enforcements": enforcements[:10],
            },
            default=str,
        )
        llm_result = cast(
            ReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Generate report:\n{context}"),
                schema=ReportOutput,
            ),
        )
        stats["executive_summary"] = llm_result.executive_summary
        stats["key_findings"] = llm_result.key_findings
        stats["risk_assessment"] = llm_result.risk_assessment
        stats["recommendations"] = llm_result.recommendations
        logger.info(
            "llm_enhanced",
            agent="nta",
            node="generate_report",
        )
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="nta",
            node="generate_report",
        )

    return {
        "stats": stats,
        "stage": NTAStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": (
            state.get("reasoning_chain", [])
            + [
                f"Report: {len(flows)} flows, "
                f"{len(threats)} threats "
                f"({critical} critical, "
                f"{high} high), "
                f"{len(enforcements)} enforcements"
            ]
        ),
    }
