"""Node implementations for the Network Forensics Agent."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.network_forensics.models import (
    ForensicsStage,
    NetworkForensicsState,
)
from shieldops.agents.network_forensics.tools import (
    NetworkForensicsToolkit,
)

logger = structlog.get_logger()

_toolkit: NetworkForensicsToolkit | None = None


def set_toolkit(toolkit: NetworkForensicsToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> NetworkForensicsToolkit:
    if _toolkit is None:
        return NetworkForensicsToolkit()
    return _toolkit


async def ingest_capture(
    state: NetworkForensicsState,
) -> dict[str, Any]:
    """Ingest pcap/netflow captures."""
    start = time.time()
    toolkit = _get_toolkit()

    sources = state.captures or [{"type": "pcap", "file": "incident.pcap"}]
    evidence = await toolkit.ingest_captures(sources)

    return {
        "evidence": [e.model_dump() for e in evidence],
        "captures_ingested": len(evidence),
        "stage": ForensicsStage.RECONSTRUCT_SESSIONS,
        "current_step": "ingest_capture",
        "session_start": start,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Ingested {len(evidence)} evidence items",
        ],
    }


async def reconstruct_sessions(
    state: NetworkForensicsState,
) -> dict[str, Any]:
    """Reconstruct network sessions from evidence."""
    toolkit = _get_toolkit()

    from shieldops.agents.network_forensics.models import (
        ForensicEvidence,
    )

    evidence = [ForensicEvidence(**e) for e in state.evidence]
    sessions = await toolkit.reconstruct_sessions(evidence)

    total_bytes = sum(s.bytes_sent + s.bytes_received for s in sessions)
    total_pkts = sum(s.packet_count for s in sessions)

    return {
        "sessions": [s.model_dump() for s in sessions],
        "sessions_reconstructed": len(sessions),
        "total_bytes_analyzed": total_bytes,
        "total_packets_analyzed": total_pkts,
        "stage": ForensicsStage.BUILD_TIMELINE,
        "current_step": "reconstruct_sessions",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Reconstructed {len(sessions)} sessions, {total_bytes} bytes",
        ],
    }


async def build_timeline(
    state: NetworkForensicsState,
) -> dict[str, Any]:
    """Build chronological timeline."""
    toolkit = _get_toolkit()

    from shieldops.agents.network_forensics.models import (
        ForensicEvidence,
        NetworkSession,
    )

    sessions = [NetworkSession(**s) for s in state.sessions]
    evidence = [ForensicEvidence(**e) for e in state.evidence]
    timeline = await toolkit.build_timeline(
        sessions,
        evidence,
    )

    return {
        "timeline": [t.model_dump() for t in timeline],
        "stage": ForensicsStage.TRACE_LATERAL,
        "current_step": "build_timeline",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Built timeline with {len(timeline)} events",
        ],
    }


async def trace_lateral(
    state: NetworkForensicsState,
) -> dict[str, Any]:
    """Detect lateral movement."""
    toolkit = _get_toolkit()

    from shieldops.agents.network_forensics.models import (
        NetworkSession,
    )

    sessions = [NetworkSession(**s) for s in state.sessions]
    movements = await toolkit.trace_lateral_movement(
        sessions,
    )

    return {
        "lateral_movements": [m.model_dump() for m in movements],
        "stage": ForensicsStage.MAP_EXFILTRATION,
        "current_step": "trace_lateral",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Traced {len(movements)} lateral hops",
        ],
    }


async def map_exfiltration(
    state: NetworkForensicsState,
) -> dict[str, Any]:
    """Map data exfiltration paths."""
    toolkit = _get_toolkit()

    from shieldops.agents.network_forensics.models import (
        NetworkSession,
    )

    sessions = [NetworkSession(**s) for s in state.sessions]
    paths = await toolkit.map_exfiltration(sessions)

    exfil_bytes = sum(p.bytes_exfiltrated for p in paths)
    suspicious = sum(1 for p in paths if p.confidence > 0.5)

    return {
        "exfil_paths": [p.model_dump() for p in paths],
        "exfil_bytes_detected": exfil_bytes,
        "suspicious_sessions": suspicious,
        "stage": ForensicsStage.REPORT,
        "current_step": "map_exfiltration",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Mapped {len(paths)} exfil paths, {exfil_bytes} bytes",
        ],
    }


async def report(
    state: NetworkForensicsState,
) -> dict[str, Any]:
    """Generate final forensics report."""
    duration_ms = 0.0
    if state.session_start:
        duration_ms = (time.time() - state.session_start) * 1000

    return {
        "session_duration_ms": duration_ms,
        "current_step": "complete",
        "stage": ForensicsStage.REPORT,
        "stats": {
            "captures_ingested": state.captures_ingested,
            "sessions_reconstructed": (state.sessions_reconstructed),
            "timeline_events": len(state.timeline),
            "lateral_hops": len(state.lateral_movements),
            "exfil_paths": len(state.exfil_paths),
            "exfil_bytes": state.exfil_bytes_detected,
            "duration_ms": duration_ms,
        },
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Forensics complete in {duration_ms:.0f}ms",
        ],
    }
