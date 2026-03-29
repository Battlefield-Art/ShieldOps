"""Tool functions for the Network Forensics Agent."""

from __future__ import annotations

import hashlib
import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.network_forensics.models import (
    EvidenceType,
    ExfilPath,
    ForensicEvidence,
    LateralMovement,
    NetworkSession,
    SessionType,
    TimelineEvent,
)

logger = structlog.get_logger()

# Suspicious patterns for detection
_SUSPICIOUS_PORTS = {4444, 5555, 8888, 1337, 31337, 6667, 6697}
_C2_INDICATORS = {"beacon", "callback", "heartbeat", "keepalive"}
_EXFIL_METHODS = {"dns_tunnel", "icmp_tunnel", "https_exfil", "smb_exfil"}

_LATERAL_PROTOCOLS = {
    SessionType.SMB: "T1021.002",
    SessionType.SSH: "T1021.004",
    SessionType.RDP: "T1021.001",
}


class NetworkForensicsToolkit:
    """Toolkit for network forensics investigation."""

    def __init__(
        self,
        pcap_client: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._pcap_client = pcap_client
        self._threat_intel = threat_intel

    async def ingest_captures(
        self,
        capture_sources: list[dict[str, Any]],
    ) -> list[ForensicEvidence]:
        """Ingest pcap/netflow captures into evidence."""
        evidence: list[ForensicEvidence] = []
        now = time.time()

        if self._pcap_client is not None:
            try:
                raw = await self._pcap_client.ingest(
                    capture_sources,
                )
                for item in raw:
                    evidence.append(ForensicEvidence(**item))
                return evidence
            except Exception:
                logger.debug("pcap_client_failed")

        # Synthetic fallback
        for src in capture_sources:
            ev_type = EvidenceType(src.get("type", "pcap"))
            evidence.append(
                ForensicEvidence(
                    id=f"ev-{uuid4().hex[:12]}",
                    evidence_type=ev_type,
                    source_file=src.get("file", "capture.pcap"),
                    timestamp=now,
                    description=f"Ingested {ev_type.value}",
                    src_ip=src.get("src_ip", "10.0.0.1"),
                    dst_ip=src.get("dst_ip", "203.0.113.50"),
                    protocol=src.get("protocol", "tcp"),
                    severity="medium",
                    confidence=0.8,
                )
            )

        logger.info(
            "network_forensics.ingested",
            count=len(evidence),
        )
        return evidence

    async def reconstruct_sessions(
        self,
        evidence: list[ForensicEvidence],
    ) -> list[NetworkSession]:
        """Reconstruct network sessions from evidence."""
        sessions: list[NetworkSession] = []
        now = time.time()

        for ev in evidence:
            s_type = SessionType.HTTP
            if ev.protocol in ("smb", "cifs"):
                s_type = SessionType.SMB
            elif ev.protocol == "dns":
                s_type = SessionType.DNS
            elif ev.protocol == "ssh":
                s_type = SessionType.SSH

            sess = NetworkSession(
                id=f"sess-{uuid4().hex[:12]}",
                session_type=s_type,
                src_ip=ev.src_ip,
                src_port=12345,
                dst_ip=ev.dst_ip,
                dst_port=443 if s_type == SessionType.HTTP else 445,
                protocol=ev.protocol,
                bytes_sent=1024 * 50,
                bytes_received=1024 * 200,
                packet_count=150,
                start_time=now - 3600,
                end_time=now - 3500,
                duration_seconds=100.0,
                is_encrypted=s_type
                in (
                    SessionType.HTTPS,
                    SessionType.SSH,
                ),
            )
            sessions.append(sess)

        logger.info(
            "network_forensics.sessions_reconstructed",
            count=len(sessions),
        )
        return sessions

    async def build_timeline(
        self,
        sessions: list[NetworkSession],
        evidence: list[ForensicEvidence],
    ) -> list[TimelineEvent]:
        """Build chronological timeline from sessions."""
        events: list[TimelineEvent] = []

        for sess in sessions:
            events.append(
                TimelineEvent(
                    timestamp=sess.start_time,
                    event_type="session_start",
                    src_ip=sess.src_ip,
                    dst_ip=sess.dst_ip,
                    description=(
                        f"{sess.session_type.value} session {sess.src_ip} -> {sess.dst_ip}"
                    ),
                    evidence_ids=[sess.id],
                    severity="low",
                )
            )

        for ev in evidence:
            if ev.severity in ("high", "critical"):
                events.append(
                    TimelineEvent(
                        timestamp=ev.timestamp,
                        event_type="alert",
                        src_ip=ev.src_ip,
                        dst_ip=ev.dst_ip,
                        description=ev.description,
                        evidence_ids=[ev.id],
                        severity=ev.severity,
                    )
                )

        events.sort(key=lambda e: e.timestamp)
        logger.info(
            "network_forensics.timeline_built",
            events=len(events),
        )
        return events

    async def trace_lateral_movement(
        self,
        sessions: list[NetworkSession],
    ) -> list[LateralMovement]:
        """Detect lateral movement patterns."""
        movements: list[LateralMovement] = []

        for sess in sessions:
            if sess.session_type in _LATERAL_PROTOCOLS:
                technique = _LATERAL_PROTOCOLS[sess.session_type]
                movements.append(
                    LateralMovement(
                        src_host=sess.src_ip,
                        dst_host=sess.dst_ip,
                        protocol=sess.session_type.value,
                        method=f"remote_{sess.session_type.value}",
                        timestamp=sess.start_time,
                        credential_used="unknown",
                        mitre_technique=technique,
                        confidence=0.7,
                    )
                )

        logger.info(
            "network_forensics.lateral_traced",
            hops=len(movements),
        )
        return movements

    async def map_exfiltration(
        self,
        sessions: list[NetworkSession],
    ) -> list[ExfilPath]:
        """Map potential data exfiltration paths."""
        paths: list[ExfilPath] = []

        for sess in sessions:
            if sess.bytes_sent > 1024 * 100:
                risk = min(
                    sess.bytes_sent / (1024 * 1024),
                    1.0,
                )
                uid = hashlib.sha256(f"{sess.src_ip}:{sess.dst_ip}".encode()).hexdigest()[:12]
                paths.append(
                    ExfilPath(
                        id=f"exfil-{uid}",
                        src_host=sess.src_ip,
                        dst_host=sess.dst_ip,
                        dst_ip=sess.dst_ip,
                        protocol=sess.protocol,
                        port=sess.dst_port,
                        method="bulk_transfer",
                        bytes_exfiltrated=sess.bytes_sent,
                        duration_seconds=sess.duration_seconds,
                        is_encrypted=sess.is_encrypted,
                        confidence=risk,
                        sessions=[sess.id],
                        mitre_techniques=["T1048"],
                        risk_score=risk * 100,
                    )
                )

        logger.info(
            "network_forensics.exfil_mapped",
            paths=len(paths),
        )
        return paths
