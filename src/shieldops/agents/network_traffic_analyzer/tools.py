"""Network Traffic Analyzer Agent — Tool functions."""

from __future__ import annotations

import time
import uuid
from collections import Counter, defaultdict
from typing import Any

import structlog

from .models import (
    NetworkFlow,
    PolicyEnforcement,
    ThreatClassification,
    ThreatType,
    TrafficAnomaly,
    TrafficCategory,
    TrafficPattern,
)

logger = structlog.get_logger()

# Known C2 ports commonly used by threat actors
C2_PORTS: set[int] = {
    4444,
    5555,
    8443,
    8888,
    1337,
    31337,
    9999,
}

# Brute-force thresholds
BRUTE_FORCE_THRESHOLD = 20

# DNS tunneling thresholds
DNS_TUNNEL_QUERY_THRESHOLD = 60

# Data exfiltration byte threshold (10 MB)
EXFIL_BYTE_THRESHOLD = 10_000_000

# Lateral movement destination threshold
LATERAL_DST_THRESHOLD = 5

# Port scan threshold
PORT_SCAN_THRESHOLD = 10

# Threat type to MITRE ATT&CK tactic mapping
THREAT_MITRE_MAP: dict[ThreatType, str] = {
    ThreatType.LATERAL_MOVEMENT: "TA0008",
    ThreatType.DATA_EXFILTRATION: "TA0010",
    ThreatType.C2_COMMUNICATION: "TA0011",
    ThreatType.PORT_SCAN: "TA0043",
    ThreatType.DNS_TUNNELING: "TA0011",
    ThreatType.BRUTE_FORCE: "TA0006",
}

# Kill chain mapping
THREAT_KILL_CHAIN: dict[ThreatType, str] = {
    ThreatType.PORT_SCAN: "recon",
    ThreatType.BRUTE_FORCE: "exploit",
    ThreatType.LATERAL_MOVEMENT: "exploit",
    ThreatType.C2_COMMUNICATION: "c2",
    ThreatType.DNS_TUNNELING: "c2",
    ThreatType.DATA_EXFILTRATION: "actions",
}

# Recommended enforcement actions per threat type
ENFORCEMENT_ACTIONS: dict[ThreatType, str] = {
    ThreatType.LATERAL_MOVEMENT: "isolate",
    ThreatType.DATA_EXFILTRATION: "block_outbound",
    ThreatType.C2_COMMUNICATION: "block_destination",
    ThreatType.PORT_SCAN: "block_source",
    ThreatType.DNS_TUNNELING: "block_dns",
    ThreatType.BRUTE_FORCE: "rate_limit",
}

# Mock realistic flow data for testing/demo
MOCK_FLOWS: list[dict[str, Any]] = [
    {
        "src_ip": "10.0.1.15",
        "dst_ip": "10.0.2.30",
        "src_port": 49152,
        "dst_port": 445,
        "protocol": "tcp",
        "bytes_sent": 2048,
        "bytes_received": 512,
        "packets": 12,
        "duration_ms": 150,
    },
    {
        "src_ip": "10.0.1.15",
        "dst_ip": "198.51.100.42",
        "src_port": 52301,
        "dst_port": 4444,
        "protocol": "tcp",
        "bytes_sent": 256,
        "bytes_received": 1024,
        "packets": 8,
        "duration_ms": 30000,
    },
    {
        "src_ip": "10.0.1.22",
        "dst_ip": "203.0.113.99",
        "src_port": 61234,
        "dst_port": 443,
        "protocol": "tcp",
        "bytes_sent": 15_000_000,
        "bytes_received": 4096,
        "packets": 9500,
        "duration_ms": 120000,
    },
    {
        "src_ip": "10.0.1.30",
        "dst_ip": "192.0.2.10",
        "src_port": 55123,
        "dst_port": 53,
        "protocol": "udp",
        "bytes_sent": 85000,
        "bytes_received": 42000,
        "packets": 500,
        "duration_ms": 60000,
    },
    {
        "src_ip": "10.0.3.5",
        "dst_ip": "10.0.1.10",
        "src_port": 45678,
        "dst_port": 22,
        "protocol": "tcp",
        "bytes_sent": 12000,
        "bytes_received": 800,
        "packets": 150,
        "duration_ms": 5000,
    },
    {
        "src_ip": "10.0.1.15",
        "dst_ip": "10.0.2.31",
        "src_port": 49200,
        "dst_port": 3389,
        "protocol": "tcp",
        "bytes_sent": 4096,
        "bytes_received": 2048,
        "packets": 20,
        "duration_ms": 500,
    },
    {
        "src_ip": "10.0.1.15",
        "dst_ip": "10.0.2.32",
        "src_port": 49201,
        "dst_port": 135,
        "protocol": "tcp",
        "bytes_sent": 1024,
        "bytes_received": 512,
        "packets": 6,
        "duration_ms": 100,
    },
    {
        "src_ip": "10.0.1.15",
        "dst_ip": "10.0.2.33",
        "src_port": 49202,
        "dst_port": 139,
        "protocol": "tcp",
        "bytes_sent": 2048,
        "bytes_received": 1024,
        "packets": 10,
        "duration_ms": 200,
    },
]


def _is_internal(ip: str) -> bool:
    """Check if an IP is in a private/internal range."""
    return ip.startswith(("10.", "172.", "192.168."))


class NetworkTrafficAnalyzerToolkit:
    """Tools for network traffic analysis."""

    def __init__(
        self,
        flow_source: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._flow_source = flow_source
        self._threat_intel = threat_intel
        self._flow_cache: dict[str, NetworkFlow] = {}

    async def capture_flows(
        self,
        tenant_id: str,
        raw_flows: list[dict[str, Any]],
    ) -> list[NetworkFlow]:
        """Parse and normalize raw flow records."""
        logger.info(
            "nta.capture_flows",
            tenant_id=tenant_id,
            flow_count=len(raw_flows),
        )
        flows: list[NetworkFlow] = []

        for raw in raw_flows:
            flow_id = raw.get(
                "id",
                f"flow-{uuid.uuid4().hex[:12]}",
            )
            flow = NetworkFlow(
                id=flow_id,
                src_ip=raw.get("src_ip", ""),
                dst_ip=raw.get("dst_ip", ""),
                src_port=int(raw.get("src_port", 0)),
                dst_port=int(raw.get("dst_port", 0)),
                protocol=str(
                    raw.get("protocol", "tcp"),
                ).lower(),
                bytes_sent=int(
                    raw.get("bytes_sent", 0),
                ),
                bytes_received=int(
                    raw.get("bytes_received", 0),
                ),
                packets=int(raw.get("packets", 0)),
                duration_ms=int(
                    raw.get("duration_ms", 0),
                ),
                timestamp=float(
                    raw.get("timestamp", time.time()),
                ),
                flags=raw.get("flags", []),
                metadata=raw.get("metadata", {}),
            )
            flows.append(flow)
            self._flow_cache[flow_id] = flow

        return flows

    async def analyze_patterns(
        self,
        flows: list[NetworkFlow],
    ) -> list[TrafficPattern]:
        """Analyze traffic patterns from captured flows."""
        logger.info(
            "nta.analyze_patterns",
            flow_count=len(flows),
        )
        patterns: list[TrafficPattern] = []

        # Group by protocol
        by_proto: dict[str, list[NetworkFlow]] = defaultdict(list)
        for f in flows:
            by_proto[f.protocol].append(f)

        for proto, proto_flows in by_proto.items():
            src_ips = list(
                {f.src_ip for f in proto_flows},
            )
            dst_ips = list(
                {f.dst_ip for f in proto_flows},
            )
            ports = list(
                {f.dst_port for f in proto_flows},
            )
            total_bytes = sum(f.bytes_sent + f.bytes_received for f in proto_flows)
            category = self._categorize_pattern(
                proto,
                proto_flows,
            )
            patterns.append(
                TrafficPattern(
                    id=f"pat-{uuid.uuid4().hex[:12]}",
                    pattern_name=f"{proto}_traffic",
                    source_ips=src_ips[:10],
                    destination_ips=dst_ips[:10],
                    ports=sorted(ports)[:20],
                    protocol=proto,
                    flow_count=len(proto_flows),
                    total_bytes=total_bytes,
                    category=category,
                    description=(
                        f"{proto.upper()} traffic: {len(proto_flows)} flows, {total_bytes} bytes"
                    ),
                ),
            )

        # Top talker pattern
        talker_counts: Counter[str] = Counter()
        for f in flows:
            talker_counts[f.src_ip] += f.bytes_sent
        top_talkers = talker_counts.most_common(5)
        if top_talkers:
            patterns.append(
                TrafficPattern(
                    id=f"pat-{uuid.uuid4().hex[:12]}",
                    pattern_name="top_talkers",
                    source_ips=[ip for ip, _ in top_talkers],
                    flow_count=len(flows),
                    total_bytes=sum(b for _, b in top_talkers),
                    category=TrafficCategory.NORMAL,
                    description=(f"Top {len(top_talkers)} talkers by bytes sent"),
                ),
            )

        return patterns

    async def detect_anomalies(
        self,
        flows: list[NetworkFlow],
        patterns: list[TrafficPattern],
    ) -> list[TrafficAnomaly]:
        """Detect anomalies in network traffic."""
        logger.info(
            "nta.detect_anomalies",
            flow_count=len(flows),
            pattern_count=len(patterns),
        )
        anomalies: list[TrafficAnomaly] = []

        # Port scan detection
        scan = self._detect_port_scan(flows)
        if scan:
            anomalies.append(scan)

        # C2 communication detection
        c2 = self._detect_c2(flows)
        if c2:
            anomalies.append(c2)

        # Data exfiltration detection
        exfil = self._detect_exfiltration(flows)
        if exfil:
            anomalies.append(exfil)

        # DNS tunneling detection
        dns = self._detect_dns_tunneling(flows)
        if dns:
            anomalies.append(dns)

        # Lateral movement detection
        lateral = self._detect_lateral_movement(flows)
        if lateral:
            anomalies.append(lateral)

        # Brute force detection
        brute = self._detect_brute_force(flows)
        if brute:
            anomalies.append(brute)

        return anomalies

    async def classify_threats(
        self,
        anomalies: list[TrafficAnomaly],
    ) -> list[ThreatClassification]:
        """Classify anomalies into threat categories."""
        logger.info(
            "nta.classify_threats",
            anomaly_count=len(anomalies),
        )
        threats: list[ThreatClassification] = []

        for anom in anomalies:
            kill_chain = THREAT_KILL_CHAIN.get(
                anom.threat_type,
                "unknown",
            )
            action = self._recommend_action(
                anom.threat_type,
            )
            threat = ThreatClassification(
                id=f"threat-{uuid.uuid4().hex[:12]}",
                threat_name=(f"{anom.threat_type.value}_threat"),
                threat_type=anom.threat_type,
                severity=anom.severity,
                confidence=anom.confidence,
                kill_chain_phase=kill_chain,
                recommended_action=action,
                evidence=anom.indicators,
            )
            threats.append(threat)

        return threats

    async def enforce_policies(
        self,
        threats: list[ThreatClassification],
    ) -> list[PolicyEnforcement]:
        """Generate policy enforcement actions."""
        logger.info(
            "nta.enforce_policies",
            threat_count=len(threats),
        )
        enforcements: list[PolicyEnforcement] = []

        for threat in threats:
            if threat.confidence < 0.5:
                continue
            action = ENFORCEMENT_ACTIONS.get(
                threat.threat_type,
                "alert",
            )
            # Collect target IPs from evidence
            target_ips: list[str] = []
            for ev in threat.evidence:
                if "=" in ev:
                    val = ev.split("=", 1)[1]
                    if val.startswith(
                        ("10.", "172.", "192.", "198."),
                    ):
                        target_ips.append(val)

            enforcement = PolicyEnforcement(
                id=f"enf-{uuid.uuid4().hex[:12]}",
                threat_id=threat.id,
                action=action,
                target_ips=target_ips[:10],
                rule_name=(f"auto_{threat.threat_type.value}"),
                status=("enforced" if threat.severity == "critical" else "pending"),
                reason=(f"Auto-enforcement for {threat.severity} {threat.threat_type.value}"),
            )
            enforcements.append(enforcement)

        return enforcements

    # ----------------------------------------------------------
    # Private detection methods
    # ----------------------------------------------------------

    def _detect_port_scan(
        self,
        flows: list[NetworkFlow],
    ) -> TrafficAnomaly | None:
        """Detect port scanning behavior."""
        src_ports: dict[str, set[int]] = defaultdict(
            set,
        )
        for f in flows:
            src_ports[f.src_ip].add(f.dst_port)

        scanners = {
            ip: ports for ip, ports in src_ports.items() if len(ports) > PORT_SCAN_THRESHOLD
        }
        if not scanners:
            return None

        top = max(
            scanners,
            key=lambda ip: len(scanners[ip]),
        )
        count = len(scanners[top])

        return TrafficAnomaly(
            id=f"anom-{uuid.uuid4().hex[:12]}",
            threat_type=ThreatType.PORT_SCAN,
            severity=("high" if count > 50 else "medium"),
            confidence=min(count / 100, 1.0),
            source_ips=[top],
            description=(f"Port scan: {top} probed {count} ports"),
            indicators=[
                f"port_count={count}",
                f"scanner={top}",
            ],
            mitre_tactic=THREAT_MITRE_MAP[ThreatType.PORT_SCAN],
        )

    def _detect_c2(
        self,
        flows: list[NetworkFlow],
    ) -> TrafficAnomaly | None:
        """Detect C2 communication patterns."""
        c2_flows = [f for f in flows if f.dst_port in C2_PORTS]
        if not c2_flows:
            return None

        src_ips = list(
            {f.src_ip for f in c2_flows},
        )
        dst_ips = list(
            {f.dst_ip for f in c2_flows},
        )
        ports = list(
            {f.dst_port for f in c2_flows},
        )

        return TrafficAnomaly(
            id=f"anom-{uuid.uuid4().hex[:12]}",
            threat_type=ThreatType.C2_COMMUNICATION,
            severity="critical",
            confidence=0.85,
            source_ips=src_ips,
            destination_ips=dst_ips,
            description=(f"C2 suspected: {len(c2_flows)} flows to known C2 ports {ports}"),
            indicators=[
                f"c2_flows={len(c2_flows)}",
                f"dst_ports={ports}",
            ],
            mitre_tactic=THREAT_MITRE_MAP[ThreatType.C2_COMMUNICATION],
        )

    def _detect_exfiltration(
        self,
        flows: list[NetworkFlow],
    ) -> TrafficAnomaly | None:
        """Detect potential data exfiltration."""
        high_vol = [f for f in flows if f.bytes_sent > EXFIL_BYTE_THRESHOLD]
        if not high_vol:
            return None

        total = sum(f.bytes_sent for f in high_vol)
        src_ips = list(
            {f.src_ip for f in high_vol},
        )
        dst_ips = list(
            {f.dst_ip for f in high_vol},
        )
        mb = total / 1_000_000

        return TrafficAnomaly(
            id=f"anom-{uuid.uuid4().hex[:12]}",
            threat_type=ThreatType.DATA_EXFILTRATION,
            severity="critical",
            confidence=0.75,
            source_ips=src_ips,
            destination_ips=dst_ips,
            description=(f"Exfiltration suspected: {mb:.1f}MB sent in {len(high_vol)} flows"),
            indicators=[
                f"total_bytes={total}",
                f"flow_count={len(high_vol)}",
            ],
            mitre_tactic=THREAT_MITRE_MAP[ThreatType.DATA_EXFILTRATION],
        )

    def _detect_dns_tunneling(
        self,
        flows: list[NetworkFlow],
    ) -> TrafficAnomaly | None:
        """Detect DNS tunneling indicators."""
        dns_flows = [f for f in flows if f.protocol == "udp" and f.dst_port == 53]
        if len(dns_flows) < DNS_TUNNEL_QUERY_THRESHOLD:
            return None

        src_ips = list(
            {f.src_ip for f in dns_flows},
        )
        total_bytes = sum(f.bytes_sent for f in dns_flows)

        return TrafficAnomaly(
            id=f"anom-{uuid.uuid4().hex[:12]}",
            threat_type=ThreatType.DNS_TUNNELING,
            severity="high",
            confidence=0.70,
            source_ips=src_ips,
            description=(
                f"DNS tunneling suspected: {len(dns_flows)} DNS queries, {total_bytes} bytes"
            ),
            indicators=[
                f"dns_flows={len(dns_flows)}",
                f"total_bytes={total_bytes}",
            ],
            mitre_tactic=THREAT_MITRE_MAP[ThreatType.DNS_TUNNELING],
        )

    def _detect_lateral_movement(
        self,
        flows: list[NetworkFlow],
    ) -> TrafficAnomaly | None:
        """Detect lateral movement patterns."""
        internal_flows = [f for f in flows if _is_internal(f.src_ip) and _is_internal(f.dst_ip)]
        src_dsts: dict[str, set[str]] = defaultdict(
            set,
        )
        for f in internal_flows:
            src_dsts[f.src_ip].add(f.dst_ip)

        movers = {ip: dsts for ip, dsts in src_dsts.items() if len(dsts) > LATERAL_DST_THRESHOLD}
        if not movers:
            return None

        top = max(
            movers,
            key=lambda ip: len(movers[ip]),
        )
        dst_count = len(movers[top])

        return TrafficAnomaly(
            id=f"anom-{uuid.uuid4().hex[:12]}",
            threat_type=ThreatType.LATERAL_MOVEMENT,
            severity="critical",
            confidence=min(dst_count / 20, 1.0),
            source_ips=[top],
            destination_ips=list(movers[top])[:10],
            description=(f"Lateral movement: {top} contacted {dst_count} internal hosts"),
            indicators=[
                f"dst_count={dst_count}",
                f"mover={top}",
            ],
            mitre_tactic=THREAT_MITRE_MAP[ThreatType.LATERAL_MOVEMENT],
        )

    def _detect_brute_force(
        self,
        flows: list[NetworkFlow],
    ) -> TrafficAnomaly | None:
        """Detect brute force login attempts."""
        auth_ports = {22, 3389, 445, 23, 21}
        auth_flows = [f for f in flows if f.dst_port in auth_ports]

        src_attempts: Counter[str] = Counter()
        for f in auth_flows:
            src_attempts[f.src_ip] += f.packets

        brute_sources = {
            ip: count for ip, count in src_attempts.items() if count > BRUTE_FORCE_THRESHOLD
        }
        if not brute_sources:
            return None

        top = max(brute_sources, key=brute_sources.get)  # type: ignore[arg-type]
        count = brute_sources[top]

        return TrafficAnomaly(
            id=f"anom-{uuid.uuid4().hex[:12]}",
            threat_type=ThreatType.BRUTE_FORCE,
            severity=("high" if count > 100 else "medium"),
            confidence=min(count / 200, 1.0),
            source_ips=[top],
            description=(f"Brute force: {top} sent {count} packets to auth ports"),
            indicators=[
                f"packet_count={count}",
                f"source={top}",
            ],
            mitre_tactic=THREAT_MITRE_MAP[ThreatType.BRUTE_FORCE],
        )

    @staticmethod
    def _categorize_pattern(
        protocol: str,
        flows: list[NetworkFlow],
    ) -> TrafficCategory:
        """Categorize a traffic pattern."""
        total_bytes = sum(f.bytes_sent for f in flows)
        c2_hits = sum(1 for f in flows if f.dst_port in C2_PORTS)

        if c2_hits > 0:
            return TrafficCategory.MALICIOUS
        if protocol in ("https", "tls"):
            return TrafficCategory.ENCRYPTED
        if total_bytes > EXFIL_BYTE_THRESHOLD:
            return TrafficCategory.SUSPICIOUS
        return TrafficCategory.NORMAL

    @staticmethod
    def _recommend_action(
        threat_type: ThreatType,
    ) -> str:
        """Return recommended action for a threat."""
        actions: dict[ThreatType, str] = {
            ThreatType.LATERAL_MOVEMENT: ("Isolate affected hosts and audit credentials"),
            ThreatType.DATA_EXFILTRATION: ("Block outbound traffic and preserve evidence"),
            ThreatType.C2_COMMUNICATION: ("Block destination IPs and investigate host"),
            ThreatType.PORT_SCAN: ("Block source IP and review firewall rules"),
            ThreatType.DNS_TUNNELING: ("Block DNS to suspicious domains"),
            ThreatType.BRUTE_FORCE: ("Rate-limit source and enforce MFA"),
        }
        return actions.get(
            threat_type,
            "Investigate further",
        )
