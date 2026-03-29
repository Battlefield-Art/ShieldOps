"""Tool functions for the Network Traffic Analyzer Agent."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.network_traffic_analyzer.models import (
    AnomalyDetection,
    ProtocolAnalysis,
    ProtocolType,
    ThreatClassification,
    TrafficAnomalyType,
    TrafficFlow,
)

logger = structlog.get_logger()

# Known C2 ports commonly used by threat actors
C2_PORTS: set[int] = {4444, 5555, 8443, 8888, 1337, 31337, 9999}

# DNS tunneling indicators
DNS_TUNNEL_THRESHOLDS = {
    "query_length": 50,
    "subdomain_entropy": 3.5,
    "queries_per_min": 60,
}

# Anomaly type to MITRE mapping
ANOMALY_MITRE_MAP: dict[TrafficAnomalyType, str] = {
    TrafficAnomalyType.LATERAL_MOVEMENT: "TA0008",
    TrafficAnomalyType.C2_BEACON: "TA0011",
    TrafficAnomalyType.DATA_EXFILTRATION: "TA0010",
    TrafficAnomalyType.DNS_TUNNELING: "TA0011",
    TrafficAnomalyType.PORT_SCAN: "TA0043",
    TrafficAnomalyType.PROTOCOL_ANOMALY: "TA0005",
    TrafficAnomalyType.BANDWIDTH_SPIKE: "TA0010",
    TrafficAnomalyType.BEACONING: "TA0011",
}

# Kill chain mapping
ANOMALY_KILL_CHAIN: dict[TrafficAnomalyType, str] = {
    TrafficAnomalyType.PORT_SCAN: "recon",
    TrafficAnomalyType.LATERAL_MOVEMENT: "exploit",
    TrafficAnomalyType.C2_BEACON: "c2",
    TrafficAnomalyType.BEACONING: "c2",
    TrafficAnomalyType.DATA_EXFILTRATION: "actions",
    TrafficAnomalyType.DNS_TUNNELING: "c2",
    TrafficAnomalyType.PROTOCOL_ANOMALY: "exploit",
    TrafficAnomalyType.BANDWIDTH_SPIKE: "actions",
}


class NetworkTrafficAnalyzerToolkit:
    """Toolkit for network traffic analysis."""

    def __init__(
        self,
        flow_source: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._flow_source = flow_source
        self._threat_intel = threat_intel

    async def ingest_flows(
        self,
        raw_flows: list[dict[str, Any]],
    ) -> list[TrafficFlow]:
        """Parse and normalize raw flow records."""
        flows: list[TrafficFlow] = []
        for raw in raw_flows:
            proto_str = str(raw.get("protocol", "tcp")).lower()
            valid_protos = [p.value for p in ProtocolType]
            proto = ProtocolType(proto_str) if proto_str in valid_protos else ProtocolType.TCP
            flow = TrafficFlow(
                id=raw.get("id", f"flow-{uuid4().hex[:12]}"),
                src_ip=raw.get("src_ip", ""),
                dst_ip=raw.get("dst_ip", ""),
                src_port=int(raw.get("src_port", 0)),
                dst_port=int(raw.get("dst_port", 0)),
                protocol=proto,
                bytes_sent=int(raw.get("bytes_sent", 0)),
                bytes_received=int(raw.get("bytes_received", 0)),
                packets=int(raw.get("packets", 0)),
                duration_ms=int(raw.get("duration_ms", 0)),
                timestamp=float(raw.get("timestamp", 0.0)),
                metadata=raw.get("metadata", {}),
            )
            flows.append(flow)

        logger.info(
            "network_traffic.flows_ingested",
            count=len(flows),
        )
        return flows

    async def detect_anomalies(
        self,
        flows: list[TrafficFlow],
    ) -> list[AnomalyDetection]:
        """Detect anomalies in network traffic flows."""
        anomalies: list[AnomalyDetection] = []

        # Check for port scanning
        scan_anomaly = self._detect_port_scan(flows)
        if scan_anomaly:
            anomalies.append(scan_anomaly)

        # Check for C2 beaconing
        c2_anomaly = self._detect_c2_beacon(flows)
        if c2_anomaly:
            anomalies.append(c2_anomaly)

        # Check for data exfiltration
        exfil_anomaly = self._detect_exfiltration(flows)
        if exfil_anomaly:
            anomalies.append(exfil_anomaly)

        # Check for DNS tunneling
        dns_anomaly = self._detect_dns_tunneling(flows)
        if dns_anomaly:
            anomalies.append(dns_anomaly)

        # Check for lateral movement
        lateral_anomaly = self._detect_lateral_movement(flows)
        if lateral_anomaly:
            anomalies.append(lateral_anomaly)

        logger.info(
            "network_traffic.anomalies_detected",
            count=len(anomalies),
        )
        return anomalies

    def _detect_port_scan(
        self,
        flows: list[TrafficFlow],
    ) -> AnomalyDetection | None:
        """Detect port scanning behavior."""
        src_dst_ports: dict[str, set[int]] = defaultdict(set)
        for f in flows:
            src_dst_ports[f.src_ip].add(f.dst_port)

        scanners = {ip: ports for ip, ports in src_dst_ports.items() if len(ports) > 10}
        if not scanners:
            return None

        top_scanner = max(scanners, key=lambda ip: len(scanners[ip]))
        port_count = len(scanners[top_scanner])

        return AnomalyDetection(
            id=f"anom-{uuid4().hex[:12]}",
            anomaly_type=TrafficAnomalyType.PORT_SCAN,
            severity="high" if port_count > 50 else "medium",
            confidence=min(port_count / 100, 1.0),
            source_ips=[top_scanner],
            description=(f"Port scan detected: {top_scanner} probed {port_count} ports"),
            indicators=[
                f"port_count={port_count}",
                f"scanner={top_scanner}",
            ],
            mitre_tactic=ANOMALY_MITRE_MAP[TrafficAnomalyType.PORT_SCAN],
        )

    def _detect_c2_beacon(
        self,
        flows: list[TrafficFlow],
    ) -> AnomalyDetection | None:
        """Detect C2 beacon communication patterns."""
        c2_flows = [f for f in flows if f.dst_port in C2_PORTS]
        if not c2_flows:
            return None

        src_ips = list({f.src_ip for f in c2_flows})
        dst_ips = list({f.dst_ip for f in c2_flows})

        return AnomalyDetection(
            id=f"anom-{uuid4().hex[:12]}",
            anomaly_type=TrafficAnomalyType.C2_BEACON,
            severity="critical",
            confidence=0.85,
            source_ips=src_ips,
            destination_ips=dst_ips,
            description=(f"C2 beacon suspected: {len(c2_flows)} flows to known C2 ports"),
            indicators=[
                f"c2_port_flows={len(c2_flows)}",
                f"dst_ports={[f.dst_port for f in c2_flows[:5]]}",
            ],
            mitre_tactic=ANOMALY_MITRE_MAP[TrafficAnomalyType.C2_BEACON],
        )

    def _detect_exfiltration(
        self,
        flows: list[TrafficFlow],
    ) -> AnomalyDetection | None:
        """Detect potential data exfiltration."""
        high_volume = [f for f in flows if f.bytes_sent > 10_000_000]
        if not high_volume:
            return None

        total_bytes = sum(f.bytes_sent for f in high_volume)
        src_ips = list({f.src_ip for f in high_volume})
        dst_ips = list({f.dst_ip for f in high_volume})

        return AnomalyDetection(
            id=f"anom-{uuid4().hex[:12]}",
            anomaly_type=TrafficAnomalyType.DATA_EXFILTRATION,
            severity="critical",
            confidence=0.75,
            source_ips=src_ips,
            destination_ips=dst_ips,
            description=(
                f"Data exfiltration suspected: "
                f"{total_bytes / 1_000_000:.1f}MB sent "
                f"in {len(high_volume)} flows"
            ),
            indicators=[
                f"total_bytes={total_bytes}",
                f"high_volume_flows={len(high_volume)}",
            ],
            mitre_tactic=ANOMALY_MITRE_MAP[TrafficAnomalyType.DATA_EXFILTRATION],
        )

    def _detect_dns_tunneling(
        self,
        flows: list[TrafficFlow],
    ) -> AnomalyDetection | None:
        """Detect DNS tunneling indicators."""
        dns_flows = [f for f in flows if f.protocol == ProtocolType.DNS or f.dst_port == 53]
        if len(dns_flows) < DNS_TUNNEL_THRESHOLDS["queries_per_min"]:
            return None

        src_ips = list({f.src_ip for f in dns_flows})

        return AnomalyDetection(
            id=f"anom-{uuid4().hex[:12]}",
            anomaly_type=TrafficAnomalyType.DNS_TUNNELING,
            severity="high",
            confidence=0.70,
            source_ips=src_ips,
            description=(f"DNS tunneling suspected: {len(dns_flows)} DNS flows exceed threshold"),
            indicators=[
                f"dns_flow_count={len(dns_flows)}",
                f"threshold={DNS_TUNNEL_THRESHOLDS['queries_per_min']}",
            ],
            mitre_tactic=ANOMALY_MITRE_MAP[TrafficAnomalyType.DNS_TUNNELING],
        )

    def _detect_lateral_movement(
        self,
        flows: list[TrafficFlow],
    ) -> AnomalyDetection | None:
        """Detect lateral movement patterns."""
        internal_flows = [
            f
            for f in flows
            if f.src_ip.startswith(("10.", "172.", "192.168."))
            and f.dst_ip.startswith(("10.", "172.", "192.168."))
        ]
        src_to_dsts: dict[str, set[str]] = defaultdict(set)
        for f in internal_flows:
            src_to_dsts[f.src_ip].add(f.dst_ip)

        movers = {ip: dsts for ip, dsts in src_to_dsts.items() if len(dsts) > 5}
        if not movers:
            return None

        top_mover = max(movers, key=lambda ip: len(movers[ip]))
        dst_count = len(movers[top_mover])

        return AnomalyDetection(
            id=f"anom-{uuid4().hex[:12]}",
            anomaly_type=TrafficAnomalyType.LATERAL_MOVEMENT,
            severity="critical",
            confidence=min(dst_count / 20, 1.0),
            source_ips=[top_mover],
            destination_ips=list(movers[top_mover])[:10],
            description=(
                f"Lateral movement detected: {top_mover} contacted {dst_count} internal hosts"
            ),
            indicators=[
                f"internal_dst_count={dst_count}",
                f"mover={top_mover}",
            ],
            mitre_tactic=ANOMALY_MITRE_MAP[TrafficAnomalyType.LATERAL_MOVEMENT],
        )

    async def classify_threats(
        self,
        anomalies: list[AnomalyDetection],
    ) -> list[ThreatClassification]:
        """Classify detected anomalies into threats."""
        threats: list[ThreatClassification] = []
        for anom in anomalies:
            threat = ThreatClassification(
                id=f"threat-{uuid4().hex[:12]}",
                threat_name=(f"{anom.anomaly_type.value}_threat"),
                anomaly_type=anom.anomaly_type,
                severity=anom.severity,
                confidence=anom.confidence,
                kill_chain_phase=ANOMALY_KILL_CHAIN.get(anom.anomaly_type, "unknown"),
                recommended_action=self._recommend_action(anom.anomaly_type),
                evidence=anom.indicators,
            )
            threats.append(threat)

        logger.info(
            "network_traffic.threats_classified",
            count=len(threats),
        )
        return threats

    def _recommend_action(
        self,
        anomaly_type: TrafficAnomalyType,
    ) -> str:
        """Return recommended action for anomaly type."""
        actions: dict[TrafficAnomalyType, str] = {
            TrafficAnomalyType.LATERAL_MOVEMENT: ("Isolate affected hosts and audit credentials"),
            TrafficAnomalyType.C2_BEACON: ("Block destination IPs and investigate host"),
            TrafficAnomalyType.DATA_EXFILTRATION: ("Block outbound traffic and preserve evidence"),
            TrafficAnomalyType.DNS_TUNNELING: ("Block DNS to suspicious domains"),
            TrafficAnomalyType.PORT_SCAN: ("Block source IP and review firewall rules"),
            TrafficAnomalyType.PROTOCOL_ANOMALY: ("Investigate protocol misuse and update IDS"),
            TrafficAnomalyType.BANDWIDTH_SPIKE: ("Rate-limit source and investigate cause"),
            TrafficAnomalyType.BEACONING: ("Block beacon destination and scan host"),
        }
        return actions.get(anomaly_type, "Investigate further")

    async def analyze_protocols(
        self,
        flows: list[TrafficFlow],
    ) -> list[ProtocolAnalysis]:
        """Analyze traffic by protocol type."""
        by_proto: dict[ProtocolType, list[TrafficFlow]] = defaultdict(
            list,
        )
        for f in flows:
            by_proto[f.protocol].append(f)

        analyses: list[ProtocolAnalysis] = []
        for proto, proto_flows in by_proto.items():
            total_bytes = sum(f.bytes_sent + f.bytes_received for f in proto_flows)

            # Count top talkers by source IP
            talker_counts: Counter[str] = Counter()
            for f in proto_flows:
                talker_counts[f.src_ip] += 1
            top_talkers = [ip for ip, _ in talker_counts.most_common(5)]

            findings: list[str] = []
            if proto == ProtocolType.DNS and len(proto_flows) > 50:
                findings.append("High DNS query volume detected")
            if proto == ProtocolType.SSH:
                unique_src = len({f.src_ip for f in proto_flows})
                if unique_src > 10:
                    findings.append(f"SSH from {unique_src} unique sources")

            analyses.append(
                ProtocolAnalysis(
                    id=f"proto-{uuid4().hex[:12]}",
                    protocol=proto,
                    total_flows=len(proto_flows),
                    total_bytes=total_bytes,
                    anomalous_flows=0,
                    top_talkers=top_talkers,
                    findings=findings,
                )
            )

        logger.info(
            "network_traffic.protocols_analyzed",
            protocols=len(analyses),
        )
        return analyses
