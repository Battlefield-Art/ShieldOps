"""eBPF Network Flow Analyzer eBPF-based network flow capture, protocol detection, latency his..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EbpfNetworkFlowAnalyzer = engine(
    "EbpfNetworkFlowAnalyzer",
    description="eBPF Network Flow Analyzer eBPF-based network flow capture, protocol detect...",
    enums={
        "protocol": EnumDef(
            "FlowProtocol",
            {
                "TCP": "tcp",
                "UDP": "udp",
                "HTTP": "http",
                "GRPC": "grpc",
                "DNS": "dns",
                "TLS": "tls",
                "QUIC": "quic",
                "UNKNOWN": "unknown",
            },
        ),
        "direction": EnumDef(
            "FlowDirection",
            {
                "INGRESS": "ingress",
                "EGRESS": "egress",
                "INTERNAL": "internal",
                "EXTERNAL": "external",
            },
        ),
        "connection_state": EnumDef(
            "ConnectionState",
            {
                "ESTABLISHED": "established",
                "SYN_SENT": "syn_sent",
                "FIN_WAIT": "fin_wait",
                "CLOSE_WAIT": "close_wait",
                "TIME_WAIT": "time_wait",
                "CLOSED": "closed",
                "RESET": "reset",
            },
        ),
    },
    record_fields=[
        FieldDef("destination_ip", str, ""),
        FieldDef("source_port", int, 0),
        FieldDef("destination_port", int, 0),
        FieldDef("bytes_sent", int, 0),
        FieldDef("bytes_received", int, 0),
        FieldDef("packets_sent", int, 0),
        FieldDef("packets_received", int, 0),
        FieldDef("latency_us", float, 0.0),
        FieldDef("retransmits", int, 0),
        FieldDef("namespace", str, ""),
        FieldDef("node", str, ""),
    ],
    key_field="source_ip",
)

# Backward-compatible re-exports
FlowProtocol = EbpfNetworkFlowAnalyzer.FlowProtocol
FlowDirection = EbpfNetworkFlowAnalyzer.FlowDirection
ConnectionState = EbpfNetworkFlowAnalyzer.ConnectionState
NetworkFlowRecord = EbpfNetworkFlowAnalyzer.Record
FlowAnalysis = EbpfNetworkFlowAnalyzer.Analysis
NetworkFlowReport = EbpfNetworkFlowAnalyzer.Report
