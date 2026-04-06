"""Ebpf Observability Analyzer eBPF-based observability analysis for kernel and network insights."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

EbpfObservabilityAnalyzer = engine(
    "EbpfObservabilityAnalyzer",
    description="Ebpf Observability Analyzer eBPF-based observability analysis for kernel an...",
    enums={
        "ebpf_probe_type": EnumDef(
            "EbpfProbeType",
            {
                "KPROBE": "kprobe",
                "UPROBE": "uprobe",
                "TRACEPOINT": "tracepoint",
                "XDP": "xdp",
                "TC": "tc",
            },
        ),
        "ebpf_source": EnumDef(
            "EbpfSource",
            {
                "CILIUM": "cilium",
                "FALCO": "falco",
                "PIXIE": "pixie",
                "BPFTRACE": "bpftrace",
                "CUSTOM": "custom",
            },
        ),
        "probe_health": EnumDef(
            "ProbeHealth",
            {
                "ACTIVE": "active",
                "DEGRADED": "degraded",
                "DETACHED": "detached",
                "ERROR": "error",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
EbpfProbeType = EbpfObservabilityAnalyzer.EbpfProbeType
EbpfSource = EbpfObservabilityAnalyzer.EbpfSource
ProbeHealth = EbpfObservabilityAnalyzer.ProbeHealth
EbpfRecord = EbpfObservabilityAnalyzer.Record
EbpfAnalysis = EbpfObservabilityAnalyzer.Analysis
EbpfObservabilityReport = EbpfObservabilityAnalyzer.Report
