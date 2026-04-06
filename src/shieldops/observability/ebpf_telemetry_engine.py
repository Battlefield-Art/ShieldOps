"""EbpfTelemetryEngine — eBPF-based telemetry collection tracking."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EbpfTelemetryEngine = engine(
    "EbpfTelemetryEngine",
    description="eBPF Telemetry Engine — kernel-level metrics, syscall tracing, network flow...",
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
        "kernel_metric": EnumDef(
            "KernelMetric",
            {
                "SYSCALL_LATENCY": "syscall_latency",
                "NETWORK_FLOW": "network_flow",
                "FILE_IO": "file_io",
                "PROCESS_LIFECYCLE": "process_lifecycle",
            },
        ),
        "probe_status": EnumDef(
            "ProbeStatus",
            {
                "ACTIVE": "active",
                "INACTIVE": "inactive",
                "ERRORED": "errored",
                "RATE_LIMITED": "rate_limited",
            },
        ),
    },
    record_fields=[
        FieldDef("cpu_overhead", float, 0.0),
    ],
)

# Backward-compatible re-exports
EbpfProbeType = EbpfTelemetryEngine.EbpfProbeType
KernelMetric = EbpfTelemetryEngine.KernelMetric
ProbeStatus = EbpfTelemetryEngine.ProbeStatus
EbpfTelemetryRecord = EbpfTelemetryEngine.Record
EbpfTelemetryAnalysis = EbpfTelemetryEngine.Analysis
EbpfTelemetryReport = EbpfTelemetryEngine.Report
