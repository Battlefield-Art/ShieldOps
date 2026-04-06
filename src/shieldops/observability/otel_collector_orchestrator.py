"""OtelCollectorOrchestrator — collector deployment management."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

OtelCollectorOrchestrator = engine(
    "OtelCollectorOrchestrator",
    description="OTel collector deployment management engine.",
    enums={
        "collector_mode": EnumDef(
            "CollectorMode",
            {
                "DAEMONSET": "daemonset",
                "DEPLOYMENT": "deployment",
                "SIDECAR": "sidecar",
                "GATEWAY": "gateway",
            },
        ),
        "collector_health": EnumDef(
            "CollectorHealth",
            {
                "RUNNING": "running",
                "DEGRADED": "degraded",
                "CRASHED": "crashed",
                "PENDING": "pending",
            },
        ),
        "scaling_policy": EnumDef(
            "ScalingPolicy",
            {
                "FIXED": "fixed",
                "HPA": "hpa",
                "VPA": "vpa",
                "CUSTOM": "custom",
            },
        ),
    },
)

# Backward-compatible re-exports
CollectorMode = OtelCollectorOrchestrator.CollectorMode
CollectorHealth = OtelCollectorOrchestrator.CollectorHealth
ScalingPolicy = OtelCollectorOrchestrator.ScalingPolicy
OtelCollectorOrchestratorRecord = OtelCollectorOrchestrator.Record
OtelCollectorOrchestratorAnalysis = OtelCollectorOrchestrator.Analysis
OtelCollectorOrchestratorReport = OtelCollectorOrchestrator.Report
