"""Cost Spike Detector Engine — detect and track cloud cost anomalies."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CostSpikeDetectorEngine = engine(
    "CostSpikeDetectorEngine",
    description="Cost Spike Detector Engine — detect and track cloud cost anomalies.",
    enums={
        "spike_type": EnumDef(
            "SpikeType",
            {
                "SUDDEN_INCREASE": "sudden_increase",
                "GRADUAL_DRIFT": "gradual_drift",
                "BILLING_ERROR": "billing_error",
                "RESOURCE_LEAK": "resource_leak",
                "LLM_OVERRUN": "llm_overrun",
            },
        ),
        "spike_source": EnumDef(
            "SpikeSource",
            {
                "COMPUTE": "compute",
                "STORAGE": "storage",
                "NETWORK": "network",
                "DATABASE": "database",
                "LLM_API": "llm_api",
            },
        ),
        "mitigation_status": EnumDef(
            "MitigationStatus",
            {
                "DETECTED": "detected",
                "INVESTIGATING": "investigating",
                "MITIGATED": "mitigated",
                "ACCEPTED": "accepted",
                "RESOLVED": "resolved",
            },
        ),
    },
    record_fields=[
        FieldDef("expected_daily", float, 0.0),
        FieldDef("actual_daily", float, 0.0),
        FieldDef("deviation_pct", float, 0.0),
    ],
    key_field="spike_id",
)

# Backward-compatible re-exports
SpikeType = CostSpikeDetectorEngine.SpikeType
SpikeSource = CostSpikeDetectorEngine.SpikeSource
MitigationStatus = CostSpikeDetectorEngine.MitigationStatus
CostSpikeRecord = CostSpikeDetectorEngine.Record
CostSpikeAnalysis = CostSpikeDetectorEngine.Analysis
CostSpikeReport = CostSpikeDetectorEngine.Report
