"""Distributed Clock Synchronization Engine — monitor clock sync in distributed traces, detect..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DistributedClockSynchronizationEngine = engine(
    "DistributedClockSynchronizationEngine",
    description="Monitor clock sync in distributed traces, detect clock drift, rank nodes by...",
    enums={
        "clock_source": EnumDef(
            "ClockSource",
            {
                "NTP": "ntp",
                "PTP": "ptp",
                "SYSTEM": "system",
                "HYBRID": "hybrid",
            },
        ),
        "sync_status": EnumDef(
            "SyncStatus",
            {
                "SYNCHRONIZED": "synchronized",
                "DRIFTING": "drifting",
                "UNSYNCHRONIZED": "unsynchronized",
                "UNKNOWN": "unknown",
            },
        ),
        "drift_severity": EnumDef(
            "DriftSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("service_name", str, ""),
        FieldDef("drift_ms", float, 0.0),
        FieldDef("offset_ms", float, 0.0),
        FieldDef("jitter_ms", float, 0.0),
        FieldDef("last_sync_ago_s", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="node_id",
)

# Backward-compatible re-exports
ClockSource = DistributedClockSynchronizationEngine.ClockSource
SyncStatus = DistributedClockSynchronizationEngine.SyncStatus
DriftSeverity = DistributedClockSynchronizationEngine.DriftSeverity
ClockSyncRecord = DistributedClockSynchronizationEngine.Record
ClockSyncAnalysis = DistributedClockSynchronizationEngine.Analysis
ClockSyncReport = DistributedClockSynchronizationEngine.Report
