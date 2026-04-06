"""Trace Anomaly Detection Engine — detect anomalous traces in distributed systems, classify a..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TraceAnomalyDetectionEngine = engine(
    "TraceAnomalyDetectionEngine",
    description="Detect anomalous traces in distributed systems, classify anomaly patterns,...",
    enums={
        "anomaly_type": EnumDef(
            "AnomalyType",
            {
                "LATENCY_SPIKE": "latency_spike",
                "ERROR_BURST": "error_burst",
                "TOPOLOGY_CHANGE": "topology_change",
                "VOLUME_SHIFT": "volume_shift",
            },
        ),
        "detection_method": EnumDef(
            "DetectionMethod",
            {
                "STATISTICAL": "statistical",
                "ML_BASED": "ml_based",
                "RULE_BASED": "rule_based",
                "HYBRID": "hybrid",
            },
        ),
        "anomaly_severity": EnumDef(
            "AnomalySeverity",
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
        FieldDef("latency_ms", float, 0.0),
        FieldDef("error_rate", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="anomaly_score",
    key_field="trace_id",
)

# Backward-compatible re-exports
AnomalyType = TraceAnomalyDetectionEngine.AnomalyType
DetectionMethod = TraceAnomalyDetectionEngine.DetectionMethod
AnomalySeverity = TraceAnomalyDetectionEngine.AnomalySeverity
TraceAnomalyRecord = TraceAnomalyDetectionEngine.Record
TraceAnomalyAnalysis = TraceAnomalyDetectionEngine.Analysis
TraceAnomalyReport = TraceAnomalyDetectionEngine.Report
