"""Chaos Experiment Tracker Engine — track chaos engineering experiments."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ChaosExperimentTrackerEngine = engine(
    "ChaosExperimentTrackerEngine",
    description="Track chaos engineering experiments and resilience outcomes.",
    enums={
        "experiment_type": EnumDef(
            "ExperimentType",
            {
                "POD_KILL": "pod_kill",
                "NETWORK_LATENCY": "network_latency",
                "CPU_STRESS": "cpu_stress",
                "MEMORY_PRESSURE": "memory_pressure",
                "DNS_FAILURE": "dns_failure",
            },
        ),
        "hypothesis_outcome": EnumDef(
            "HypothesisOutcome",
            {
                "CONFIRMED": "confirmed",
                "DISPROVED": "disproved",
                "INCONCLUSIVE": "inconclusive",
                "PARTIALLY_CONFIRMED": "partially_confirmed",
                "NOT_TESTED": "not_tested",
            },
        ),
        "resilience_score": EnumDef(
            "ResilienceScore",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "MODERATE": "moderate",
                "POOR": "poor",
                "FAILING": "failing",
            },
        ),
    },
    record_fields=[
        FieldDef("service_id", str, ""),
        FieldDef("duration_seconds", float, 0.0),
        FieldDef("recovery_time_seconds", float, 0.0),
        FieldDef("error_rate_during", float, 0.0),
        FieldDef("blast_radius", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="experiment_name",
)

# Backward-compatible re-exports
ExperimentType = ChaosExperimentTrackerEngine.ExperimentType
HypothesisOutcome = ChaosExperimentTrackerEngine.HypothesisOutcome
ResilienceScore = ChaosExperimentTrackerEngine.ResilienceScore
ChaosExperimentTrackerRecord = ChaosExperimentTrackerEngine.Record
ChaosExperimentTrackerAnalysis = ChaosExperimentTrackerEngine.Analysis
ChaosExperimentTrackerReport = ChaosExperimentTrackerEngine.Report
