"""Entity Behavior Profiler — profile entity behaviors and detect anomalies."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

EntityBehaviorProfiler = engine(
    "EntityBehaviorProfiler",
    description="Profile entity behaviors, detect anomalies, and track behavioral baselines.",
    enums={
        "entity_type": EnumDef(
            "EntityType",
            {
                "USER": "user",
                "SERVICE_ACCOUNT": "service_account",
                "DEVICE": "device",
                "APPLICATION": "application",
                "NETWORK_SEGMENT": "network_segment",
            },
        ),
        "behavior_category": EnumDef(
            "BehaviorCategory",
            {
                "AUTHENTICATION": "authentication",
                "DATA_ACCESS": "data_access",
                "NETWORK_ACTIVITY": "network_activity",
                "PRIVILEGE_USE": "privilege_use",
                "RESOURCE_CONSUMPTION": "resource_consumption",
            },
        ),
        "profile_status": EnumDef(
            "ProfileStatus",
            {
                "BASELINE": "baseline",
                "NORMAL": "normal",
                "ANOMALOUS": "anomalous",
                "SUSPICIOUS": "suspicious",
                "COMPROMISED": "compromised",
            },
        ),
    },
    score_field="behavior_score",
    key_field="entity_name",
)

# Backward-compatible re-exports
EntityType = EntityBehaviorProfiler.EntityType
BehaviorCategory = EntityBehaviorProfiler.BehaviorCategory
ProfileStatus = EntityBehaviorProfiler.ProfileStatus
BehaviorRecord = EntityBehaviorProfiler.Record
BehaviorAnalysis = EntityBehaviorProfiler.Analysis
BehaviorProfileReport = EntityBehaviorProfiler.Report
