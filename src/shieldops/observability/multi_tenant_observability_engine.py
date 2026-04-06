"""MultiTenantObservabilityEngine — multi-tenant."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MultiTenantObservabilityEngine = engine(
    "MultiTenantObservabilityEngine",
    description="Multi-Tenant Observability Engine. Manages observability across tenants wit...",
    enums={
        "tier": EnumDef(
            "TenantTier",
            {
                "FREE": "free",
                "STANDARD": "standard",
                "PREMIUM": "premium",
                "ENTERPRISE": "enterprise",
            },
        ),
        "isolation": EnumDef(
            "IsolationLevel",
            {
                "SHARED": "shared",
                "NAMESPACE": "namespace",
                "DEDICATED": "dedicated",
                "CUSTOM": "custom",
            },
        ),
        "quota_status": EnumDef(
            "QuotaStatus",
            {
                "WITHIN_LIMIT": "within_limit",
                "WARNING": "warning",
                "EXCEEDED": "exceeded",
                "SUSPENDED": "suspended",
            },
        ),
    },
    record_fields=[
        FieldDef("usage_pct", float, 0.0),
        FieldDef("data_volume_gb", float, 0.0),
    ],
)

# Backward-compatible re-exports
TenantTier = MultiTenantObservabilityEngine.TenantTier
IsolationLevel = MultiTenantObservabilityEngine.IsolationLevel
QuotaStatus = MultiTenantObservabilityEngine.QuotaStatus
TenantRecord = MultiTenantObservabilityEngine.Record
TenantAnalysis = MultiTenantObservabilityEngine.Analysis
TenantReport = MultiTenantObservabilityEngine.Report
