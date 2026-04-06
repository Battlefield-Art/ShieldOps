"""InternalDeveloperPortalEngine Internal developer portal health, component catalog scoring,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

InternalDeveloperPortalEngine = engine(
    "InternalDeveloperPortalEngine",
    module="operations",  # uses record_item
    description="Internal developer portal health and adoption tracking.",
    enums={
        "portal_component": EnumDef(
            "PortalComponent",
            {
                "SERVICE_CATALOG": "service_catalog",
                "API_DOCS": "api_docs",
                "SCAFFOLDER": "scaffolder",
                "TECH_RADAR": "tech_radar",
                "SEARCH": "search",
            },
        ),
        "portal_adoption": EnumDef(
            "PortalAdoption",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NONE": "none",
                "UNKNOWN": "unknown",
            },
        ),
        "content_freshness": EnumDef(
            "ContentFreshness",
            {
                "CURRENT": "current",
                "STALE": "stale",
                "OUTDATED": "outdated",
                "MISSING": "missing",
                "ARCHIVED": "archived",
            },
        ),
    },
)

# Backward-compatible re-exports
PortalComponent = InternalDeveloperPortalEngine.PortalComponent
PortalAdoption = InternalDeveloperPortalEngine.PortalAdoption
ContentFreshness = InternalDeveloperPortalEngine.ContentFreshness
InternalDeveloperPortalRecord = InternalDeveloperPortalEngine.Record
InternalDeveloperPortalAnalysis = InternalDeveloperPortalEngine.Analysis
InternalDeveloperPortalReport = InternalDeveloperPortalEngine.Report
