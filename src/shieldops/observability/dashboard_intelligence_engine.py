"""Dashboard Intelligence Engine — dashboard intelligence with usage analytics and optimization."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DashboardIntelligenceEngine = engine(
    "DashboardIntelligenceEngine",
    description="Dashboard Intelligence Engine dashboard intelligence with usage analytics a...",
    enums={
        "dashboard_issue": EnumDef(
            "DashboardIssue",
            {
                "STALE_PANEL": "stale_panel",
                "MISSING_DATA": "missing_data",
                "SLOW_QUERY": "slow_query",
                "REDUNDANT": "redundant",
                "MISCONFIGURED": "misconfigured",
            },
        ),
        "dashboard_source": EnumDef(
            "DashboardSource",
            {
                "GRAFANA": "grafana",
                "DATADOG": "datadog",
                "KIBANA": "kibana",
                "CLOUDWATCH": "cloudwatch",
                "CUSTOM": "custom",
            },
        ),
        "dashboard_health": EnumDef(
            "DashboardHealth",
            {
                "OPTIMAL": "optimal",
                "GOOD": "good",
                "NEEDS_ATTENTION": "needs_attention",
                "POOR": "poor",
                "BROKEN": "broken",
            },
        ),
    },
)

# Backward-compatible re-exports
DashboardIssue = DashboardIntelligenceEngine.DashboardIssue
DashboardSource = DashboardIntelligenceEngine.DashboardSource
DashboardHealth = DashboardIntelligenceEngine.DashboardHealth
DashboardRecord = DashboardIntelligenceEngine.Record
DashboardAnalysis = DashboardIntelligenceEngine.Analysis
DashboardIntelligenceReport = DashboardIntelligenceEngine.Report
