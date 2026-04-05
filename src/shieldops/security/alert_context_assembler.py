"""Alert Context Assembler — enrich alerts with contextual data from multiple sources."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AlertContextAssembler = engine(
    "AlertContextAssembler",
    description="Enrich alerts with contextual data from multiple sources for faster triage.",
    enums={
        "context_source": EnumDef(
            "ContextSource",
            {
                "ASSET_INVENTORY": "asset_inventory",
                "THREAT_INTEL": "threat_intel",
                "USER_DIRECTORY": "user_directory",
                "NETWORK_TOPOLOGY": "network_topology",
                "VULN_DATABASE": "vuln_database",
            },
        ),
        "context_relevance": EnumDef(
            "ContextRelevance",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NONE": "none",
            },
        ),
        "assembly_method": EnumDef(
            "AssemblyMethod",
            {
                "AUTOMATED": "automated",
                "SEMI_AUTOMATED": "semi_automated",
                "MANUAL": "manual",
                "CACHED": "cached",
                "REALTIME": "realtime",
            },
        ),
    },
    score_field="enrichment_score",
    key_field="alert_name",
)

# Backward-compatible re-exports
ContextSource = AlertContextAssembler.ContextSource
ContextRelevance = AlertContextAssembler.ContextRelevance
AssemblyMethod = AlertContextAssembler.AssemblyMethod
ContextRecord = AlertContextAssembler.Record
ContextAnalysis = AlertContextAssembler.Analysis
ContextReport = AlertContextAssembler.Report
