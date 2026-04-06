"""Multi-Hop Root Cause Engine — model root cause analysis as multi-hop reasoning chains, vali..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MultiHopRootCauseEngine = engine(
    "MultiHopRootCauseEngine",
    description="Model root cause analysis as multi-hop reasoning chains, validate hop depen...",
    enums={
        "hop_depth": EnumDef(
            "HopDepth",
            {
                "SINGLE_HOP": "single_hop",
                "TWO_HOP": "two_hop",
                "THREE_HOP": "three_hop",
                "DEEP_HOP": "deep_hop",
            },
        ),
        "causal_link_type": EnumDef(
            "CausalLinkType",
            {
                "DIRECT": "direct",
                "INDIRECT": "indirect",
                "CORRELATED": "correlated",
                "SPECULATIVE": "speculative",
            },
        ),
        "chain_status": EnumDef(
            "ChainStatus",
            {
                "COMPLETE": "complete",
                "PARTIAL": "partial",
                "BROKEN": "broken",
                "UNVERIFIED": "unverified",
            },
        ),
    },
    record_fields=[
        FieldDef("hop_count", int, 1),
        FieldDef("root_cause", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="confidence_score",
    key_field="chain_id",
)

# Backward-compatible re-exports
HopDepth = MultiHopRootCauseEngine.HopDepth
CausalLinkType = MultiHopRootCauseEngine.CausalLinkType
ChainStatus = MultiHopRootCauseEngine.ChainStatus
MultiHopRootCauseRecord = MultiHopRootCauseEngine.Record
MultiHopRootCauseAnalysis = MultiHopRootCauseEngine.Analysis
MultiHopRootCauseReport = MultiHopRootCauseEngine.Report
