"""Investigation Reasoning Depth Engine — analyze investigation reasoning chain depth, identif..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

InvestigationReasoningDepthEngine = engine(
    "InvestigationReasoningDepthEngine",
    description="Analyze investigation reasoning chain depth, identify breakdowns, correlate...",
    enums={
        "reasoning_depth": EnumDef(
            "ReasoningDepth",
            {
                "SHALLOW": "shallow",
                "MODERATE": "moderate",
                "DEEP": "deep",
                "EXHAUSTIVE": "exhaustive",
            },
        ),
        "breakdown_point": EnumDef(
            "BreakdownPoint",
            {
                "DATA_GAP": "data_gap",
                "AMBIGUITY": "ambiguity",
                "TIMEOUT": "timeout",
                "COMPLEXITY_LIMIT": "complexity_limit",
            },
        ),
        "investigation_style": EnumDef(
            "InvestigationStyle",
            {
                "LINEAR": "linear",
                "BRANCHING": "branching",
                "ITERATIVE": "iterative",
                "PARALLEL": "parallel",
            },
        ),
    },
    record_fields=[
        FieldDef("steps_taken", int, 0),
        FieldDef("resolved", bool, False),
        FieldDef("description", str, ""),
    ],
    score_field="depth_score",
    key_field="investigation_id",
)

# Backward-compatible re-exports
ReasoningDepth = InvestigationReasoningDepthEngine.ReasoningDepth
BreakdownPoint = InvestigationReasoningDepthEngine.BreakdownPoint
InvestigationStyle = InvestigationReasoningDepthEngine.InvestigationStyle
InvestigationReasoningDepthRecord = InvestigationReasoningDepthEngine.Record
InvestigationReasoningDepthAnalysis = InvestigationReasoningDepthEngine.Analysis
InvestigationReasoningDepthReport = InvestigationReasoningDepthEngine.Report
