"""Tool Use Interleaving Engine — optimize reasoning/tool-call interleaving in investigations,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ToolUseInterleavingEngine = engine(
    "ToolUseInterleavingEngine",
    description="Optimize reasoning/tool-call interleaving in investigations, recommend next...",
    enums={
        "turn_type": EnumDef(
            "TurnType",
            {
                "REASONING": "reasoning",
                "TOOL_CALL": "tool_call",
                "SYNTHESIS": "synthesis",
                "VERIFICATION": "verification",
            },
        ),
        "interleaving_pattern": EnumDef(
            "InterleavingPattern",
            {
                "REASON_FIRST": "reason_first",
                "TOOL_FIRST": "tool_first",
                "ALTERNATING": "alternating",
                "ADAPTIVE": "adaptive",
            },
        ),
        "tool_call_outcome": EnumDef(
            "ToolCallOutcome",
            {
                "INFORMATIVE": "informative",
                "REDUNDANT": "redundant",
                "FAILED": "failed",
                "DECISIVE": "decisive",
            },
        ),
    },
    record_fields=[
        FieldDef("information_gain", float, 0.0),
        FieldDef("turn_duration_ms", float, 0.0),
        FieldDef("tool_name", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="session_id",
)

# Backward-compatible re-exports
TurnType = ToolUseInterleavingEngine.TurnType
InterleavingPattern = ToolUseInterleavingEngine.InterleavingPattern
ToolCallOutcome = ToolUseInterleavingEngine.ToolCallOutcome
ToolUseInterleavingRecord = ToolUseInterleavingEngine.Record
ToolUseInterleavingAnalysis = ToolUseInterleavingEngine.Analysis
ToolUseInterleavingReport = ToolUseInterleavingEngine.Report
