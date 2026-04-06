"""Trace Topology Reconstruction Engine — reconstruct service topology from traces, detect top..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TraceTopologyReconstructionEngine = engine(
    "TraceTopologyReconstructionEngine",
    description="Reconstruct service topology from traces, detect topology changes, validate...",
    enums={
        "topology_type": EnumDef(
            "TopologyType",
            {
                "STATIC": "static",
                "DYNAMIC": "dynamic",
                "HYBRID": "hybrid",
                "INFERRED": "inferred",
            },
        ),
        "reconstruction_accuracy": EnumDef(
            "ReconstructionAccuracy",
            {
                "EXACT": "exact",
                "APPROXIMATE": "approximate",
                "PARTIAL": "partial",
                "OUTDATED": "outdated",
            },
        ),
        "change_type": EnumDef(
            "ChangeType",
            {
                "NEW_EDGE": "new_edge",
                "REMOVED_EDGE": "removed_edge",
                "WEIGHT_CHANGE": "weight_change",
                "NODE_CHANGE": "node_change",
            },
        ),
    },
    record_fields=[
        FieldDef("source_service", str, ""),
        FieldDef("target_service", str, ""),
        FieldDef("edge_weight", float, 0.0),
        FieldDef("call_count", int, 0),
        FieldDef("error_count", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="trace_id",
)

# Backward-compatible re-exports
TopologyType = TraceTopologyReconstructionEngine.TopologyType
ReconstructionAccuracy = TraceTopologyReconstructionEngine.ReconstructionAccuracy
ChangeType = TraceTopologyReconstructionEngine.ChangeType
TraceTopologyRecord = TraceTopologyReconstructionEngine.Record
TraceTopologyAnalysis = TraceTopologyReconstructionEngine.Analysis
TraceTopologyReport = TraceTopologyReconstructionEngine.Report
