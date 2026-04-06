"""Log Pipeline Optimizer — log pipeline optimization for throughput and cost."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

LogPipelineOptimizer = engine(
    "LogPipelineOptimizer",
    description="Log Pipeline Optimizer — log pipeline optimization for throughput and cost.",
    enums={
        "pipeline_stage": EnumDef(
            "PipelineStage",
            {
                "INGESTION": "ingestion",
                "PARSING": "parsing",
                "ENRICHMENT": "enrichment",
                "ROUTING": "routing",
                "STORAGE": "storage",
            },
        ),
        "pipeline_source": EnumDef(
            "PipelineSource",
            {
                "FLUENTD": "fluentd",
                "VECTOR": "vector",
                "LOGSTASH": "logstash",
                "FLUENT_BIT": "fluent_bit",
                "CUSTOM": "custom",
            },
        ),
        "stage_efficiency": EnumDef(
            "StageEfficiency",
            {
                "OPTIMAL": "optimal",
                "ACCEPTABLE": "acceptable",
                "BOTTLENECK": "bottleneck",
                "FAILING": "failing",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
PipelineStage = LogPipelineOptimizer.PipelineStage
PipelineSource = LogPipelineOptimizer.PipelineSource
StageEfficiency = LogPipelineOptimizer.StageEfficiency
LogPipelineRecord = LogPipelineOptimizer.Record
LogPipelineAnalysis = LogPipelineOptimizer.Analysis
LogPipelineReport = LogPipelineOptimizer.Report
