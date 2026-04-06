"""Metric Topology Mapper — metric topology mapping and relationship discovery."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

MetricTopologyMapper = engine(
    "MetricTopologyMapper",
    description="Metric Topology Mapper — metric topology mapping and relationship discovery.",
    enums={
        "topology_relation": EnumDef(
            "TopologyRelation",
            {
                "DEPENDS_ON": "depends_on",
                "CORRELATED": "correlated",
                "INVERSE": "inverse",
                "DERIVED": "derived",
                "INDEPENDENT": "independent",
            },
        ),
        "metric_source": EnumDef(
            "MetricSource",
            {
                "PROMETHEUS": "prometheus",
                "CLOUDWATCH": "cloudwatch",
                "DATADOG": "datadog",
                "STATSD": "statsd",
                "CUSTOM": "custom",
            },
        ),
        "mapping_confidence": EnumDef(
            "MappingConfidence",
            {
                "CERTAIN": "certain",
                "PROBABLE": "probable",
                "POSSIBLE": "possible",
                "UNLIKELY": "unlikely",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
TopologyRelation = MetricTopologyMapper.TopologyRelation
MetricSource = MetricTopologyMapper.MetricSource
MappingConfidence = MetricTopologyMapper.MappingConfidence
TopologyRecord = MetricTopologyMapper.Record
TopologyAnalysis = MetricTopologyMapper.Analysis
MetricTopologyReport = MetricTopologyMapper.Report
