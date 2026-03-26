"""Trust Graph Analytics — analyze identity trust graphs."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class GraphMetric(StrEnum):
    DENSITY = "density"
    DIAMETER = "diameter"
    CENTRALITY = "centrality"
    CLUSTERING = "clustering"


class TrustDensity(StrEnum):
    OVER_CONNECTED = "over_connected"
    BALANCED = "balanced"
    SPARSE = "sparse"
    ISOLATED = "isolated"


class AbusePattern(StrEnum):
    FEDERATION_ABUSE = "federation_abuse"
    DELEGATION_CHAIN = "delegation_chain"
    CROSS_ACCOUNT_PIVOT = "cross_account_pivot"


# --- Models ---


class TrustGraphRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_entity: str = ""
    target_entity: str = ""
    trust_type: str = ""
    metric: GraphMetric = GraphMetric.DENSITY
    density: TrustDensity = TrustDensity.BALANCED
    abuse_pattern: AbusePattern | None = None
    risk_score: float = 0.0
    edge_count: int = 0
    node_count: int = 0
    created_at: float = Field(default_factory=time.time)


class TrustGraphAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity: str = ""
    total_edges: int = 0
    total_nodes: int = 0
    density_class: str = ""
    abuse_detected: int = 0
    avg_risk: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class TrustGraphReport(BaseModel):
    total_records: int = 0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_density: dict[str, int] = Field(default_factory=dict)
    by_abuse: dict[str, int] = Field(default_factory=dict)
    avg_risk_score: float = 0.0
    over_connected_count: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class TrustGraphAnalyticsEngine:
    """Analyze identity trust graph structure."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 0.7,
    ) -> None:
        self._max_records = max_records
        self._risk_threshold = risk_threshold
        self._records: list[TrustGraphRecord] = []
        logger.info(
            "trust_graph_analytics.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / query --

    def add_record(
        self,
        source_entity: str,
        target_entity: str = "",
        trust_type: str = "",
        metric: GraphMetric = GraphMetric.DENSITY,
        density: TrustDensity = (TrustDensity.BALANCED),
        abuse_pattern: AbusePattern | None = None,
        risk_score: float = 0.0,
        edge_count: int = 0,
        node_count: int = 0,
    ) -> TrustGraphRecord:
        record = TrustGraphRecord(
            source_entity=source_entity,
            target_entity=target_entity,
            trust_type=trust_type,
            metric=metric,
            density=density,
            abuse_pattern=abuse_pattern,
            risk_score=risk_score,
            edge_count=edge_count,
            node_count=node_count,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "trust_graph_analytics.record_added",
            record_id=record.id,
            source=source_entity,
            density=density.value,
        )
        return record

    def process(self, entity: str) -> TrustGraphAnalysis:
        items = [r for r in self._records if r.source_entity == entity or r.target_entity == entity]
        if not items:
            return TrustGraphAnalysis(entity=entity)
        total_edges = sum(r.edge_count for r in items)
        total_nodes = sum(r.node_count for r in items)
        density_counts: dict[str, int] = {}
        for r in items:
            key = r.density.value
            density_counts[key] = density_counts.get(key, 0) + 1
        dominant = (
            max(
                density_counts,
                key=density_counts.get,  # type: ignore[arg-type]
            )
            if density_counts
            else ""
        )
        abuse_ct = sum(1 for r in items if r.abuse_pattern is not None)
        avg_risk = round(
            sum(r.risk_score for r in items) / len(items),
            4,
        )
        return TrustGraphAnalysis(
            entity=entity,
            total_edges=total_edges,
            total_nodes=total_nodes,
            density_class=dominant,
            abuse_detected=abuse_ct,
            avg_risk=avg_risk,
        )

    def generate_report(self) -> TrustGraphReport:
        by_metric: dict[str, int] = {}
        by_density: dict[str, int] = {}
        by_abuse: dict[str, int] = {}
        for r in self._records:
            by_metric[r.metric.value] = by_metric.get(r.metric.value, 0) + 1
            by_density[r.density.value] = by_density.get(r.density.value, 0) + 1
            if r.abuse_pattern:
                key = r.abuse_pattern.value
                by_abuse[key] = by_abuse.get(key, 0) + 1
        total = len(self._records)
        avg_risk = (
            round(
                sum(r.risk_score for r in self._records) / total,
                4,
            )
            if total
            else 0.0
        )
        over_ct = by_density.get(TrustDensity.OVER_CONNECTED.value, 0)
        recs: list[str] = []
        if over_ct > 0:
            recs.append(f"{over_ct} over-connected segment(s) — reduce trust scope")
        abuse_total = sum(by_abuse.values())
        if abuse_total > 0:
            recs.append(f"{abuse_total} abuse pattern(s) detected")
        if avg_risk > self._risk_threshold:
            recs.append("High avg graph risk — review trust relationships")
        if not recs:
            recs.append("Trust graph health is good")
        return TrustGraphReport(
            total_records=total,
            by_metric=by_metric,
            by_density=by_density,
            by_abuse=by_abuse,
            avg_risk_score=avg_risk,
            over_connected_count=over_ct,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        density_dist: dict[str, int] = {}
        for r in self._records:
            key = r.density.value
            density_dist[key] = density_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "risk_threshold": self._risk_threshold,
            "density_distribution": density_dist,
            "unique_sources": len({r.source_entity for r in self._records}),
            "abuse_patterns": sum(1 for r in self._records if r.abuse_pattern is not None),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("trust_graph_analytics.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def analyze_graph_density(
        self,
        source_entity: str,
        edge_count: int,
        node_count: int,
    ) -> dict[str, Any]:
        """Analyze trust graph density."""
        if node_count < 2:
            density_val = 0.0
        else:
            max_edges = node_count * (node_count - 1)
            density_val = edge_count / max_edges if max_edges > 0 else 0.0
        if density_val > 0.7:
            density = TrustDensity.OVER_CONNECTED
            risk = 0.8
        elif density_val > 0.3:
            density = TrustDensity.BALANCED
            risk = 0.3
        elif density_val > 0.05:
            density = TrustDensity.SPARSE
            risk = 0.2
        else:
            density = TrustDensity.ISOLATED
            risk = 0.1
        record = self.add_record(
            source_entity=source_entity,
            metric=GraphMetric.DENSITY,
            density=density,
            risk_score=risk,
            edge_count=edge_count,
            node_count=node_count,
        )
        return {
            "record_id": record.id,
            "source": source_entity,
            "density_value": round(density_val, 4),
            "density_class": density.value,
            "risk_score": risk,
            "edges": edge_count,
            "nodes": node_count,
        }

    def detect_trust_anomalies(
        self,
        source_entity: str,
        target_entity: str,
        abuse_pattern: AbusePattern | None = None,
        risk_score: float = 0.5,
    ) -> dict[str, Any]:
        """Detect trust relationship anomalies."""
        record = self.add_record(
            source_entity=source_entity,
            target_entity=target_entity,
            metric=GraphMetric.CENTRALITY,
            abuse_pattern=abuse_pattern,
            risk_score=risk_score,
        )
        is_anomaly = abuse_pattern is not None or risk_score >= self._risk_threshold
        logger.info(
            "trust_graph_analytics.anomaly_detected",
            source=source_entity,
            target=target_entity,
            is_anomaly=is_anomaly,
        )
        return {
            "record_id": record.id,
            "source": source_entity,
            "target": target_entity,
            "is_anomaly": is_anomaly,
            "abuse_pattern": (abuse_pattern.value if abuse_pattern else None),
            "risk_score": risk_score,
        }

    def forecast_risk(
        self,
        source_entity: str | None = None,
        window: int = 20,
    ) -> dict[str, Any]:
        """Forecast trust graph risk trends."""
        targets = self._records
        if source_entity:
            targets = [r for r in targets if r.source_entity == source_entity]
        recent = targets[-window:]
        if len(recent) < 2:
            return {
                "entity": source_entity or "all",
                "sufficient_data": False,
                "count": len(recent),
            }
        risks = [r.risk_score for r in recent]
        half = len(risks) // 2
        first_avg = sum(risks[:half]) / max(half, 1)
        second_avg = sum(risks[half:]) / max(len(risks) - half, 1)
        trend = round(second_avg - first_avg, 4)
        return {
            "entity": source_entity or "all",
            "sufficient_data": True,
            "current_avg_risk": round(second_avg, 4),
            "previous_avg_risk": round(first_avg, 4),
            "trend": trend,
            "risk_increasing": trend > 0,
            "sample_count": len(recent),
        }
