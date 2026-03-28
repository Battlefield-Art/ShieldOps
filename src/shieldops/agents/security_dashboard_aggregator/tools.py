"""Tool functions for the Security Dashboard Aggregator Agent."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.security_dashboard_aggregator.models import (
    AgentMetric,
    DashboardData,
    DomainAggregate,
    KPICalculation,
    KPIStatus,
    MetricAnomaly,
    MetricDomain,
)

logger = structlog.get_logger()

_KPI_TARGETS: dict[str, tuple[float, str]] = {
    "mttd_minutes": (5.0, "minutes"),
    "mttr_minutes": (60.0, "minutes"),
    "coverage_pct": (95.0, "percent"),
    "patch_compliance_pct": (90.0, "percent"),
    "false_positive_rate": (5.0, "percent"),
    "agent_uptime_pct": (99.5, "percent"),
}


class SecurityDashboardAggregatorToolkit:
    """Toolkit for aggregating security metrics."""

    def __init__(
        self,
        agent_registry: Any | None = None,
        metric_store: Any | None = None,
        incident_store: Any | None = None,
        finding_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._agent_registry = agent_registry
        self._metric_store = metric_store
        self._incident_store = incident_store
        self._finding_store = finding_store
        self._repository = repository

    async def collect_agent_metrics(
        self,
        tenant_id: str,
    ) -> list[AgentMetric]:
        """Collect metrics from all agents."""
        logger.info(
            "dashboard_agg.collect_metrics",
            tenant_id=tenant_id,
        )
        if self._metric_store is not None:
            try:
                return await self._metric_store.list(tenant_id)
            except Exception:
                logger.warning("dashboard_agg.collect_fallback")
        return []

    async def aggregate_by_domain(
        self,
        metrics: list[AgentMetric],
    ) -> list[DomainAggregate]:
        """Aggregate metrics by security domain."""
        logger.info(
            "dashboard_agg.aggregate",
            metric_count=len(metrics),
        )
        domain_map: dict[MetricDomain, list[AgentMetric]] = {}
        for m in metrics:
            domain_map.setdefault(m.domain, []).append(m)

        aggregates: list[DomainAggregate] = []
        for domain, mlist in domain_map.items():
            values = [m.value for m in mlist]
            agents = {m.agent_name for m in mlist}
            avg = sum(values) / len(values) if values else 0.0
            aggregates.append(
                DomainAggregate(
                    domain=domain,
                    metric_count=len(mlist),
                    agents_reporting=len(agents),
                    avg_value=round(avg, 2),
                    min_value=(round(min(values), 2) if values else 0.0),
                    max_value=(round(max(values), 2) if values else 0.0),
                    trend="stable",
                )
            )
        return aggregates

    async def calculate_kpis(
        self,
        aggregates: list[DomainAggregate],
        metrics: list[AgentMetric],
    ) -> list[KPICalculation]:
        """Calculate KPIs from aggregated data."""
        logger.info(
            "dashboard_agg.calculate_kpis",
            aggregate_count=len(aggregates),
        )
        kpis: list[KPICalculation] = []
        metric_by_name: dict[str, float] = {}
        for m in metrics:
            metric_by_name[m.metric_name] = m.value

        for name, (target, unit) in _KPI_TARGETS.items():
            value = metric_by_name.get(name, target)
            if name.endswith("_rate") or name in (
                "mttd_minutes",
                "mttr_minutes",
            ):
                status = (
                    KPIStatus.ON_TARGET
                    if value <= target
                    else (KPIStatus.AT_RISK if value <= target * 1.5 else KPIStatus.OFF_TARGET)
                )
            else:
                status = (
                    KPIStatus.ON_TARGET
                    if value >= target
                    else (KPIStatus.AT_RISK if value >= target * 0.8 else KPIStatus.OFF_TARGET)
                )
            domain = MetricDomain.DETECTION
            if "coverage" in name:
                domain = MetricDomain.COVERAGE
            elif "compliance" in name or "patch" in name:
                domain = MetricDomain.COMPLIANCE
            elif "mttr" in name:
                domain = MetricDomain.RESPONSE
            kpis.append(
                KPICalculation(
                    name=name,
                    value=round(value, 2),
                    target=target,
                    unit=unit,
                    status=status,
                    domain=domain,
                )
            )
        return kpis

    async def detect_anomalies(
        self,
        metrics: list[AgentMetric],
    ) -> list[MetricAnomaly]:
        """Detect anomalies in agent metrics."""
        logger.info(
            "dashboard_agg.detect_anomalies",
            metric_count=len(metrics),
        )
        anomalies: list[MetricAnomaly] = []
        name_groups: dict[str, list[AgentMetric]] = {}
        for m in metrics:
            name_groups.setdefault(m.metric_name, []).append(m)

        for _name, mlist in name_groups.items():
            if len(mlist) < 2:
                continue
            values = [m.value for m in mlist]
            avg = sum(values) / len(values)
            if avg == 0:
                continue
            for m in mlist:
                deviation = abs(m.value - avg) / avg
                if deviation > 0.5:
                    severity = "critical" if deviation > 1.0 else "warning"
                    anomalies.append(
                        MetricAnomaly(
                            agent_name=m.agent_name,
                            metric_name=m.metric_name,
                            expected_value=round(avg, 2),
                            actual_value=m.value,
                            deviation_pct=round(deviation * 100, 1),
                            severity=severity,
                            description=(
                                f"{m.metric_name} deviates {deviation * 100:.0f}% from average"
                            ),
                        )
                    )
        return anomalies

    async def generate_dashboard(
        self,
        aggregates: list[DomainAggregate],
        kpis: list[KPICalculation],
        anomalies: list[MetricAnomaly],
        agents_reporting: int,
    ) -> DashboardData:
        """Compose final dashboard data."""
        logger.info(
            "dashboard_agg.generate_dashboard",
            kpi_count=len(kpis),
        )
        on_target = sum(1 for k in kpis if k.status == KPIStatus.ON_TARGET)
        total = max(len(kpis), 1)
        score = round((on_target / total) * 100, 1)

        risk = "low"
        if score < 50:
            risk = "critical"
        elif score < 70:
            risk = "high"
        elif score < 85:
            risk = "medium"

        domain_scores = {a.domain.value: round(a.avg_value, 2) for a in aggregates}
        top_kpis = [
            {
                "name": k.name,
                "value": k.value,
                "target": k.target,
                "status": k.status.value,
            }
            for k in kpis
        ]
        return DashboardData(
            overall_score=score,
            risk_level=risk,
            domain_scores=domain_scores,
            top_kpis=top_kpis,
            agents_healthy=agents_reporting,
            agents_total=agents_reporting,
            executive_summary=(
                f"Security score: {score}/100 ({risk} risk). {on_target}/{total} KPIs on target."
            ),
        )
