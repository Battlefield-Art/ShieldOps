"""Pre-built Grafana Dashboard Definitions.

Generates dashboard JSON compatible with Grafana's provisioning API
(POST /api/dashboards/db).  Each function returns a complete dashboard
model that can be imported directly into Grafana.
"""

from __future__ import annotations

from typing import Any


def _panel(
    title: str,
    panel_type: str,
    grid_x: int,
    grid_y: int,
    width: int,
    height: int,
    datasource: str,
    expr: str,
    legend: str = "",
) -> dict[str, Any]:
    """Build a single Grafana panel definition."""
    panel: dict[str, Any] = {
        "title": title,
        "type": panel_type,
        "gridPos": {"x": grid_x, "y": grid_y, "w": width, "h": height},
        "datasource": {"type": datasource, "uid": f"${{{datasource}}}"},
        "targets": [
            {
                "expr": expr,
                "legendFormat": legend or "{{agent_type}}",
            }
        ],
    }
    return panel


def shieldops_agent_dashboard() -> dict[str, Any]:
    """Grafana dashboard: ShieldOps agent overview with Loki+Mimir+Tempo panels.

    Panels:
    - Agent invocation rate (Mimir PromQL)
    - Agent logs (Loki LogQL)
    - Trace latency p50/p95/p99 (Tempo)
    - Success rate gauge (Mimir)
    - LLM cost over time (Mimir)
    - Active agents count (Mimir)
    """
    return {
        "dashboard": {
            "title": "ShieldOps — Agent Overview",
            "uid": "shieldops-agent-overview",
            "tags": ["shieldops", "agents", "lgtm"],
            "timezone": "browser",
            "refresh": "30s",
            "time": {"from": "now-1h", "to": "now"},
            "panels": [
                _panel(
                    title="Agent Invocation Rate",
                    panel_type="timeseries",
                    grid_x=0,
                    grid_y=0,
                    width=12,
                    height=8,
                    datasource="prometheus",
                    expr="sum(rate(shieldops_agent_invocations_total[5m])) by (agent_type)",
                    legend="{{agent_type}}",
                ),
                _panel(
                    title="Agent Logs",
                    panel_type="logs",
                    grid_x=12,
                    grid_y=0,
                    width=12,
                    height=8,
                    datasource="loki",
                    expr='{platform="shieldops"} | json',
                ),
                _panel(
                    title="Agent Trace Latency (p95)",
                    panel_type="timeseries",
                    grid_x=0,
                    grid_y=8,
                    width=12,
                    height=8,
                    datasource="prometheus",
                    expr=(
                        "histogram_quantile(0.95,"
                        " sum(rate(shieldops_agent_duration_seconds_bucket[5m]))"
                        " by (le, agent_type))"
                    ),
                    legend="p95 {{agent_type}}",
                ),
                _panel(
                    title="Agent Success Rate",
                    panel_type="gauge",
                    grid_x=12,
                    grid_y=8,
                    width=6,
                    height=8,
                    datasource="prometheus",
                    expr=(
                        "sum(rate(shieldops_agent_success_total[5m]))"
                        " / sum(rate(shieldops_agent_invocations_total[5m]))"
                    ),
                ),
                _panel(
                    title="LLM Cost Over Time",
                    panel_type="timeseries",
                    grid_x=18,
                    grid_y=8,
                    width=6,
                    height=8,
                    datasource="prometheus",
                    expr="sum(increase(shieldops_llm_cost_dollars[1h])) by (model)",
                    legend="{{model}}",
                ),
                _panel(
                    title="Active Agents",
                    panel_type="stat",
                    grid_x=0,
                    grid_y=16,
                    width=6,
                    height=4,
                    datasource="prometheus",
                    expr="count(shieldops_agent_last_execution_timestamp > 0)",
                ),
            ],
        },
        "overwrite": True,
    }


def shieldops_sre_dashboard() -> dict[str, Any]:
    """Grafana dashboard: SRE operations with incident/remediation tracking.

    Panels:
    - Incident volume over time
    - Mean time to remediate (MTTR)
    - Remediation success rate
    - Active incidents table
    - SLO burn rate
    - Error budget remaining
    """
    return {
        "dashboard": {
            "title": "ShieldOps — SRE Operations",
            "uid": "shieldops-sre-ops",
            "tags": ["shieldops", "sre", "incidents"],
            "timezone": "browser",
            "refresh": "30s",
            "time": {"from": "now-6h", "to": "now"},
            "panels": [
                _panel(
                    title="Incident Volume",
                    panel_type="timeseries",
                    grid_x=0,
                    grid_y=0,
                    width=12,
                    height=8,
                    datasource="prometheus",
                    expr="sum(increase(shieldops_incidents_total[1h])) by (severity)",
                    legend="{{severity}}",
                ),
                _panel(
                    title="Mean Time to Remediate (MTTR)",
                    panel_type="stat",
                    grid_x=12,
                    grid_y=0,
                    width=6,
                    height=8,
                    datasource="prometheus",
                    expr=("avg(shieldops_remediation_duration_seconds) / 60"),
                ),
                _panel(
                    title="Remediation Success Rate",
                    panel_type="gauge",
                    grid_x=18,
                    grid_y=0,
                    width=6,
                    height=8,
                    datasource="prometheus",
                    expr=(
                        "sum(rate(shieldops_remediation_success_total[1h]))"
                        " / sum(rate(shieldops_remediation_total[1h]))"
                    ),
                ),
                _panel(
                    title="Incident Logs",
                    panel_type="logs",
                    grid_x=0,
                    grid_y=8,
                    width=24,
                    height=8,
                    datasource="loki",
                    expr='{platform="shieldops", level="error"} | json',
                ),
                _panel(
                    title="SLO Burn Rate",
                    panel_type="timeseries",
                    grid_x=0,
                    grid_y=16,
                    width=12,
                    height=8,
                    datasource="prometheus",
                    expr="shieldops_slo_burn_rate",
                    legend="{{slo_name}}",
                ),
                _panel(
                    title="Error Budget Remaining",
                    panel_type="gauge",
                    grid_x=12,
                    grid_y=16,
                    width=12,
                    height=8,
                    datasource="prometheus",
                    expr="shieldops_error_budget_remaining_ratio",
                ),
            ],
        },
        "overwrite": True,
    }


def shieldops_security_dashboard() -> dict[str, Any]:
    """Grafana dashboard: Security operations with threat intel and risk scoring.

    Panels:
    - Threat detections over time
    - Risk score distribution
    - Security agent activity logs
    - MITRE ATT&CK technique coverage
    - IOC match rate
    - Active threat hunts
    """
    return {
        "dashboard": {
            "title": "ShieldOps — Security Operations",
            "uid": "shieldops-security-ops",
            "tags": ["shieldops", "security", "threat-intel"],
            "timezone": "browser",
            "refresh": "30s",
            "time": {"from": "now-24h", "to": "now"},
            "panels": [
                _panel(
                    title="Threat Detections",
                    panel_type="timeseries",
                    grid_x=0,
                    grid_y=0,
                    width=12,
                    height=8,
                    datasource="prometheus",
                    expr=("sum(increase(shieldops_threat_detections_total[1h])) by (severity)"),
                    legend="{{severity}}",
                ),
                _panel(
                    title="Entity Risk Score Distribution",
                    panel_type="histogram",
                    grid_x=12,
                    grid_y=0,
                    width=12,
                    height=8,
                    datasource="prometheus",
                    expr="shieldops_entity_risk_score",
                ),
                _panel(
                    title="Security Agent Logs",
                    panel_type="logs",
                    grid_x=0,
                    grid_y=8,
                    width=24,
                    height=8,
                    datasource="loki",
                    expr=(
                        '{platform="shieldops",'
                        ' agent_type=~"security|threat_hunter|soc_analyst"} | json'
                    ),
                ),
                _panel(
                    title="MITRE ATT&CK Coverage",
                    panel_type="stat",
                    grid_x=0,
                    grid_y=16,
                    width=8,
                    height=6,
                    datasource="prometheus",
                    expr="shieldops_mitre_technique_coverage_ratio",
                ),
                _panel(
                    title="IOC Match Rate",
                    panel_type="timeseries",
                    grid_x=8,
                    grid_y=16,
                    width=8,
                    height=6,
                    datasource="prometheus",
                    expr="sum(rate(shieldops_ioc_matches_total[5m])) by (ioc_type)",
                    legend="{{ioc_type}}",
                ),
                _panel(
                    title="Active Threat Hunts",
                    panel_type="stat",
                    grid_x=16,
                    grid_y=16,
                    width=8,
                    height=6,
                    datasource="prometheus",
                    expr='count(shieldops_hunt_status{status="active"})',
                ),
            ],
        },
        "overwrite": True,
    }
