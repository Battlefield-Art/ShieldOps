"""Security Change Manager Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    ApprovalDecision,
    ApprovalStatus,
    ChangeRequest,
    ChangeRiskLevel,
    DependencyCheck,
    RiskAssessment,
    RolloutMetric,
)

logger = structlog.get_logger()

_SAMPLE_CHANGES: list[dict[str, Any]] = [
    {
        "title": "Deploy auth-service v2.4.0",
        "description": "OAuth2 token refresh fix + rate limit update",
        "submitter": "alice@corp.io",
        "service": "auth-service",
        "environment": "production",
        "change_type": "standard",
    },
    {
        "title": "Update WAF rules for API gateway",
        "description": "Block SQLi patterns observed in recent scan",
        "submitter": "bob@corp.io",
        "service": "api-gateway",
        "environment": "production",
        "change_type": "emergency",
    },
    {
        "title": "Scale Redis cluster to 6 nodes",
        "description": "Handle increased session load",
        "submitter": "carol@corp.io",
        "service": "cache-layer",
        "environment": "production",
        "change_type": "standard",
    },
    {
        "title": "Rotate TLS certificates for ingress",
        "description": "Expiring in 7 days, automated rotation",
        "submitter": "dave@corp.io",
        "service": "ingress-controller",
        "environment": "production",
        "change_type": "standard",
    },
    {
        "title": "Enable debug logging on payment service",
        "description": "Troubleshoot intermittent 502 errors",
        "submitter": "eve@corp.io",
        "service": "payment-service",
        "environment": "staging",
        "change_type": "normal",
    },
    {
        "title": "Upgrade PostgreSQL from 15 to 16",
        "description": "Major version upgrade with schema migration",
        "submitter": "frank@corp.io",
        "service": "database",
        "environment": "production",
        "change_type": "major",
    },
]

_SERVICE_DEPS: dict[str, list[str]] = {
    "auth-service": ["api-gateway", "user-service", "session-store"],
    "api-gateway": ["auth-service", "rate-limiter", "logging"],
    "cache-layer": ["auth-service", "api-gateway", "session-store"],
    "ingress-controller": ["api-gateway", "cdn", "waf"],
    "payment-service": ["database", "auth-service", "notification"],
    "database": ["backup-agent", "replication-manager", "audit-log"],
}

_ROLLOUT_METRICS: list[str] = [
    "error_rate",
    "p99_latency_ms",
    "cpu_utilization",
    "memory_utilization",
    "request_throughput",
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class SecurityChangeManagerToolkit:
    """Tools for security-aware change management."""

    def __init__(
        self,
        change_source: Any | None = None,
        approval_api: Any | None = None,
    ) -> None:
        self._change_source = change_source
        self._approval_api = approval_api

    async def receive_change(
        self,
        tenant_id: str,
    ) -> list[ChangeRequest]:
        """Receive and ingest change requests."""
        logger.info(
            "scm.receive_change",
            tenant_id=tenant_id,
        )

        if self._change_source is not None:
            try:
                raw = await self._change_source.get_changes(
                    tenant_id=tenant_id,
                )
                return [ChangeRequest(**r) for r in raw]
            except Exception:
                logger.exception("scm.receive_change.error")

        changes: list[ChangeRequest] = []
        for i, c in enumerate(_SAMPLE_CHANGES):
            changes.append(
                ChangeRequest(
                    id=_gen_id("CR", tenant_id, i),
                    title=c["title"],
                    description=c["description"],
                    submitter=c["submitter"],
                    service=c["service"],
                    environment=c["environment"],
                    change_type=c["change_type"],
                    scheduled_at=f"2026-03-30T{10 + i}:00:00Z",
                    rollback_plan=f"Revert {c['service']} to previous version",
                )
            )
        return changes

    async def assess_change_risk(
        self,
        changes: list[ChangeRequest],
    ) -> list[RiskAssessment]:
        """Assess security risk for each change request."""
        logger.info(
            "scm.assess_risk",
            count=len(changes),
        )

        risk_map = {
            "emergency": ChangeRiskLevel.HIGH,
            "major": ChangeRiskLevel.CRITICAL,
            "standard": ChangeRiskLevel.MEDIUM,
            "normal": ChangeRiskLevel.LOW,
        }
        env_multiplier = {"production": 1.5, "staging": 1.0, "dev": 0.5}

        assessments: list[RiskAssessment] = []
        for i, cr in enumerate(changes):
            base_risk = risk_map.get(cr.change_type, ChangeRiskLevel.MEDIUM)
            mult = env_multiplier.get(cr.environment, 1.0)
            noise = random.uniform(-0.05, 0.05)  # noqa: S311
            base_score = {"critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.3}
            score = round(
                min(base_score.get(base_risk.value, 0.5) * mult + noise, 1.0),
                2,
            )
            deps = _SERVICE_DEPS.get(cr.service, [])
            blast = len(deps) + 1

            compliance_flags: list[str] = []
            if cr.environment == "production" and cr.change_type == "emergency":
                compliance_flags.append("SOC2-change-control")
            if "database" in cr.service.lower():
                compliance_flags.append("PCI-DSS-data-integrity")

            assessments.append(
                RiskAssessment(
                    id=_gen_id("RA", cr.id, i),
                    change_id=cr.id,
                    risk_level=base_risk,
                    risk_score=score,
                    blast_radius=blast,
                    affected_services=deps,
                    security_impact=f"{base_risk.value} impact on {cr.service}",
                    compliance_flags=compliance_flags,
                    mitigations=[
                        f"Canary deploy for {cr.service}",
                        "Monitor error rate post-deploy",
                    ],
                )
            )
        return assessments

    async def check_dependencies(
        self,
        changes: list[ChangeRequest],
    ) -> list[DependencyCheck]:
        """Analyze dependency impact of changes."""
        logger.info(
            "scm.check_dependencies",
            count=len(changes),
        )

        checks: list[DependencyCheck] = []
        all_services = {c.service for c in changes}
        for i, cr in enumerate(changes):
            deps = _SERVICE_DEPS.get(cr.service, [])
            upstream = [d for d in deps[:2] if d != cr.service]
            downstream = [d for d in deps[2:] if d != cr.service]
            conflicts = [
                c2.id
                for c2 in changes
                if c2.id != cr.id and c2.service in all_services and c2.service in deps
            ]
            dep_risk = round(len(conflicts) * 0.2 + len(deps) * 0.1, 2)

            checks.append(
                DependencyCheck(
                    id=_gen_id("DC", cr.id, i),
                    change_id=cr.id,
                    upstream_services=upstream,
                    downstream_services=downstream,
                    conflicting_changes=conflicts,
                    dependency_risk=min(dep_risk, 1.0),
                    freeze_window_conflict=False,
                )
            )
        return checks

    async def process_approval(
        self,
        assessments: list[RiskAssessment],
        dep_checks: list[DependencyCheck],
    ) -> list[ApprovalDecision]:
        """Process approval or rejection for changes."""
        logger.info(
            "scm.process_approval",
            count=len(assessments),
        )

        dep_map = {d.change_id: d for d in dep_checks}
        decisions: list[ApprovalDecision] = []
        for i, ra in enumerate(assessments):
            dep = dep_map.get(ra.change_id)
            has_conflicts = bool(dep and dep.conflicting_changes)

            if ra.risk_level == ChangeRiskLevel.CRITICAL:
                status = ApprovalStatus.ESCALATED
                reason = "Critical risk requires CAB review"
            elif ra.risk_score > 0.8 or has_conflicts:
                status = ApprovalStatus.REJECTED
                reason = (
                    "High combined risk and dependency conflicts"
                    if has_conflicts
                    else "Risk score exceeds threshold"
                )
            elif ra.risk_score < 0.35 and not has_conflicts:
                status = ApprovalStatus.AUTO_APPROVED
                reason = "Low risk, no dependency conflicts"
            else:
                status = ApprovalStatus.APPROVED
                reason = "Risk within acceptable range"

            decisions.append(
                ApprovalDecision(
                    id=_gen_id("AD", ra.change_id, i),
                    change_id=ra.change_id,
                    status=status,
                    approver="change-bot" if status == ApprovalStatus.AUTO_APPROVED else "cab-team",
                    reason=reason,
                    conditions=ra.mitigations if status == ApprovalStatus.APPROVED else [],
                    approved_at=f"2026-03-30T{11 + i}:00:00Z",
                )
            )
        return decisions

    async def monitor_rollout(
        self,
        decisions: list[ApprovalDecision],
    ) -> list[RolloutMetric]:
        """Monitor post-change rollout health."""
        logger.info(
            "scm.monitor_rollout",
            count=len(decisions),
        )

        approved = [
            d
            for d in decisions
            if d.status in (ApprovalStatus.APPROVED, ApprovalStatus.AUTO_APPROVED)
        ]
        metrics: list[RolloutMetric] = []
        idx = 0
        for dec in approved:
            for metric_name in _ROLLOUT_METRICS:
                baseline = random.uniform(10.0, 80.0)  # noqa: S311
                current = baseline * random.uniform(0.9, 1.15)  # noqa: S311
                threshold = baseline * 1.2
                breached = current > threshold
                metrics.append(
                    RolloutMetric(
                        id=_gen_id("RM", dec.change_id, idx),
                        change_id=dec.change_id,
                        metric_name=metric_name,
                        baseline_value=round(baseline, 2),
                        current_value=round(current, 2),
                        threshold=round(threshold, 2),
                        breached=breached,
                        rollback_recommended=breached and metric_name == "error_rate",
                    )
                )
                idx += 1
        return metrics

    async def record_metric(
        self,
        change_id: str,
        metric_name: str,
        value: float,
    ) -> dict[str, Any]:
        """Record a custom metric for a change."""
        logger.info(
            "scm.record_metric",
            change_id=change_id,
            metric=metric_name,
        )
        return {
            "change_id": change_id,
            "metric": metric_name,
            "value": value,
            "recorded": True,
        }
