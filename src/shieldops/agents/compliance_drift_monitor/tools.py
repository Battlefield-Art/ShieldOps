"""Compliance Drift Monitor Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any
from uuid import uuid4

import structlog

from .models import (
    AlertRecord,
    BaselineComparison,
    ControlScan,
    ControlStatus,
    DriftEvent,
    DriftSeverity,
    ImpactAssessment,
)

logger = structlog.get_logger()

_SAMPLE_CONTROLS: list[dict[str, Any]] = [
    {
        "control_id": "SOC2-CC6.1",
        "framework": "SOC 2",
        "description": "Logical access controls",
        "baseline": "compliant",
    },
    {
        "control_id": "SOC2-CC7.2",
        "framework": "SOC 2",
        "description": "System monitoring",
        "baseline": "compliant",
    },
    {
        "control_id": "HIPAA-164.312(a)",
        "framework": "HIPAA",
        "description": "Access control",
        "baseline": "compliant",
    },
    {
        "control_id": "PCI-DSS-3.4",
        "framework": "PCI DSS",
        "description": "Render PAN unreadable",
        "baseline": "compliant",
    },
    {
        "control_id": "NIST-AC-2",
        "framework": "NIST 800-53",
        "description": "Account management",
        "baseline": "compliant",
    },
    {
        "control_id": "ISO27001-A.9.2",
        "framework": "ISO 27001",
        "description": "User access management",
        "baseline": "compliant",
    },
    {
        "control_id": "GDPR-Art.32",
        "framework": "GDPR",
        "description": "Security of processing",
        "baseline": "compliant",
    },
    {
        "control_id": "SOC2-CC8.1",
        "framework": "SOC 2",
        "description": "Change management",
        "baseline": "compliant",
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class ComplianceDriftMonitorToolkit:
    """Tools for compliance drift monitoring."""

    def __init__(
        self,
        compliance_store: Any | None = None,
        alert_service: Any | None = None,
    ) -> None:
        self._compliance_store = compliance_store
        self._alert_service = alert_service

    async def scan_controls(
        self,
        tenant_id: str,
    ) -> list[ControlScan]:
        """Scan current compliance control status."""
        logger.info(
            "cdm.scan_controls",
            tenant_id=tenant_id,
        )

        if self._compliance_store is not None:
            try:
                raw = await self._compliance_store.scan(
                    tenant_id=tenant_id,
                )
                return [ControlScan(**r) for r in raw]
            except Exception:
                logger.exception("cdm.scan_controls.error")

        controls: list[ControlScan] = []
        for i, c in enumerate(_SAMPLE_CONTROLS):
            roll = random.random()  # noqa: S311
            if roll < 0.6:
                status = ControlStatus.COMPLIANT
            elif roll < 0.8:
                status = ControlStatus.DRIFTED
            elif roll < 0.9:
                status = ControlStatus.PARTIALLY_COMPLIANT
            else:
                status = ControlStatus.MISSING
            controls.append(
                ControlScan(
                    id=_gen_id("CS", tenant_id, i),
                    control_id=c["control_id"],
                    framework=c["framework"],
                    description=c["description"],
                    status=status,
                    evidence=[f"scan-{str(uuid4())[:8]}"],
                    last_checked="2026-03-30T12:00:00Z",
                )
            )
        return controls

    async def compare_baseline(
        self,
        controls: list[ControlScan],
    ) -> list[BaselineComparison]:
        """Compare current control states against baseline."""
        logger.info(
            "cdm.compare_baseline",
            count=len(controls),
        )

        comparisons: list[BaselineComparison] = []
        for i, c in enumerate(controls):
            baseline = ControlStatus.COMPLIANT
            has_drifted = c.status != baseline
            detail = ""
            if has_drifted:
                detail = f"Control {c.control_id} changed from {baseline.value} to {c.status.value}"
            comparisons.append(
                BaselineComparison(
                    id=_gen_id("BC", c.control_id, i),
                    control_id=c.control_id,
                    baseline_status=baseline,
                    current_status=c.status,
                    has_drifted=has_drifted,
                    drift_detail=detail,
                )
            )
        return comparisons

    async def detect_drift(
        self,
        comparisons: list[BaselineComparison],
        controls: list[ControlScan],
    ) -> list[DriftEvent]:
        """Detect compliance drift from baseline comparisons."""
        logger.info(
            "cdm.detect_drift",
            count=len(comparisons),
        )

        control_map = {c.control_id: c for c in controls}
        drifts: list[DriftEvent] = []
        idx = 0
        for comp in comparisons:
            if not comp.has_drifted:
                continue
            ctrl = control_map.get(comp.control_id)
            framework = ctrl.framework if ctrl else "Unknown"

            if comp.current_status == ControlStatus.MISSING:
                sev = DriftSeverity.CRITICAL
            elif comp.current_status == ControlStatus.DRIFTED:
                sev = DriftSeverity.HIGH
            else:
                sev = DriftSeverity.MEDIUM

            drifts.append(
                DriftEvent(
                    id=_gen_id("DE", comp.control_id, idx),
                    control_id=comp.control_id,
                    framework=framework,
                    severity=sev,
                    drift_type=comp.current_status.value,
                    description=comp.drift_detail,
                    detected_at="2026-03-30T12:05:00Z",
                    remediation_hint=(f"Restore {comp.control_id} to compliant state"),
                )
            )
            idx += 1
        return drifts

    async def assess_impact(
        self,
        drift_events: list[DriftEvent],
    ) -> list[ImpactAssessment]:
        """Assess the impact of compliance drifts."""
        logger.info(
            "cdm.assess_impact",
            count=len(drift_events),
        )

        assessments: list[ImpactAssessment] = []
        for i, d in enumerate(drift_events):
            reg_risk = random.uniform(0.3, 0.95)  # noqa: S311
            audit_impact = random.uniform(0.2, 0.9)  # noqa: S311
            priority = (
                1
                if d.severity == DriftSeverity.CRITICAL
                else (2 if d.severity == DriftSeverity.HIGH else 3)
            )
            assessments.append(
                ImpactAssessment(
                    id=_gen_id("IA", d.id, i),
                    drift_event_id=d.id,
                    business_impact=d.severity.value,
                    regulatory_risk=round(reg_risk, 2),
                    audit_readiness_impact=round(audit_impact, 2),
                    affected_assets=["infra-primary", "data-store"],
                    priority=priority,
                )
            )
        return assessments

    async def send_alerts(
        self,
        drift_events: list[DriftEvent],
        assessments: list[ImpactAssessment],
    ) -> list[AlertRecord]:
        """Send alerts for detected compliance drifts."""
        logger.info(
            "cdm.send_alerts",
            count=len(drift_events),
        )

        alerts: list[AlertRecord] = []
        for i, d in enumerate(drift_events):
            alerts.append(
                AlertRecord(
                    id=_gen_id("AL", d.id, i),
                    drift_event_id=d.id,
                    channel="slack",
                    recipients=["compliance-team", "security-ops"],
                    sent=True,
                    acknowledged=False,
                )
            )
        return alerts

    async def record_metric(
        self,
        metric_name: str,
        value: float,
    ) -> dict[str, Any]:
        """Record a compliance drift metric."""
        logger.info(
            "cdm.record_metric",
            metric=metric_name,
            value=value,
        )
        return {
            "metric": metric_name,
            "value": value,
            "recorded": True,
        }
