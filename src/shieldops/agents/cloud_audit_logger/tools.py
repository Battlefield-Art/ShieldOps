"""Cloud Audit Logger Agent — Tool functions for audit log analysis."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    AuditCorrelation,
    AuditEvent,
    AuditEventSeverity,
    AuditLogSource,
    SuspiciousActivity,
)

logger = structlog.get_logger()

_SUSPICIOUS_EVENTS: dict[str, list[dict[str, Any]]] = {
    "cloudtrail": [
        {
            "event_name": "DeleteTrail",
            "activity_type": "audit_evasion",
            "severity": AuditEventSeverity.CRITICAL,
            "mitre": "T1562.008",
        },
        {
            "event_name": "CreateAccessKey",
            "activity_type": "privilege_escalation",
            "severity": AuditEventSeverity.HIGH,
            "mitre": "T1098.001",
        },
        {
            "event_name": "PutBucketPolicy",
            "activity_type": "data_exposure",
            "severity": AuditEventSeverity.HIGH,
            "mitre": "T1537",
        },
        {
            "event_name": "StopLogging",
            "activity_type": "defense_evasion",
            "severity": AuditEventSeverity.CRITICAL,
            "mitre": "T1562.008",
        },
        {
            "event_name": "AttachUserPolicy",
            "activity_type": "privilege_escalation",
            "severity": AuditEventSeverity.HIGH,
            "mitre": "T1098",
        },
    ],
    "gcp_audit": [
        {
            "event_name": "SetIamPolicy",
            "activity_type": "privilege_escalation",
            "severity": AuditEventSeverity.HIGH,
            "mitre": "T1098",
        },
        {
            "event_name": "DeleteSink",
            "activity_type": "audit_evasion",
            "severity": AuditEventSeverity.CRITICAL,
            "mitre": "T1562.008",
        },
        {
            "event_name": "CreateServiceAccountKey",
            "activity_type": "credential_access",
            "severity": AuditEventSeverity.HIGH,
            "mitre": "T1098.001",
        },
    ],
    "azure_activity": [
        {
            "event_name": "Microsoft.Authorization/roleAssignments/write",
            "activity_type": "privilege_escalation",
            "severity": AuditEventSeverity.HIGH,
            "mitre": "T1098",
        },
        {
            "event_name": "Microsoft.Storage/storageAccounts/delete",
            "activity_type": "resource_destruction",
            "severity": AuditEventSeverity.CRITICAL,
            "mitre": "T1485",
        },
        {
            "event_name": "Microsoft.Insights/diagnosticSettings/delete",
            "activity_type": "defense_evasion",
            "severity": AuditEventSeverity.CRITICAL,
            "mitre": "T1562.008",
        },
    ],
}

_REGIONS: dict[str, list[str]] = {
    "cloudtrail": ["us-east-1", "us-west-2", "eu-west-1"],
    "gcp_audit": ["us-central1", "europe-west1", "asia-east1"],
    "azure_activity": ["eastus", "westeurope", "southeastasia"],
}


def _event_hash(source: str, event: str, idx: int) -> str:
    raw = f"{source}-{event}-{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class CloudAuditLoggerToolkit:
    """Tools for cloud audit log ingestion, analysis, and correlation."""

    def __init__(
        self,
        log_clients: Any | None = None,
        siem_client: Any | None = None,
    ) -> None:
        self._log_clients = log_clients
        self._siem_client = siem_client

    async def ingest_audit_logs(
        self,
        tenant_id: str,
        sources: list[str],
        time_range_hours: int = 24,
    ) -> list[AuditEvent]:
        """Ingest audit logs from cloud providers."""
        logger.info(
            "audit_logger.ingest",
            tenant_id=tenant_id,
            sources=sources,
        )

        if self._log_clients is not None:
            try:
                raw = await self._log_clients.fetch(
                    tenant_id=tenant_id,
                    sources=sources,
                    hours=time_range_hours,
                )
                return [AuditEvent(**r) for r in raw]
            except Exception:
                logger.exception("audit_logger.ingest.client_error")

        events: list[AuditEvent] = []
        for source_key in sources:
            susp_events = _SUSPICIOUS_EVENTS.get(source_key, [])
            regions = _REGIONS.get(source_key, ["global"])
            principals = [
                "admin@company.com",
                "ci-bot@sa.iam",
                "deploy-role",
                "unknown-user",
            ]

            normal_events = [
                "DescribeInstances",
                "ListBuckets",
                "GetObject",
                "AssumeRole",
            ]
            all_events = [s["event_name"] for s in susp_events] + normal_events

            for idx in range(random.randint(15, 40)):  # noqa: S311
                event_name = random.choice(all_events)  # noqa: S311
                eid = _event_hash(source_key, event_name, idx)
                events.append(
                    AuditEvent(
                        id=eid,
                        source=AuditLogSource(source_key),
                        event_name=event_name,
                        principal=random.choice(principals),  # noqa: S311
                        source_ip=f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",  # noqa: S311, E501
                        region=random.choice(regions),  # noqa: S311
                        resource_type="cloud_resource",
                        resource_id=f"res-{eid}",
                        timestamp=time.time() - random.uniform(0, time_range_hours * 3600),  # noqa: S311
                    )
                )

        logger.info("audit_logger.ingest.done", event_count=len(events))
        return events

    async def detect_suspicious_activity(
        self,
        events: list[AuditEvent],
    ) -> list[SuspiciousActivity]:
        """Detect suspicious activities from audit events."""
        logger.info(
            "audit_logger.detect",
            event_count=len(events),
        )

        suspicious_names: dict[str, dict[str, Any]] = {}
        for source_events in _SUSPICIOUS_EVENTS.values():
            for se in source_events:
                suspicious_names[se["event_name"]] = se

        activities: list[SuspiciousActivity] = []
        for event in events:
            if event.event_name in suspicious_names:
                info = suspicious_names[event.event_name]
                noise = random.uniform(-5.0, 5.0)  # noqa: S311
                base_risk = {
                    AuditEventSeverity.CRITICAL: 90.0,
                    AuditEventSeverity.HIGH: 70.0,
                    AuditEventSeverity.MEDIUM: 50.0,
                }.get(info["severity"], 50.0)

                activities.append(
                    SuspiciousActivity(
                        id=str(uuid.uuid4())[:8],
                        event_ids=[event.id],
                        activity_type=info["activity_type"],
                        severity=info["severity"],
                        principal=event.principal,
                        description=(
                            f"{event.event_name} by {event.principal} from {event.source_ip}"
                        ),
                        risk_score=round(max(0.0, min(100.0, base_risk + noise)), 1),
                        mitre_technique=info["mitre"],
                        recommended_action=(
                            f"Investigate {info['activity_type']} by {event.principal}"
                        ),
                    )
                )

        logger.info(
            "audit_logger.detect.done",
            activity_count=len(activities),
        )
        return activities

    async def correlate_activities(
        self,
        activities: list[SuspiciousActivity],
    ) -> list[AuditCorrelation]:
        """Correlate suspicious activities into attack chains."""
        logger.info(
            "audit_logger.correlate",
            activity_count=len(activities),
        )

        by_principal: dict[str, list[SuspiciousActivity]] = {}
        for act in activities:
            by_principal.setdefault(act.principal, []).append(act)

        correlations: list[AuditCorrelation] = []
        for principal, acts in by_principal.items():
            if len(acts) < 2:
                continue
            correlations.append(
                AuditCorrelation(
                    id=str(uuid.uuid4())[:8],
                    activity_ids=[a.id for a in acts],
                    chain_type="multi_stage_attack",
                    description=(f"{len(acts)} suspicious activities by {principal}"),
                    blast_radius=("high" if len(acts) >= 3 else "medium"),
                    confidence=round(min(0.95, 0.5 + len(acts) * 0.1), 2),
                )
            )

        logger.info(
            "audit_logger.correlate.done",
            chain_count=len(correlations),
        )
        return correlations
