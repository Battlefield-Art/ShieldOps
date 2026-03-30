"""Audit Trail Analyzer Agent — Tool functions."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import AuditSource

logger = structlog.get_logger()

_MOCK_EVENTS: list[dict[str, Any]] = [
    {
        "source": "identity",
        "actor": "admin@corp.com",
        "action": "login",
        "resource": "aws-console",
        "outcome": "success",
    },
    {
        "source": "identity",
        "actor": "admin@corp.com",
        "action": "assume_role",
        "resource": "arn:aws:iam::role/admin",
        "outcome": "success",
    },
    {
        "source": "cloud",
        "actor": "admin@corp.com",
        "action": "create_user",
        "resource": "iam",
        "outcome": "success",
    },
    {
        "source": "database",
        "actor": "svc-etl",
        "action": "bulk_export",
        "resource": "customer_db",
        "outcome": "success",
    },
    {
        "source": "application",
        "actor": "user-042",
        "action": "download",
        "resource": "/api/v1/reports/sensitive",
        "outcome": "success",
    },
    {
        "source": "network",
        "actor": "10.0.1.42",
        "action": "port_scan",
        "resource": "10.0.0.0/24",
        "outcome": "blocked",
    },
    {
        "source": "infrastructure",
        "actor": "deploy-bot",
        "action": "modify_security_group",
        "resource": "sg-prod-web",
        "outcome": "success",
    },
    {
        "source": "identity",
        "actor": "unknown@external.com",
        "action": "login",
        "resource": "vpn-gateway",
        "outcome": "failure",
    },
    {
        "source": "identity",
        "actor": "unknown@external.com",
        "action": "login",
        "resource": "vpn-gateway",
        "outcome": "failure",
    },
    {
        "source": "cloud",
        "actor": "svc-backup",
        "action": "delete_snapshot",
        "resource": "rds-prod",
        "outcome": "success",
    },
]

_ANOMALY_RULES = [
    {
        "pattern": "bulk_export",
        "type": "data_exfiltration",
        "severity": "high",
        "desc": "Bulk data export detected",
    },
    {
        "pattern": "port_scan",
        "type": "reconnaissance",
        "severity": "medium",
        "desc": "Port scanning activity detected",
    },
    {
        "pattern": "delete_snapshot",
        "type": "destructive_action",
        "severity": "high",
        "desc": "Production snapshot deletion",
    },
    {
        "pattern": "modify_security_group",
        "type": "config_change",
        "severity": "medium",
        "desc": "Security group modified",
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class AuditTrailAnalyzerToolkit:
    """Tools for audit trail analysis."""

    def __init__(
        self,
        log_collector: Any | None = None,
        anomaly_engine: Any | None = None,
        correlation_engine: Any | None = None,
    ) -> None:
        self._log_collector = log_collector
        self._anomaly_engine = anomaly_engine
        self._correlation_engine = correlation_engine

    async def collect_logs(
        self,
        tenant_id: str,
        sources: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Collect audit logs from sources."""
        logger.info(
            "ata.collect",
            tenant_id=tenant_id,
        )

        if self._log_collector is not None:
            try:
                return await self._log_collector.collect(
                    tenant_id=tenant_id,
                    sources=sources,
                )
            except Exception:
                logger.exception("ata.collect.error")

        now = time.time()
        results: list[dict[str, Any]] = []
        for i, evt in enumerate(_MOCK_EVENTS):
            results.append(
                {
                    "id": _gen_id("evt", tenant_id, i),
                    "source": evt["source"],
                    "actor": evt["actor"],
                    "action": evt["action"],
                    "resource": evt["resource"],
                    "timestamp": now - (i * 60),
                    "outcome": evt["outcome"],
                    "metadata": {},
                }
            )
        return results

    def normalize_event(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        """Normalize an audit event."""
        source = event.get("source", "application")
        try:
            AuditSource(source)
        except ValueError:
            source = "application"

        event["source"] = source
        event["actor"] = event.get("actor", "").strip().lower()
        event["action"] = event.get("action", "").strip().lower()
        event["normalized"] = True
        return event

    def detect_anomalies(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect anomalies in audit events."""
        anomalies: list[dict[str, Any]] = []
        idx = 0

        for rule in _ANOMALY_RULES:
            matching = [e for e in events if rule["pattern"] in e.get("action", "")]
            if matching:
                anomalies.append(
                    {
                        "id": _gen_id(
                            "anom",
                            rule["type"],
                            idx,
                        ),
                        "event_ids": [e.get("id", "") for e in matching],
                        "anomaly_type": rule["type"],
                        "description": rule["desc"],
                        "severity": rule["severity"],
                        "confidence": 0.85,
                    }
                )
                idx += 1

        # Detect brute force (repeated failures)
        failure_actors: dict[str, int] = {}
        failure_events: dict[str, list[str]] = {}
        for e in events:
            if e.get("outcome") == "failure":
                actor = e.get("actor", "")
                failure_actors[actor] = failure_actors.get(actor, 0) + 1
                failure_events.setdefault(
                    actor,
                    [],
                ).append(e.get("id", ""))

        for actor, count in failure_actors.items():
            if count >= 2:
                anomalies.append(
                    {
                        "id": _gen_id(
                            "anom",
                            actor,
                            idx,
                        ),
                        "event_ids": failure_events[actor],
                        "anomaly_type": "brute_force",
                        "description": (f"Repeated login failures from {actor} ({count}x)"),
                        "severity": "high",
                        "confidence": 0.9,
                    }
                )
                idx += 1

        return anomalies

    def correlate_activities(
        self,
        anomalies: list[dict[str, Any]],
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Correlate anomalies into findings."""
        findings: list[dict[str, Any]] = []

        for i, anom in enumerate(anomalies):
            event_ids = anom.get("event_ids", [])
            actors = set()
            for eid in event_ids:
                for e in events:
                    if e.get("id") == eid:
                        actors.add(e.get("actor", ""))

            findings.append(
                {
                    "id": _gen_id("fnd", anom["id"], i),
                    "anomaly_ids": [anom.get("id", "")],
                    "title": anom.get("description", ""),
                    "description": (f"{anom.get('anomaly_type')}: {anom.get('description')}"),
                    "severity": anom.get(
                        "severity",
                        "medium",
                    ),
                    "actor": ", ".join(actors),
                    "recommendation": (f"Investigate {anom.get('anomaly_type')} activity"),
                }
            )

        return findings

    def generate_report(
        self,
        events: list[dict[str, Any]],
        anomalies: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate audit trail analysis report."""
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        sources = list({e.get("source", "") for e in events})

        return {
            "total_events": len(events),
            "anomalies_detected": len(anomalies),
            "total_findings": len(findings),
            "critical_findings": critical,
            "high_findings": high,
            "sources_covered": sources,
            "findings": findings,
            "generated_at": time.time(),
        }
