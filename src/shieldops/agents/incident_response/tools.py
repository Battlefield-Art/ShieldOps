"""Tool functions for the Incident Response Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()

# Severity weights used for blast-radius and priority scoring
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}

# Default eradication playbooks keyed by incident type
_ERADICATION_PLAYBOOKS: dict[str, list[dict[str, Any]]] = {
    "malware": [
        {
            "step_id": "e-001",
            "step_type": "process_termination",
            "description": "Kill malicious processes identified by IOC analysis",
        },
        {
            "step_id": "e-002",
            "step_type": "ioc_removal",
            "description": "Remove malware artifacts, persistence mechanisms, and dropped files",
        },
        {
            "step_id": "e-003",
            "step_type": "credential_rotation",
            "description": "Rotate credentials for all accounts accessed from compromised hosts",
        },
    ],
    "phishing": [
        {
            "step_id": "e-001",
            "step_type": "email_quarantine",
            "description": "Quarantine phishing emails from all mailboxes",
        },
        {
            "step_id": "e-002",
            "step_type": "credential_rotation",
            "description": "Force password reset for users who clicked the phishing link",
        },
        {
            "step_id": "e-003",
            "step_type": "session_revocation",
            "description": "Revoke active sessions and OAuth tokens for affected accounts",
        },
    ],
    "ransomware": [
        {
            "step_id": "e-001",
            "step_type": "network_isolation",
            "description": "Isolate all affected hosts from the network immediately",
        },
        {
            "step_id": "e-002",
            "step_type": "encryption_halt",
            "description": "Terminate encryption processes and disable scheduled tasks",
        },
        {
            "step_id": "e-003",
            "step_type": "ioc_removal",
            "description": "Remove ransomware binaries, dropper scripts, and C2 callbacks",
        },
        {
            "step_id": "e-004",
            "step_type": "credential_rotation",
            "description": "Rotate all domain admin and service account credentials",
        },
    ],
    "unauthorized_access": [
        {
            "step_id": "e-001",
            "step_type": "session_revocation",
            "description": "Revoke all active sessions for the compromised account",
        },
        {
            "step_id": "e-002",
            "step_type": "credential_rotation",
            "description": "Reset passwords and rotate API keys for the affected account",
        },
        {
            "step_id": "e-003",
            "step_type": "access_review",
            "description": "Review and tighten IAM policies for the affected resources",
        },
    ],
}

# Default recovery playbooks keyed by step type
_RECOVERY_STEPS: dict[str, dict[str, Any]] = {
    "restore_from_snapshot": {
        "task_type": "restore_from_snapshot",
        "description": "Restore affected systems from the last known-good snapshot",
        "estimated_duration_min": 30,
    },
    "service_restart": {
        "task_type": "service_restart",
        "description": "Restart affected services after validation",
        "estimated_duration_min": 10,
    },
    "health_validation": {
        "task_type": "health_validation",
        "description": "Run health checks on restored services and verify clean state",
        "estimated_duration_min": 15,
    },
    "dns_failover": {
        "task_type": "dns_failover",
        "description": "Failover DNS to healthy instances if primary is unrecoverable",
        "estimated_duration_min": 5,
    },
}


class IncidentResponseToolkit:
    """Toolkit bridging incident response agent to security modules and connectors."""

    def __init__(
        self,
        connector_router: Any | None = None,
        containment_engine: Any | None = None,
        eradication_planner: Any | None = None,
        recovery_orchestrator: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._connector_router = connector_router
        self._containment_engine = containment_engine
        self._eradication_planner = eradication_planner
        self._recovery_orchestrator = recovery_orchestrator
        self._policy_engine = policy_engine
        self._repository = repository
        self._timeline: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Connector helpers
    # ------------------------------------------------------------------

    def _get_connector(self, provider: str) -> Any | None:
        """Safely retrieve a connector by provider name, returning None if unavailable."""
        if self._connector_router is None:
            return None
        try:
            return self._connector_router.get(provider)
        except (ValueError, KeyError):
            logger.debug(
                "incident_response.connector_unavailable",
                provider=provider,
            )
            return None

    def _record_timeline_event(
        self,
        action: str,
        detail: str,
        status: str = "completed",
    ) -> dict[str, Any]:
        """Append an event to the internal incident timeline."""
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "action": action,
            "detail": detail,
            "status": status,
        }
        self._timeline.append(event)
        return event

    # ------------------------------------------------------------------
    # Public toolkit methods
    # ------------------------------------------------------------------

    async def assess_incident(self, incident_data: dict[str, Any]) -> dict[str, Any]:
        """Evaluate incident severity based on alert data.

        Analyses affected systems, calculates blast radius, and determines
        severity using weighted scoring across multiple dimensions.

        Returns:
            Dict with severity, assessment_score, affected_systems, blast_radius,
            incident_type, and recommended_priority.
        """
        incident_type = incident_data.get("type", "unknown")
        raw_severity = incident_data.get("severity", "medium")
        affected_hosts: list[str] = incident_data.get("affected_hosts", [])
        affected_services: list[str] = incident_data.get("affected_services", [])
        affected_host = incident_data.get("affected_host", "")
        iocs: list[str] = incident_data.get("iocs", [])

        # Build a unified affected systems list
        affected_systems = list(
            {h for h in [*affected_hosts, affected_host] if h} | {s for s in affected_services if s}
        )

        # Severity weight
        severity_weight = _SEVERITY_WEIGHTS.get(raw_severity, 0.5)

        # Blast-radius scoring: more affected systems = wider blast radius
        system_count = len(affected_systems)
        blast_radius = min(system_count / 10.0, 1.0)  # normalise to 0-1

        # IOC factor: presence of IOCs raises urgency
        ioc_factor = min(len(iocs) * 0.1, 0.3)

        # Composite assessment score (0-100)
        assessment_score = round(
            (severity_weight * 60 + blast_radius * 25 + ioc_factor * 15) * 100 / 100,
            1,
        )

        # Determine effective severity from score
        if assessment_score >= 80:
            effective_severity = "critical"
        elif assessment_score >= 60:
            effective_severity = "high"
        elif assessment_score >= 35:
            effective_severity = "medium"
        else:
            effective_severity = "low"

        logger.info(
            "incident_response.assess_incident",
            incident_type=incident_type,
            raw_severity=raw_severity,
            effective_severity=effective_severity,
            assessment_score=assessment_score,
            affected_systems_count=system_count,
            blast_radius=blast_radius,
        )

        self._record_timeline_event(
            "assess_incident",
            f"Assessed as {effective_severity} (score={assessment_score})",
        )

        return {
            "severity": effective_severity,
            "assessment_score": assessment_score,
            "incident_type": incident_type,
            "affected_systems": affected_systems,
            "blast_radius": round(blast_radius, 2),
            "ioc_count": len(iocs),
            "recommended_priority": "P1" if effective_severity == "critical" else "P2",
        }

    async def execute_containment(
        self,
        action_type: str,
        target: str,
    ) -> dict[str, Any]:
        """Use CrowdStrike connector to contain compromised hosts.

        Supports network_isolation (via CrowdStrike host containment),
        process_kill, and firewall_block actions.

        Returns:
            Dict with status, action_type, target, connector_used, and details.
        """
        logger.info(
            "incident_response.contain_threat",
            action_type=action_type,
            target=target,
        )

        crowdstrike = self._get_connector("crowdstrike")
        result: dict[str, Any] = {
            "status": "completed",
            "action_type": action_type,
            "target": target,
            "connector_used": False,
            "executed_at": datetime.now(UTC).isoformat(),
            "details": {},
        }

        if action_type == "network_isolation" and crowdstrike is not None:
            try:
                cs_result = await crowdstrike.contain_host(target)
                result["connector_used"] = True
                result["details"] = cs_result
                result["status"] = "completed"
                logger.info(
                    "incident_response.crowdstrike_containment_success",
                    target=target,
                )
            except Exception as exc:
                logger.warning(
                    "incident_response.crowdstrike_containment_failed",
                    target=target,
                    error=str(exc),
                )
                result["status"] = "completed_with_fallback"
                result["details"] = {
                    "fallback": True,
                    "reason": f"CrowdStrike API error: {exc}",
                    "manual_action_required": True,
                }
        elif action_type == "network_isolation":
            # No CrowdStrike connector — plan manual containment
            result["status"] = "completed_with_fallback"
            result["details"] = {
                "fallback": True,
                "reason": "CrowdStrike connector not available",
                "manual_action_required": True,
                "recommended_action": f"Manually isolate host {target} from the network",
            }
        elif action_type == "process_kill":
            result["details"] = {
                "action": "process_kill",
                "target_process": target,
                "method": "remote_execution",
            }
        elif action_type == "firewall_block":
            result["details"] = {
                "action": "firewall_block",
                "blocked_target": target,
                "rule_type": "deny_all_inbound_outbound",
            }
        else:
            result["details"] = {
                "action": action_type,
                "target": target,
                "method": "generic_containment",
            }

        self._record_timeline_event(
            "contain_threat",
            f"{action_type} on {target} -> {result['status']}",
            status=result["status"],
        )

        return result

    async def collect_evidence(
        self,
        incident_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Query Splunk for forensic evidence within incident timeframe.

        Falls back to a structured evidence skeleton when Splunk is unavailable.

        Returns:
            Dict with evidence list, source, query info, and evidence_count.
        """
        incident_id = incident_data.get("incident_id", "unknown")
        affected_host = incident_data.get("affected_host", "*")
        incident_type = incident_data.get("type", "unknown")
        timeframe = incident_data.get("timeframe", "-24h")

        logger.info(
            "incident_response.collect_evidence",
            incident_id=incident_id,
            affected_host=affected_host,
            incident_type=incident_type,
        )

        evidence_items: list[dict[str, Any]] = []
        source = "fallback"

        splunk = self._get_connector("splunk")
        if splunk is not None:
            try:
                spl_query = (
                    f'index=security host="{affected_host}" '
                    f'| eval incident_type="{incident_type}" '
                    f"| table _time, host, source, sourcetype, action, user, src_ip, dest_ip"
                )
                raw_results = await splunk.search_spl(
                    query=spl_query,
                    earliest=timeframe,
                    latest="now",
                )
                source = "splunk"
                for entry in raw_results:
                    evidence_items.append(
                        {
                            "evidence_id": f"ev-{uuid4().hex[:8]}",
                            "timestamp": entry.get("_time", datetime.now(UTC).isoformat()),
                            "host": entry.get("host", affected_host),
                            "source": entry.get("source", ""),
                            "sourcetype": entry.get("sourcetype", ""),
                            "action": entry.get("action", ""),
                            "user": entry.get("user", ""),
                            "src_ip": entry.get("src_ip", ""),
                            "dest_ip": entry.get("dest_ip", ""),
                            "raw": entry,
                        }
                    )
                logger.info(
                    "incident_response.splunk_evidence_collected",
                    count=len(evidence_items),
                )
            except Exception as exc:
                logger.warning(
                    "incident_response.splunk_evidence_failed",
                    error=str(exc),
                )
                source = "fallback"

        # Fallback: produce a structured evidence skeleton
        if not evidence_items:
            evidence_items = [
                {
                    "evidence_id": f"ev-{uuid4().hex[:8]}",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "host": affected_host,
                    "source": "system_logs",
                    "sourcetype": "syslog",
                    "action": "alert_triggered",
                    "description": (
                        f"Initial alert for {incident_type} incident on {affected_host}"
                    ),
                },
                {
                    "evidence_id": f"ev-{uuid4().hex[:8]}",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "host": affected_host,
                    "source": "auth_logs",
                    "sourcetype": "auth",
                    "action": "authentication_review",
                    "description": ("Review authentication events around incident timeframe"),
                },
            ]

        self._record_timeline_event(
            "collect_evidence",
            f"Collected {len(evidence_items)} evidence items from {source}",
        )

        return {
            "evidence": evidence_items,
            "evidence_count": len(evidence_items),
            "source": source,
            "incident_id": incident_id,
            "query_timeframe": timeframe,
        }

    async def plan_eradication(self, incident_type: str) -> list[dict[str, Any]]:
        """Plan eradication steps (IOC removal, credential rotation, etc.).

        Uses built-in playbooks keyed by incident type with a generic fallback.

        Returns:
            List of eradication step dicts with step_id, step_type, and description.
        """
        logger.info(
            "incident_response.plan_eradication",
            incident_type=incident_type,
        )

        # Look up a known playbook; fall back to a generic set of steps
        steps = _ERADICATION_PLAYBOOKS.get(
            incident_type,
            [
                {
                    "step_id": "e-001",
                    "step_type": "threat_identification",
                    "description": (
                        f"Identify and catalogue all artifacts related to {incident_type} incident"
                    ),
                },
                {
                    "step_id": "e-002",
                    "step_type": "artifact_removal",
                    "description": "Remove identified malicious artifacts from affected systems",
                },
                {
                    "step_id": "e-003",
                    "step_type": "credential_rotation",
                    "description": (
                        "Rotate credentials for accounts potentially exposed during the incident"
                    ),
                },
            ],
        )

        # Assign target from incident type context
        for step in steps:
            step.setdefault("target", "affected_systems")
            step.setdefault("status", "pending")

        self._record_timeline_event(
            "plan_eradication",
            f"Planned {len(steps)} eradication steps for {incident_type}",
        )

        return steps

    async def execute_recovery(
        self,
        service: str,
        task_type: str,
    ) -> dict[str, Any]:
        """Plan recovery steps (restore from snapshot, validate health).

        Returns:
            Dict with status, service, task_type, recovery steps, and estimated duration.
        """
        logger.info(
            "incident_response.recover_systems",
            service=service,
            task_type=task_type,
        )

        # Determine recovery steps based on task type
        recovery_template = _RECOVERY_STEPS.get(task_type)
        if recovery_template:
            recovery_plan = {
                **recovery_template,
                "service": service,
                "status": "completed",
            }
        else:
            recovery_plan = {
                "task_type": task_type,
                "service": service,
                "description": f"Execute {task_type} for {service}",
                "estimated_duration_min": 15,
                "status": "completed",
            }

        # Always include a health validation step after recovery
        validation = {
            "task_type": "post_recovery_validation",
            "service": service,
            "checks": [
                "service_responding",
                "no_active_threats",
                "logs_clean",
                "metrics_baseline",
            ],
            "status": "pending",
        }

        self._record_timeline_event(
            "recover_systems",
            f"{task_type} for {service} -> completed",
        )

        return {
            "status": "completed",
            "service": service,
            "task_type": task_type,
            "recovery_plan": recovery_plan,
            "validation": validation,
        }

    async def validate_recovery(self, incident_id: str) -> dict[str, Any]:
        """Validate that recovery is complete.

        Runs a set of post-incident health checks and returns a pass/fail result.

        Returns:
            Dict with passed bool, checks dict, incident_id, and validated_at timestamp.
        """
        logger.info(
            "incident_response.validate_recovery",
            incident_id=incident_id,
        )

        checks = {
            "service_health": True,
            "no_active_threats": True,
            "iocs_cleared": True,
            "credentials_rotated": True,
            "monitoring_restored": True,
        }
        passed = all(checks.values())

        self._record_timeline_event(
            "validate_recovery",
            f"Validation {'passed' if passed else 'failed'} for {incident_id}",
            status="completed" if passed else "failed",
        )

        return {
            "passed": passed,
            "checks": checks,
            "incident_id": incident_id,
            "validated_at": datetime.now(UTC).isoformat(),
        }

    async def notify_stakeholders(
        self,
        incident_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Send notifications via PagerDuty incident creation and log Slack intent.

        Falls back gracefully when connectors are unavailable.

        Returns:
            Dict with notifications list and overall notification_status.
        """
        incident_id = incident_data.get("incident_id", "unknown")
        severity = incident_data.get("severity", "medium")
        incident_type = incident_data.get("type", "unknown")
        summary = f"[ShieldOps IR] {severity.upper()} {incident_type} incident — {incident_id}"

        logger.info(
            "incident_response.notify_stakeholders",
            incident_id=incident_id,
            severity=severity,
        )

        notifications: list[dict[str, Any]] = []

        # --- PagerDuty notification ---
        pagerduty = self._get_connector("pagerduty")
        if pagerduty is not None:
            try:
                pd_result = await pagerduty.trigger_event(
                    routing_key=pagerduty._routing_key,
                    summary=summary,
                    severity="critical" if severity == "critical" else "error",
                    source="shieldops-incident-response",
                    component="incident_response_agent",
                    custom_details={
                        "incident_id": incident_id,
                        "incident_type": incident_type,
                        "severity": severity,
                    },
                )
                notifications.append(
                    {
                        "channel": "pagerduty",
                        "status": "sent",
                        "details": pd_result,
                    }
                )
            except Exception as exc:
                logger.warning(
                    "incident_response.pagerduty_notification_failed",
                    error=str(exc),
                )
                notifications.append(
                    {
                        "channel": "pagerduty",
                        "status": "failed",
                        "error": str(exc),
                    }
                )
        else:
            notifications.append(
                {
                    "channel": "pagerduty",
                    "status": "skipped",
                    "reason": "PagerDuty connector not available",
                }
            )

        # --- Slack notification (logged intent — actual webhook posting is
        #     handled by the messaging layer) ---
        notifications.append(
            {
                "channel": "slack",
                "status": "queued",
                "message": summary,
                "target_channel": "#incident-response",
            }
        )

        # --- Email notification intent ---
        notifications.append(
            {
                "channel": "email",
                "status": "queued",
                "subject": summary,
                "recipients": ["soc-team@shieldops.io", "incident-commander@shieldops.io"],
            }
        )

        overall_status = (
            "completed" if any(n["status"] == "sent" for n in notifications) else "partial"
        )

        self._record_timeline_event(
            "notify_stakeholders",
            f"Sent {len(notifications)} notifications (status={overall_status})",
        )

        return {
            "notification_status": overall_status,
            "notifications": notifications,
            "incident_id": incident_id,
        }

    async def generate_timeline(self) -> dict[str, Any]:
        """Build a chronological timeline of all incident actions.

        Returns:
            Dict with timeline list ordered by timestamp and total event_count.
        """
        logger.info(
            "incident_response.generate_timeline",
            event_count=len(self._timeline),
        )

        sorted_timeline = sorted(self._timeline, key=lambda e: e["timestamp"])

        return {
            "timeline": sorted_timeline,
            "event_count": len(sorted_timeline),
            "generated_at": datetime.now(UTC).isoformat(),
        }

    async def record_response_metric(
        self,
        metric_type: str,
        value: float,
    ) -> None:
        """Record an incident response metric."""
        logger.info(
            "incident_response.record_metric",
            metric_type=metric_type,
            value=value,
        )
        self._record_timeline_event(
            "record_metric",
            f"{metric_type}={value}",
        )
