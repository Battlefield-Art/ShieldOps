"""Privilege Escalation Detector Agent — Tool functions for escalation detection."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    EscalationEvent,
    EscalationFinding,
    EscalationType,
    ResponseAction,
    RiskAssessment,
    ThreatSeverity,
)

logger = structlog.get_logger()

# Detection thresholds
_RAPID_ESCALATION_WINDOW_SEC = 600  # 10 minutes
_HIGH_CONFIDENCE_THRESHOLD = 0.85
_AUTO_RESPOND_THRESHOLD = 0.90
_MAX_SUDO_FAILURES_THRESHOLD = 5


class PrivilegeEscalationToolkit:
    """Tools for detecting privilege escalation attempts."""

    def __init__(
        self,
        identity_store: Any | None = None,
        cloud_connectors: dict[str, Any] | None = None,
        response_engine: Any | None = None,
    ) -> None:
        self._identity_store = identity_store
        self._cloud_connectors = cloud_connectors or {}
        self._response_engine = response_engine
        self._event_cache: dict[str, list[EscalationEvent]] = {}

    async def collect_escalation_events(
        self,
        tenant_id: str,
        time_window_hours: int = 24,
    ) -> list[EscalationEvent]:
        """Collect privilege-related events from all sources.

        Gathers sudo logs, IAM policy changes, role assignments,
        service account key creation, and privilege boundary
        modifications within the specified time window.
        """
        logger.info(
            "privilege_escalation.collect_events",
            tenant_id=tenant_id,
            time_window_hours=time_window_hours,
        )
        now = time.time()
        cutoff = now - (time_window_hours * 3600)
        events: list[EscalationEvent] = []

        for source_name, connector in self._cloud_connectors.items():
            try:
                if hasattr(connector, "get_privilege_events"):
                    raw = await connector.get_privilege_events(
                        tenant_id=tenant_id,
                        since=cutoff,
                    )
                    for evt in raw:
                        event = EscalationEvent(
                            id=evt.get(
                                "id",
                                hashlib.sha256(f"{source_name}:{evt}".encode()).hexdigest()[:16],
                            ),
                            principal_id=evt.get("principal_id", ""),
                            principal_type=evt.get("principal_type", "unknown"),
                            source_system=source_name,
                            action=evt.get("action", ""),
                            target_resource=evt.get("target_resource", ""),
                            previous_privilege=evt.get("previous_privilege", ""),
                            new_privilege=evt.get("new_privilege", ""),
                            timestamp=evt.get("timestamp", now),
                            geo_location=evt.get("geo_location", "unknown"),
                            risk_indicators=evt.get("risk_indicators", []),
                        )
                        events.append(event)
            except Exception:
                logger.warning(
                    "privilege_escalation.collect.error",
                    source=source_name,
                )

        if not self._cloud_connectors:
            events = self._generate_synthetic_events(tenant_id, cutoff, now)

        self._event_cache[tenant_id] = events
        return events

    async def classify_escalations(
        self,
        events: list[EscalationEvent],
    ) -> list[EscalationFinding]:
        """Classify events into escalation findings.

        Detects: sudo abuse, unexpected role changes, IAM policy
        modifications, service account elevation, privilege
        boundary bypass, and token privilege escalation.
        """
        logger.info(
            "privilege_escalation.classify",
            event_count=len(events),
        )
        findings: list[EscalationFinding] = []

        findings.extend(self._detect_sudo_abuse(events))
        findings.extend(self._detect_role_changes(events))
        findings.extend(self._detect_iam_policy_modifications(events))
        findings.extend(self._detect_service_account_elevation(events))
        findings.extend(self._detect_privilege_boundary_bypass(events))
        findings.extend(self._detect_token_escalation(events))

        return findings

    async def assess_risk(
        self,
        findings: list[EscalationFinding],
    ) -> list[RiskAssessment]:
        """Evaluate risk for each detected escalation finding."""
        logger.info(
            "privilege_escalation.assess_risk",
            finding_count=len(findings),
        )
        assessments: list[RiskAssessment] = []

        for finding in findings:
            severity = self._compute_severity(finding)
            containment = self._recommend_containment(finding, severity)

            affected_resources: list[str] = []
            affected_identities: list[str] = [finding.principal_id]

            for hop in finding.timeline:
                resource = hop.get("target_resource", "")
                if resource and resource not in affected_resources:
                    affected_resources.append(resource)
                identity = hop.get("principal_id", "")
                if identity and identity not in affected_identities:
                    affected_identities.append(identity)

            assessment = RiskAssessment(
                id=hashlib.sha256(f"risk:{finding.id}".encode()).hexdigest()[:16],
                finding_id=finding.id,
                severity=severity,
                affected_resources=affected_resources,
                affected_identities=affected_identities,
                blast_radius=len(affected_resources) + len(affected_identities),
                containment_actions=containment,
            )
            assessments.append(assessment)

        return assessments

    async def execute_response(
        self,
        findings: list[EscalationFinding],
        assessments: list[RiskAssessment],
    ) -> list[ResponseAction]:
        """Execute response actions based on confidence thresholds.

        Auto-executes containment for high-confidence detections
        (>=0.90). Generates recommendations for lower confidence.
        """
        logger.info(
            "privilege_escalation.execute_response",
            finding_count=len(findings),
            assessment_count=len(assessments),
        )
        actions: list[ResponseAction] = []
        assessment_map = {a.finding_id: a for a in assessments}

        for finding in findings:
            assessment = assessment_map.get(finding.id)
            if not assessment:
                continue

            auto_execute = finding.confidence >= _AUTO_RESPOND_THRESHOLD

            for containment_action in assessment.containment_actions:
                action_type, target = self._parse_containment(containment_action, finding)
                success = False

                if auto_execute and self._response_engine:
                    try:
                        await self._response_engine.execute(
                            action_type=action_type,
                            target=target,
                        )
                        success = True
                    except Exception:
                        logger.warning(
                            "privilege_escalation.response.failed",
                            action_type=action_type,
                            target=target,
                        )
                elif auto_execute:
                    success = False

                action = ResponseAction(
                    id=hashlib.sha256(f"resp:{finding.id}:{action_type}".encode()).hexdigest()[:16],
                    finding_id=finding.id,
                    action_type=action_type,
                    target=target,
                    description=(f"{assessment.severity.value} severity: {containment_action}"),
                    auto_executed=(auto_execute and self._response_engine is not None),
                    success=success,
                )
                actions.append(action)

        return actions

    # -- Detection helpers --

    def _detect_sudo_abuse(self, events: list[EscalationEvent]) -> list[EscalationFinding]:
        """Detect sudo abuse: repeated failures, unusual commands."""
        findings: list[EscalationFinding] = []
        sudo_actions = {
            "sudo",
            "sudo_failed",
            "sudo_su",
            "sudo_root",
            "pkexec",
        }

        sudo_events = [e for e in events if e.action in sudo_actions]
        if not sudo_events:
            return findings

        principal_groups: dict[str, list[EscalationEvent]] = {}
        for evt in sudo_events:
            principal_groups.setdefault(evt.principal_id, []).append(evt)

        for principal_id, evts in principal_groups.items():
            failures = [e for e in evts if e.action == "sudo_failed"]
            if len(failures) >= _MAX_SUDO_FAILURES_THRESHOLD:
                sorted_evts = sorted(evts, key=lambda e: e.timestamp)
                timeline = [
                    {
                        "principal_id": e.principal_id,
                        "source": e.source_system,
                        "action": e.action,
                        "target_resource": e.target_resource,
                        "timestamp": e.timestamp,
                    }
                    for e in sorted_evts
                ]
                finding = EscalationFinding(
                    id=hashlib.sha256(f"sudo:{principal_id}".encode()).hexdigest()[:16],
                    escalation_type=EscalationType.SUDO_ABUSE,
                    principal_id=principal_id,
                    source_system=sorted_evts[0].source_system,
                    target_resource=(sorted_evts[-1].target_resource),
                    privilege_delta="user -> root (sudo)",
                    confidence=min(0.6 + len(failures) * 0.05, 0.95),
                    mitre_technique="T1548.003",
                    timeline=timeline,
                )
                findings.append(finding)

        return findings

    def _detect_role_changes(self, events: list[EscalationEvent]) -> list[EscalationFinding]:
        """Detect unexpected role changes and assignments."""
        findings: list[EscalationFinding] = []
        role_actions = {
            "assign_role",
            "add_role_binding",
            "attach_policy",
            "grant_admin",
            "set_iam_policy",
        }

        role_events = [e for e in events if e.action in role_actions]
        if len(role_events) < 2:
            return findings

        sorted_events = sorted(role_events, key=lambda e: e.timestamp)
        chain: list[EscalationEvent] = []

        for evt in sorted_events:
            if not chain or (evt.timestamp - chain[-1].timestamp < _RAPID_ESCALATION_WINDOW_SEC):
                chain.append(evt)
            else:
                if len(chain) >= 2:
                    self._emit_role_finding(findings, chain)
                chain = [evt]

        if len(chain) >= 2:
            self._emit_role_finding(findings, chain)

        return findings

    def _emit_role_finding(
        self,
        findings: list[EscalationFinding],
        chain: list[EscalationEvent],
    ) -> None:
        """Create a role-change finding from a chain of events."""
        timeline = [
            {
                "principal_id": e.principal_id,
                "source": e.source_system,
                "action": e.action,
                "target_resource": e.target_resource,
                "timestamp": e.timestamp,
            }
            for e in chain
        ]
        fid = hashlib.sha256(
            f"role:{chain[0].principal_id}:{chain[0].timestamp}".encode()
        ).hexdigest()[:16]
        finding = EscalationFinding(
            id=fid,
            escalation_type=EscalationType.ROLE_CHANGE,
            principal_id=chain[0].principal_id,
            source_system=chain[0].source_system,
            target_resource=chain[-1].target_resource,
            privilege_delta=(f"{chain[0].action} -> {chain[-1].action}"),
            confidence=min(0.65 + len(chain) * 0.08, 0.95),
            mitre_technique="T1098",
            timeline=timeline,
        )
        findings.append(finding)

    def _detect_iam_policy_modifications(
        self, events: list[EscalationEvent]
    ) -> list[EscalationFinding]:
        """Detect IAM policy modifications (create, update, attach)."""
        findings: list[EscalationFinding] = []
        iam_actions = {
            "create_policy",
            "update_policy",
            "attach_policy",
            "put_role_policy",
            "create_access_key",
            "update_assume_role_policy",
        }

        iam_events = [e for e in events if e.action in iam_actions]
        if not iam_events:
            return findings

        principal_groups: dict[str, list[EscalationEvent]] = {}
        for evt in iam_events:
            principal_groups.setdefault(evt.principal_id, []).append(evt)

        for principal_id, evts in principal_groups.items():
            if len(evts) >= 2:
                sorted_evts = sorted(evts, key=lambda e: e.timestamp)
                timeline = [
                    {
                        "principal_id": e.principal_id,
                        "source": e.source_system,
                        "action": e.action,
                        "target_resource": e.target_resource,
                        "timestamp": e.timestamp,
                    }
                    for e in sorted_evts
                ]
                finding = EscalationFinding(
                    id=hashlib.sha256(f"iam:{principal_id}".encode()).hexdigest()[:16],
                    escalation_type=(EscalationType.IAM_POLICY_MODIFICATION),
                    principal_id=principal_id,
                    source_system=sorted_evts[0].source_system,
                    target_resource=(sorted_evts[-1].target_resource),
                    privilege_delta=(f"IAM: {len(evts)} policy modifications"),
                    confidence=min(0.7 + len(evts) * 0.05, 0.95),
                    mitre_technique="T1098.001",
                    timeline=timeline,
                )
                findings.append(finding)

        return findings

    def _detect_service_account_elevation(
        self, events: list[EscalationEvent]
    ) -> list[EscalationFinding]:
        """Detect service account privilege elevation."""
        findings: list[EscalationFinding] = []
        sa_elevation_actions = {
            "create_service_account_key",
            "impersonate_service_account",
            "enable_service_account",
            "set_iam_binding_sa",
        }

        sa_events = [
            e
            for e in events
            if e.action in sa_elevation_actions or e.principal_type == "service_account"
        ]
        if not sa_events:
            return findings

        principal_groups: dict[str, list[EscalationEvent]] = {}
        for evt in sa_events:
            principal_groups.setdefault(evt.principal_id, []).append(evt)

        for principal_id, evts in principal_groups.items():
            elevation = [e for e in evts if e.action in sa_elevation_actions]
            if len(elevation) >= 1:
                sorted_evts = sorted(evts, key=lambda e: e.timestamp)
                timeline = [
                    {
                        "principal_id": e.principal_id,
                        "source": e.source_system,
                        "action": e.action,
                        "target_resource": e.target_resource,
                        "timestamp": e.timestamp,
                    }
                    for e in sorted_evts
                ]
                finding = EscalationFinding(
                    id=hashlib.sha256(f"sa_elev:{principal_id}".encode()).hexdigest()[:16],
                    escalation_type=(EscalationType.SERVICE_ACCOUNT_ELEVATION),
                    principal_id=principal_id,
                    source_system=sorted_evts[0].source_system,
                    target_resource=(sorted_evts[-1].target_resource),
                    privilege_delta=(f"SA elevation: {len(elevation)} actions"),
                    confidence=min(0.65 + len(elevation) * 0.1, 0.95),
                    mitre_technique="T1078.004",
                    timeline=timeline,
                )
                findings.append(finding)

        return findings

    def _detect_privilege_boundary_bypass(
        self, events: list[EscalationEvent]
    ) -> list[EscalationFinding]:
        """Detect privilege boundary bypass attempts."""
        findings: list[EscalationFinding] = []
        bypass_actions = {
            "delete_permission_boundary",
            "modify_permission_boundary",
            "detach_scp",
            "disable_guardrail",
            "bypass_mfa",
        }

        bypass_events = [e for e in events if e.action in bypass_actions]
        for evt in bypass_events:
            timeline = [
                {
                    "principal_id": evt.principal_id,
                    "source": evt.source_system,
                    "action": evt.action,
                    "target_resource": evt.target_resource,
                    "timestamp": evt.timestamp,
                }
            ]
            finding = EscalationFinding(
                id=hashlib.sha256(f"bypass:{evt.id}".encode()).hexdigest()[:16],
                escalation_type=(EscalationType.PRIVILEGE_BOUNDARY_BYPASS),
                principal_id=evt.principal_id,
                source_system=evt.source_system,
                target_resource=evt.target_resource,
                privilege_delta=(f"Boundary bypass: {evt.action}"),
                confidence=0.90,
                mitre_technique="T1548",
                timeline=timeline,
            )
            findings.append(finding)

        return findings

    def _detect_token_escalation(self, events: list[EscalationEvent]) -> list[EscalationFinding]:
        """Detect token privilege escalation (STS, OAuth scope widening)."""
        findings: list[EscalationFinding] = []
        token_actions = {
            "sts_assume_role",
            "oauth_scope_escalation",
            "token_exchange",
            "create_login_profile",
        }

        token_events = [e for e in events if e.action in token_actions]
        if len(token_events) < 2:
            return findings

        sorted_events = sorted(token_events, key=lambda e: e.timestamp)
        principal_groups: dict[str, list[EscalationEvent]] = {}
        for evt in sorted_events:
            principal_groups.setdefault(evt.principal_id, []).append(evt)

        for principal_id, evts in principal_groups.items():
            if len(evts) >= 2:
                timeline = [
                    {
                        "principal_id": e.principal_id,
                        "source": e.source_system,
                        "action": e.action,
                        "target_resource": e.target_resource,
                        "timestamp": e.timestamp,
                    }
                    for e in evts
                ]
                finding = EscalationFinding(
                    id=hashlib.sha256(f"token_esc:{principal_id}".encode()).hexdigest()[:16],
                    escalation_type=(EscalationType.TOKEN_PRIVILEGE_ESCALATION),
                    principal_id=principal_id,
                    source_system=evts[0].source_system,
                    target_resource=evts[-1].target_resource,
                    privilege_delta=(f"Token escalation: {len(evts)} hops"),
                    confidence=min(0.6 + len(evts) * 0.1, 0.95),
                    mitre_technique="T1134.001",
                    timeline=timeline,
                )
                findings.append(finding)

        return findings

    # -- Severity & containment helpers --

    def _compute_severity(self, finding: EscalationFinding) -> ThreatSeverity:
        """Compute severity from escalation type and confidence."""
        if finding.confidence >= 0.9:
            return ThreatSeverity.CRITICAL
        if finding.confidence >= 0.8 or finding.escalation_type in (
            EscalationType.PRIVILEGE_BOUNDARY_BYPASS,
            EscalationType.IAM_POLICY_MODIFICATION,
        ):
            return ThreatSeverity.HIGH
        if finding.confidence >= 0.6:
            return ThreatSeverity.MEDIUM
        if finding.confidence >= 0.4:
            return ThreatSeverity.LOW
        return ThreatSeverity.INFO

    def _recommend_containment(
        self,
        finding: EscalationFinding,
        severity: ThreatSeverity,
    ) -> list[str]:
        """Recommend containment actions."""
        actions: list[str] = []

        if severity in (
            ThreatSeverity.CRITICAL,
            ThreatSeverity.HIGH,
        ):
            actions.append(f"Revoke active sessions for {finding.principal_id}")

        if finding.escalation_type == EscalationType.SUDO_ABUSE:
            actions.append("Lock user account pending review")
            actions.append("Audit sudoers configuration")
        elif finding.escalation_type == EscalationType.ROLE_CHANGE:
            actions.append("Revert role assignment")
            actions.append("Review role assignment policies")
        elif finding.escalation_type == EscalationType.IAM_POLICY_MODIFICATION:
            actions.append("Revert IAM policy changes")
            actions.append("Enable IAM change alerting")
        elif finding.escalation_type == EscalationType.SERVICE_ACCOUNT_ELEVATION:
            actions.append("Rotate service account keys immediately")
            actions.append("Review service account IAM bindings")
        elif finding.escalation_type == EscalationType.PRIVILEGE_BOUNDARY_BYPASS:
            actions.append("Restore permission boundary immediately")
            actions.append("Enforce SCP guardrails")
        elif finding.escalation_type == EscalationType.TOKEN_PRIVILEGE_ESCALATION:
            actions.append("Invalidate escalated tokens")
            actions.append("Restrict STS assume-role trust")

        if severity == ThreatSeverity.CRITICAL:
            actions.append("Escalate to security incident response team")

        return actions

    def _parse_containment(self, action_str: str, finding: EscalationFinding) -> tuple[str, str]:
        """Parse containment action string into (type, target)."""
        action_lower = action_str.lower()
        if "revoke" in action_lower:
            return ("revoke_sessions", finding.principal_id)
        if "lock" in action_lower:
            return ("lock_account", finding.principal_id)
        if "revert" in action_lower:
            return ("revert_change", finding.target_resource)
        if "rotate" in action_lower:
            return (
                "rotate_credentials",
                finding.principal_id,
            )
        if "restore" in action_lower:
            return ("restore_boundary", finding.target_resource)
        if "invalidate" in action_lower:
            return ("invalidate_tokens", finding.principal_id)
        if "escalate" in action_lower:
            return ("escalate_incident", finding.id)
        return ("recommend", finding.principal_id)

    def _generate_synthetic_events(
        self,
        tenant_id: str,
        cutoff: float,
        now: float,
    ) -> list[EscalationEvent]:
        """Generate synthetic events when no connectors are available."""
        mid = (cutoff + now) / 2
        return [
            EscalationEvent(
                id=f"syn-{tenant_id}-1",
                principal_id=f"user-{tenant_id}-admin",
                principal_type="user",
                source_system="linux",
                action="sudo_failed",
                target_resource="/usr/bin/passwd",
                previous_privilege="user",
                new_privilege="root",
                timestamp=mid,
                geo_location="us-east-1",
                risk_indicators=["repeated_failure"],
            ),
            EscalationEvent(
                id=f"syn-{tenant_id}-2",
                principal_id=f"user-{tenant_id}-admin",
                principal_type="user",
                source_system="aws",
                action="attach_policy",
                target_resource=("arn:aws:iam::123:policy/AdminAccess"),
                previous_privilege="ReadOnly",
                new_privilege="AdministratorAccess",
                timestamp=mid + 120,
                geo_location="us-east-1",
                risk_indicators=[
                    "admin_escalation",
                    "self_assign",
                ],
            ),
            EscalationEvent(
                id=f"syn-{tenant_id}-3",
                principal_id=f"sa-{tenant_id}-compute",
                principal_type="service_account",
                source_system="gcp",
                action="impersonate_service_account",
                target_resource="sa-admin@project.iam",
                previous_privilege="compute.viewer",
                new_privilege="owner",
                timestamp=mid + 240,
                geo_location="us-central1",
                risk_indicators=[
                    "sa_impersonation",
                    "privilege_jump",
                ],
            ),
        ]
