"""Zero Trust Network Access — Tool functions for ZTNA enforcement."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    AccessPoint,
    DevicePosture,
    IdentityTrustScore,
    IdentityType,
    PolicyEnforcement,
    SessionMonitor,
    TrustDecision,
)

logger = structlog.get_logger()

# Trust thresholds
_TRUST_ALLOW = 0.80
_TRUST_CHALLENGE = 0.60
_TRUST_RESTRICT = 0.40
_TRUST_DENY = 0.20

# Session limits
_SESSION_ANOMALY_LIMIT = 5
_SESSION_IDLE_MINUTES = 30
_MAX_SESSIONS_PER_IDENTITY = 100


class ZeroTrustNetworkToolkit:
    """Tools for identity-first zero trust network access."""

    def __init__(
        self,
        policy_engine: Any | None = None,
        identity_store: Any | None = None,
        alert_sink: Any | None = None,
    ) -> None:
        self._policy_engine = policy_engine
        self._identity_store = identity_store
        self._alert_sink = alert_sink
        self._access_points: dict[str, AccessPoint] = {}
        self._identity_cache: dict[str, IdentityTrustScore] = {}
        self._sessions: dict[str, SessionMonitor] = {}
        self._enforcement_log: list[PolicyEnforcement] = []

    # -- Discovery --

    async def discover_access_points(
        self,
        tenant_id: str,
        scope: str = "full",
    ) -> list[AccessPoint]:
        """Discover API, network, and MCP access points."""
        logger.info(
            "ztna.discover_access_points",
            tenant_id=tenant_id,
            scope=scope,
        )
        points: list[AccessPoint] = []

        # API gateway endpoints
        points.append(
            AccessPoint(
                access_point_id=f"{tenant_id}-api-gw",
                name="API Gateway",
                endpoint="/api/v1/*",
                protocol="https",
                identity_types_allowed=[
                    IdentityType.HUMAN.value,
                    IdentityType.SERVICE_ACCOUNT.value,
                    IdentityType.AI_AGENT.value,
                ],
                auth_method="jwt",
                encryption="tls_1_3",
                exposed=True,
                risk_score=0.3,
            )
        )

        # MCP tool server
        points.append(
            AccessPoint(
                access_point_id=f"{tenant_id}-mcp-server",
                name="MCP Tool Server",
                endpoint="mcp://tools/*",
                protocol="mcp",
                identity_types_allowed=[
                    IdentityType.AI_AGENT.value,
                    IdentityType.MCP_CLIENT.value,
                ],
                auth_method="oauth2_token",
                encryption="tls_1_3",
                exposed=True,
                risk_score=0.5,
            )
        )

        # Internal service mesh
        points.append(
            AccessPoint(
                access_point_id=f"{tenant_id}-svc-mesh",
                name="Service Mesh",
                endpoint="grpc://internal/*",
                protocol="grpc",
                identity_types_allowed=[
                    IdentityType.SERVICE_ACCOUNT.value,
                ],
                auth_method="mtls",
                encryption="mtls",
                exposed=False,
                risk_score=0.2,
            )
        )

        # SSH bastion
        points.append(
            AccessPoint(
                access_point_id=f"{tenant_id}-ssh-bastion",
                name="SSH Bastion",
                endpoint="ssh://bastion:22",
                protocol="ssh",
                identity_types_allowed=[
                    IdentityType.HUMAN.value,
                ],
                auth_method="certificate",
                encryption="ssh",
                exposed=True,
                risk_score=0.4,
            )
        )

        for p in points:
            self._access_points[p.access_point_id] = p

        return points

    # -- Identity Trust --

    async def assess_identity_trust(
        self,
        identity_id: str,
        identity_type: IdentityType,
        context: dict[str, Any] | None = None,
    ) -> IdentityTrustScore:
        """Compute composite trust score for an identity."""
        logger.info(
            "ztna.assess_identity_trust",
            identity_id=identity_id,
            identity_type=identity_type.value,
        )
        context = context or {}
        now = time.time()

        # Behavioral score
        behavioral = self._compute_behavioral_score(identity_id, identity_type, context)

        # Credential score
        credential = self._compute_credential_score(identity_id, identity_type, context)

        # History score
        history = self._compute_history_score(identity_id, context)

        # Composite trust
        composite = behavioral * 0.40 + credential * 0.35 + history * 0.25

        # Determine decision
        decision = self._score_to_decision(composite)

        anomalies: list[str] = []
        if behavioral < 0.5:
            anomalies.append("low_behavioral_score")
        if credential < 0.5:
            anomalies.append("weak_credentials")
        if history < 0.5:
            anomalies.append("poor_history")
        if identity_type == IdentityType.AI_AGENT and not context.get("mfa_enabled", False):
            anomalies.append("ai_agent_no_step_up_auth")
        if identity_type == IdentityType.MCP_CLIENT and context.get("god_key_detected", False):
            anomalies.append("mcp_god_key_detected")
            decision = TrustDecision.QUARANTINE

        score = IdentityTrustScore(
            identity_id=identity_id,
            identity_type=identity_type,
            display_name=context.get("display_name", ""),
            trust_score=round(composite, 4),
            behavioral_score=round(behavioral, 4),
            credential_score=round(credential, 4),
            history_score=round(history, 4),
            last_verified=now,
            mfa_enabled=context.get("mfa_enabled", False),
            anomalies=anomalies,
            decision=decision,
        )
        self._identity_cache[identity_id] = score
        return score

    # -- Device Posture --

    async def evaluate_device_posture(
        self,
        device_id: str,
        identity_id: str,
        context: dict[str, Any] | None = None,
    ) -> DevicePosture:
        """Assess device or runtime posture."""
        logger.info(
            "ztna.evaluate_device_posture",
            device_id=device_id,
            identity_id=identity_id,
        )
        context = context or {}
        issues: list[str] = []
        score = 1.0

        os_patched = context.get("os_patched", True)
        encryption = context.get("encryption_enabled", True)
        agent_runtime = context.get("agent_runtime", "unknown")

        if not os_patched:
            issues.append("os_not_patched")
            score -= 0.3
        if not encryption:
            issues.append("encryption_disabled")
            score -= 0.3
        if agent_runtime == "unknown":
            issues.append("unknown_agent_runtime")
            score -= 0.2

        compliant = score >= 0.6 and not issues

        return DevicePosture(
            device_id=device_id,
            identity_id=identity_id,
            os_type=context.get("os_type", "linux"),
            os_patched=os_patched,
            agent_runtime=agent_runtime,
            encryption_enabled=encryption,
            compliant=compliant,
            posture_score=round(max(score, 0.0), 4),
            issues=issues,
        )

    # -- Policy Enforcement --

    async def enforce_policy(
        self,
        identity_id: str,
        access_point_id: str,
        trust_score: float,
        device_compliant: bool,
        context: dict[str, Any] | None = None,
    ) -> PolicyEnforcement:
        """Enforce zero trust policy for an access request."""
        logger.info(
            "ztna.enforce_policy",
            identity_id=identity_id,
            access_point_id=access_point_id,
        )
        context = context or {}
        now = time.time()

        # Base decision from trust score
        decision = self._score_to_decision(trust_score)

        # Override: non-compliant device always restricted
        if not device_compliant:
            if decision == TrustDecision.ALLOW:
                decision = TrustDecision.RESTRICT
            elif decision == TrustDecision.CHALLENGE:
                decision = TrustDecision.DENY

        # Override: exposed endpoints need higher trust
        ap = self._access_points.get(access_point_id)
        if ap and ap.exposed and trust_score < _TRUST_ALLOW and decision == TrustDecision.ALLOW:
            decision = TrustDecision.CHALLENGE

        conditions: list[str] = []
        if decision == TrustDecision.CHALLENGE:
            conditions.append("mfa_required")
        if decision == TrustDecision.RESTRICT:
            conditions.append("read_only_access")
            conditions.append("session_recording")

        policy_hash = hashlib.sha256(f"{identity_id}:{access_point_id}:{now}".encode()).hexdigest()[
            :12
        ]

        enforcement = PolicyEnforcement(
            policy_id=f"ztna-{policy_hash}",
            identity_id=identity_id,
            access_point_id=access_point_id,
            decision=decision,
            reason=self._decision_reason(decision, trust_score, device_compliant),
            conditions=conditions,
            enforced_at=now,
        )
        self._enforcement_log.append(enforcement)
        return enforcement

    # -- Session Monitoring --

    async def monitor_session(
        self,
        session_id: str,
        identity_id: str,
        identity_type: IdentityType,
        access_point_id: str,
        request_count: int = 0,
        anomaly_signals: list[str] | None = None,
    ) -> SessionMonitor:
        """Continuously monitor an active session."""
        logger.info(
            "ztna.monitor_session",
            session_id=session_id,
            identity_id=identity_id,
        )
        now = time.time()
        anomaly_signals = anomaly_signals or []

        existing = self._sessions.get(session_id)
        if existing:
            started = existing.started_at
            total_requests = existing.requests_count + request_count
            total_anomalies = existing.anomaly_count + len(anomaly_signals)
        else:
            started = now
            total_requests = request_count
            total_anomalies = len(anomaly_signals)

        # Re-evaluate trust
        cached = self._identity_cache.get(identity_id)
        trust = cached.trust_score if cached else 0.5

        # Degrade trust on anomalies
        if total_anomalies > 0:
            penalty = min(total_anomalies * 0.05, 0.4)
            trust = max(trust - penalty, 0.0)

        # Determine status
        status = "active"
        if total_anomalies >= _SESSION_ANOMALY_LIMIT:
            status = "quarantined"
        elif trust < _TRUST_DENY:
            status = "terminated"

        session = SessionMonitor(
            session_id=session_id,
            identity_id=identity_id,
            identity_type=identity_type,
            access_point_id=access_point_id,
            started_at=started,
            last_activity=now,
            trust_score=round(trust, 4),
            requests_count=total_requests,
            anomaly_count=total_anomalies,
            status=status,
        )
        self._sessions[session_id] = session

        # Ring buffer
        if len(self._sessions) > _MAX_SESSIONS_PER_IDENTITY:
            oldest = min(
                self._sessions,
                key=lambda k: self._sessions[k].last_activity,
            )
            del self._sessions[oldest]

        return session

    async def get_session_summary(
        self,
    ) -> dict[str, Any]:
        """Get summary of all active sessions."""
        sessions = list(self._sessions.values())
        active = [s for s in sessions if s.status == "active"]
        quarantined = [s for s in sessions if s.status == "quarantined"]
        terminated = [s for s in sessions if s.status == "terminated"]
        return {
            "total_sessions": len(sessions),
            "active": len(active),
            "quarantined": len(quarantined),
            "terminated": len(terminated),
            "avg_trust": round(
                sum(s.trust_score for s in sessions) / max(len(sessions), 1),
                4,
            ),
        }

    # -- Internal Helpers --

    def _compute_behavioral_score(
        self,
        identity_id: str,
        identity_type: IdentityType,
        context: dict[str, Any],
    ) -> float:
        """Score identity behavior against baseline."""
        score = 0.8  # default
        if context.get("unusual_hours", False):
            score -= 0.2
        if context.get("geo_anomaly", False):
            score -= 0.3
        if context.get("rate_spike", False):
            score -= 0.2
        # AI agents get extra scrutiny
        if identity_type == IdentityType.AI_AGENT and context.get("tool_scope_violation", False):
            score -= 0.3
        if identity_type == IdentityType.MCP_CLIENT and context.get("unauthorized_tools", False):
            score -= 0.35
        return max(score, 0.0)

    def _compute_credential_score(
        self,
        identity_id: str,
        identity_type: IdentityType,
        context: dict[str, Any],
    ) -> float:
        """Score credential hygiene."""
        score = 0.9
        if not context.get("mfa_enabled", False):
            score -= 0.2
        if context.get("credential_age_days", 0) > 90:
            score -= 0.2
        if context.get("leaked_credential", False):
            score -= 0.5
        # Service accounts and API keys need rotation
        if (
            identity_type in (IdentityType.SERVICE_ACCOUNT, IdentityType.API_KEY)
            and context.get("credential_age_days", 0) > 30
        ):
            score -= 0.15
        return max(score, 0.0)

    def _compute_history_score(
        self,
        identity_id: str,
        context: dict[str, Any],
    ) -> float:
        """Score historical trustworthiness."""
        score = 0.85
        violations = context.get("past_violations", 0)
        if violations > 0:
            score -= min(violations * 0.1, 0.5)
        if context.get("first_seen_recently", False):
            score -= 0.2
        return max(score, 0.0)

    def _score_to_decision(
        self,
        score: float,
    ) -> TrustDecision:
        """Map trust score to access decision."""
        if score >= _TRUST_ALLOW:
            return TrustDecision.ALLOW
        if score >= _TRUST_CHALLENGE:
            return TrustDecision.CHALLENGE
        if score >= _TRUST_RESTRICT:
            return TrustDecision.RESTRICT
        if score >= _TRUST_DENY:
            return TrustDecision.DENY
        return TrustDecision.QUARANTINE

    def _decision_reason(
        self,
        decision: TrustDecision,
        trust_score: float,
        device_compliant: bool,
    ) -> str:
        """Generate human-readable reason for decision."""
        parts = [f"trust_score={trust_score:.2f}"]
        if not device_compliant:
            parts.append("device_non_compliant")
        parts.append(f"decision={decision.value}")
        return "; ".join(parts)
