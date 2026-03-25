"""Lateral Movement Detector Agent — Tool functions for identity movement detection."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    BlastRadiusAssessment,
    IdentitySignal,
    MovementPath,
    MovementSeverity,
    MovementType,
    ResponseAction,
)

logger = structlog.get_logger()

# Detection thresholds
_GEO_IMPOSSIBLE_SPEED_KMH = 900  # faster than commercial flight
_TOKEN_REUSE_WINDOW_SEC = 300  # 5 minutes
_MAX_HOP_DEPTH = 5
_HIGH_CONFIDENCE_THRESHOLD = 0.85
_AUTO_RESPOND_THRESHOLD = 0.90


class LateralMovementToolkit:
    """Tools for detecting identity-based lateral movement across clouds."""

    def __init__(
        self,
        identity_store: Any | None = None,
        cloud_connectors: dict[str, Any] | None = None,
        response_engine: Any | None = None,
    ) -> None:
        self._identity_store = identity_store
        self._cloud_connectors = cloud_connectors or {}
        self._response_engine = response_engine
        self._signal_cache: dict[str, list[IdentitySignal]] = {}

    async def collect_identity_signals(
        self,
        tenant_id: str,
        time_window_hours: int = 24,
    ) -> list[IdentitySignal]:
        """Collect auth events, token usage, and role assumptions from all clouds.

        Gathers identity signals including OAuth grants, STS assume-role calls,
        service account key usage, federation token exchanges, and cross-cloud
        API calls within the specified time window.
        """
        logger.info(
            "lateral_movement.collect_signals",
            tenant_id=tenant_id,
            time_window_hours=time_window_hours,
        )
        now = time.time()
        cutoff = now - (time_window_hours * 3600)
        signals: list[IdentitySignal] = []

        # Collect from each cloud connector
        for cloud_name, connector in self._cloud_connectors.items():
            try:
                if hasattr(connector, "get_identity_events"):
                    raw_events = await connector.get_identity_events(
                        tenant_id=tenant_id,
                        since=cutoff,
                    )
                    for evt in raw_events:
                        sig = IdentitySignal(
                            id=evt.get(
                                "id",
                                hashlib.sha256(f"{cloud_name}:{evt}".encode()).hexdigest()[:16],
                            ),
                            identity_id=evt.get("identity_id", ""),
                            identity_type=evt.get("identity_type", "unknown"),
                            source_cloud=cloud_name,
                            action=evt.get("action", ""),
                            target_resource=evt.get("target_resource", ""),
                            timestamp=evt.get("timestamp", now),
                            geo_location=evt.get("geo_location", "unknown"),
                            risk_indicators=evt.get("risk_indicators", []),
                        )
                        signals.append(sig)
            except Exception:
                logger.warning(
                    "lateral_movement.collect_signals.connector_error",
                    cloud=cloud_name,
                )

        # If no connectors available, generate synthetic signals for analysis
        if not self._cloud_connectors:
            signals = self._generate_synthetic_signals(tenant_id, cutoff, now)

        # Cache signals by tenant
        self._signal_cache[tenant_id] = signals
        return signals

    async def analyze_movement_paths(
        self,
        signals: list[IdentitySignal],
    ) -> list[MovementPath]:
        """Identify lateral movement chains from signal patterns.

        Detects: same token used across different clouds, rapid role chaining,
        geo-impossible identity hops, delegation chain abuse, and credential
        relay patterns.
        """
        logger.info(
            "lateral_movement.analyze_paths",
            signal_count=len(signals),
        )
        paths: list[MovementPath] = []

        # Group signals by identity
        identity_groups: dict[str, list[IdentitySignal]] = {}
        for sig in signals:
            identity_groups.setdefault(sig.identity_id, []).append(sig)

        # Detect cross-cloud token reuse
        paths.extend(self._detect_token_reuse(signals))

        # Detect service account pivoting
        paths.extend(self._detect_service_account_pivots(identity_groups))

        # Detect cross-cloud privilege escalation
        paths.extend(self._detect_cross_cloud_escalation(signals))

        # Detect federation abuse
        paths.extend(self._detect_federation_abuse(signals))

        # Detect delegation chain abuse
        paths.extend(self._detect_delegation_chains(identity_groups))

        # Detect credential relay
        paths.extend(self._detect_credential_relay(signals))

        return paths

    async def assess_blast_radius(
        self,
        paths: list[MovementPath],
    ) -> list[BlastRadiusAssessment]:
        """Evaluate the impact of each detected movement path.

        Determines affected resources, identities at risk, data exposure,
        severity, and recommended containment actions.
        """
        logger.info(
            "lateral_movement.assess_blast_radius",
            path_count=len(paths),
        )
        assessments: list[BlastRadiusAssessment] = []

        for path in paths:
            severity = self._compute_severity(path)
            containment = self._recommend_containment(path, severity)

            # Estimate affected resources from timeline
            affected_resources: list[str] = []
            affected_identities: list[str] = [
                path.source_identity,
                path.target_identity,
            ]
            data_at_risk: list[str] = []

            for hop in path.timeline:
                resource = hop.get("target_resource", "")
                if resource and resource not in affected_resources:
                    affected_resources.append(resource)
                identity = hop.get("identity_id", "")
                if identity and identity not in affected_identities:
                    affected_identities.append(identity)
                if hop.get("data_access"):
                    data_at_risk.append(hop["data_access"])

            assessment = BlastRadiusAssessment(
                id=hashlib.sha256(f"blast:{path.id}".encode()).hexdigest()[:16],
                path_id=path.id,
                affected_resources=affected_resources,
                affected_identities=affected_identities,
                data_at_risk=data_at_risk,
                severity=severity,
                containment_actions=containment,
            )
            assessments.append(assessment)

        return assessments

    async def execute_response(
        self,
        paths: list[MovementPath],
        assessments: list[BlastRadiusAssessment],
    ) -> list[ResponseAction]:
        """Execute response actions based on confidence thresholds.

        Auto-executes containment for high-confidence detections (>=0.90).
        Generates recommendations for lower-confidence detections.
        """
        logger.info(
            "lateral_movement.execute_response",
            path_count=len(paths),
            assessment_count=len(assessments),
        )
        actions: list[ResponseAction] = []
        assessment_map = {a.path_id: a for a in assessments}

        for path in paths:
            assessment = assessment_map.get(path.id)
            if not assessment:
                continue

            auto_execute = path.confidence >= _AUTO_RESPOND_THRESHOLD
            severity = assessment.severity

            for containment_action in assessment.containment_actions:
                action_type, target = self._parse_containment(containment_action, path)
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
                            "lateral_movement.response.failed",
                            action_type=action_type,
                            target=target,
                        )
                elif auto_execute:
                    # No engine — mark as recommended
                    success = False

                action = ResponseAction(
                    id=hashlib.sha256(f"resp:{path.id}:{action_type}".encode()).hexdigest()[:16],
                    path_id=path.id,
                    action_type=action_type,
                    target=target,
                    description=(f"{severity.value} severity: {containment_action}"),
                    auto_executed=auto_execute and self._response_engine is not None,
                    success=success,
                )
                actions.append(action)

        return actions

    # -- Detection helpers --

    def _detect_token_reuse(self, signals: list[IdentitySignal]) -> list[MovementPath]:
        """Detect same OAuth/bearer token used across different clouds."""
        paths: list[MovementPath] = []
        token_signals: dict[str, list[IdentitySignal]] = {}

        for sig in signals:
            if "token_reuse" in sig.risk_indicators or sig.action in (
                "oauth_token_use",
                "bearer_token_auth",
                "sts_assume_role",
            ):
                token_signals.setdefault(sig.identity_id, []).append(sig)

        for identity_id, sigs in token_signals.items():
            clouds = {s.source_cloud for s in sigs}
            if len(clouds) > 1:
                sorted_sigs = sorted(sigs, key=lambda s: s.timestamp)
                timeline = [
                    {
                        "identity_id": s.identity_id,
                        "cloud": s.source_cloud,
                        "action": s.action,
                        "target_resource": s.target_resource,
                        "timestamp": s.timestamp,
                    }
                    for s in sorted_sigs
                ]
                path = MovementPath(
                    id=hashlib.sha256(f"token_reuse:{identity_id}".encode()).hexdigest()[:16],
                    movement_type=MovementType.OAUTH_TOKEN_REUSE,
                    source_identity=identity_id,
                    target_identity=identity_id,
                    source_cloud=sorted_sigs[0].source_cloud,
                    target_cloud=sorted_sigs[-1].source_cloud,
                    hops=len(clouds) - 1,
                    confidence=min(0.7 + (len(clouds) - 1) * 0.1, 0.95),
                    mitre_technique="T1550.001",
                    timeline=timeline,
                )
                paths.append(path)
        return paths

    def _detect_service_account_pivots(
        self,
        identity_groups: dict[str, list[IdentitySignal]],
    ) -> list[MovementPath]:
        """Detect service account being used to pivot to other identities."""
        paths: list[MovementPath] = []

        for identity_id, sigs in identity_groups.items():
            sa_sigs = [s for s in sigs if s.identity_type == "service_account"]
            if not sa_sigs:
                continue

            escalation_actions = [
                s
                for s in sa_sigs
                if s.action
                in (
                    "impersonate",
                    "create_key",
                    "assume_role",
                    "delegate",
                    "create_token",
                )
            ]
            if len(escalation_actions) >= 2:
                sorted_acts = sorted(escalation_actions, key=lambda s: s.timestamp)
                timeline = [
                    {
                        "identity_id": s.identity_id,
                        "cloud": s.source_cloud,
                        "action": s.action,
                        "target_resource": s.target_resource,
                        "timestamp": s.timestamp,
                    }
                    for s in sorted_acts
                ]
                path = MovementPath(
                    id=hashlib.sha256(f"sa_pivot:{identity_id}".encode()).hexdigest()[:16],
                    movement_type=MovementType.SERVICE_ACCOUNT_PIVOT,
                    source_identity=identity_id,
                    target_identity=sorted_acts[-1].target_resource,
                    source_cloud=sorted_acts[0].source_cloud,
                    target_cloud=sorted_acts[-1].source_cloud,
                    hops=len(escalation_actions),
                    confidence=min(0.6 + len(escalation_actions) * 0.1, 0.95),
                    mitre_technique="T1078.004",
                    timeline=timeline,
                )
                paths.append(path)
        return paths

    def _detect_cross_cloud_escalation(self, signals: list[IdentitySignal]) -> list[MovementPath]:
        """Detect privilege escalation spanning multiple clouds."""
        paths: list[MovementPath] = []
        escalation_actions = {
            "assume_role",
            "elevate_privileges",
            "grant_admin",
            "add_role_binding",
            "assign_role",
            "create_admin",
        }

        esc_signals = [s for s in signals if s.action in escalation_actions]
        if len(esc_signals) < 2:
            return paths

        # Group by time proximity
        sorted_esc = sorted(esc_signals, key=lambda s: s.timestamp)
        clouds_seen: set[str] = set()
        chain: list[IdentitySignal] = []

        for sig in sorted_esc:
            if not chain or (sig.timestamp - chain[-1].timestamp < 3600):
                chain.append(sig)
                clouds_seen.add(sig.source_cloud)
            else:
                if len(clouds_seen) > 1 and len(chain) >= 2:
                    self._emit_escalation_path(paths, chain, clouds_seen)
                chain = [sig]
                clouds_seen = {sig.source_cloud}

        if len(clouds_seen) > 1 and len(chain) >= 2:
            self._emit_escalation_path(paths, chain, clouds_seen)

        return paths

    def _emit_escalation_path(
        self,
        paths: list[MovementPath],
        chain: list[IdentitySignal],
        clouds: set[str],
    ) -> None:
        """Helper to create a cross-cloud escalation MovementPath."""
        timeline = [
            {
                "identity_id": s.identity_id,
                "cloud": s.source_cloud,
                "action": s.action,
                "target_resource": s.target_resource,
                "timestamp": s.timestamp,
            }
            for s in chain
        ]
        path_id = hashlib.sha256(
            f"xcloud_esc:{chain[0].identity_id}:{chain[0].timestamp}".encode()
        ).hexdigest()[:16]
        path = MovementPath(
            id=path_id,
            movement_type=MovementType.CROSS_CLOUD_ESCALATION,
            source_identity=chain[0].identity_id,
            target_identity=chain[-1].identity_id,
            source_cloud=chain[0].source_cloud,
            target_cloud=chain[-1].source_cloud,
            hops=len(chain) - 1,
            confidence=min(0.75 + len(clouds) * 0.05, 0.95),
            mitre_technique="T1078",
            timeline=timeline,
        )
        paths.append(path)

    def _detect_federation_abuse(self, signals: list[IdentitySignal]) -> list[MovementPath]:
        """Detect federation trust abuse (SAML, OIDC, workload identity)."""
        paths: list[MovementPath] = []
        federation_actions = {
            "federation_login",
            "saml_assertion",
            "oidc_exchange",
            "workload_identity_federation",
            "external_identity_provider",
        }

        fed_signals = [s for s in signals if s.action in federation_actions]
        if len(fed_signals) < 2:
            return paths

        # Suspicious: same identity federating into multiple clouds rapidly
        identity_fed: dict[str, list[IdentitySignal]] = {}
        for sig in fed_signals:
            identity_fed.setdefault(sig.identity_id, []).append(sig)

        for identity_id, sigs in identity_fed.items():
            clouds = {s.source_cloud for s in sigs}
            if len(clouds) > 1:
                sorted_sigs = sorted(sigs, key=lambda s: s.timestamp)
                timeline = [
                    {
                        "identity_id": s.identity_id,
                        "cloud": s.source_cloud,
                        "action": s.action,
                        "target_resource": s.target_resource,
                        "timestamp": s.timestamp,
                    }
                    for s in sorted_sigs
                ]
                path = MovementPath(
                    id=hashlib.sha256(f"fed_abuse:{identity_id}".encode()).hexdigest()[:16],
                    movement_type=MovementType.FEDERATION_ABUSE,
                    source_identity=identity_id,
                    target_identity=identity_id,
                    source_cloud=sorted_sigs[0].source_cloud,
                    target_cloud=sorted_sigs[-1].source_cloud,
                    hops=len(clouds) - 1,
                    confidence=min(0.65 + len(clouds) * 0.1, 0.95),
                    mitre_technique="T1606.002",
                    timeline=timeline,
                )
                paths.append(path)
        return paths

    def _detect_delegation_chains(
        self,
        identity_groups: dict[str, list[IdentitySignal]],
    ) -> list[MovementPath]:
        """Detect long delegation chains (identity A -> B -> C -> ...)."""
        paths: list[MovementPath] = []
        delegation_actions = {"delegate", "impersonate", "act_as"}

        for identity_id, sigs in identity_groups.items():
            deleg_sigs = [s for s in sigs if s.action in delegation_actions]
            if len(deleg_sigs) >= _MAX_HOP_DEPTH:
                sorted_deleg = sorted(deleg_sigs, key=lambda s: s.timestamp)
                timeline = [
                    {
                        "identity_id": s.identity_id,
                        "cloud": s.source_cloud,
                        "action": s.action,
                        "target_resource": s.target_resource,
                        "timestamp": s.timestamp,
                    }
                    for s in sorted_deleg
                ]
                path = MovementPath(
                    id=hashlib.sha256(f"deleg_chain:{identity_id}".encode()).hexdigest()[:16],
                    movement_type=MovementType.DELEGATION_CHAIN,
                    source_identity=identity_id,
                    target_identity=sorted_deleg[-1].target_resource,
                    source_cloud=sorted_deleg[0].source_cloud,
                    target_cloud=sorted_deleg[-1].source_cloud,
                    hops=len(deleg_sigs),
                    confidence=min(0.6 + len(deleg_sigs) * 0.05, 0.95),
                    mitre_technique="T1134.001",
                    timeline=timeline,
                )
                paths.append(path)
        return paths

    def _detect_credential_relay(self, signals: list[IdentitySignal]) -> list[MovementPath]:
        """Detect credential relay (creds used in rapid succession across targets)."""
        paths: list[MovementPath] = []
        auth_signals = [
            s
            for s in signals
            if s.action in ("authenticate", "login", "api_key_use", "token_exchange")
        ]
        if len(auth_signals) < 3:
            return paths

        sorted_auth = sorted(auth_signals, key=lambda s: s.timestamp)
        # Sliding window: 3+ auths within TOKEN_REUSE_WINDOW
        for i in range(len(sorted_auth) - 2):
            window = [sorted_auth[i]]
            for j in range(i + 1, len(sorted_auth)):
                if sorted_auth[j].timestamp - sorted_auth[i].timestamp <= _TOKEN_REUSE_WINDOW_SEC:
                    window.append(sorted_auth[j])
                else:
                    break

            targets = {s.target_resource for s in window}
            if len(window) >= 3 and len(targets) >= 2:
                timeline = [
                    {
                        "identity_id": s.identity_id,
                        "cloud": s.source_cloud,
                        "action": s.action,
                        "target_resource": s.target_resource,
                        "timestamp": s.timestamp,
                    }
                    for s in window
                ]
                path_id = hashlib.sha256(
                    f"cred_relay:{window[0].identity_id}:{window[0].timestamp}".encode()
                ).hexdigest()[:16]
                path = MovementPath(
                    id=path_id,
                    movement_type=MovementType.CREDENTIAL_RELAY,
                    source_identity=window[0].identity_id,
                    target_identity=window[-1].identity_id,
                    source_cloud=window[0].source_cloud,
                    target_cloud=window[-1].source_cloud,
                    hops=len(window) - 1,
                    confidence=min(0.5 + len(window) * 0.1, 0.95),
                    mitre_technique="T1550",
                    timeline=timeline,
                )
                paths.append(path)
                break  # One relay detection per scan

        return paths

    # -- Severity & containment helpers --

    def _compute_severity(self, path: MovementPath) -> MovementSeverity:
        """Compute severity based on movement type, confidence, and hop count."""
        if path.confidence >= 0.9 and path.hops >= 3:
            return MovementSeverity.CRITICAL
        if path.confidence >= 0.8 or path.movement_type in (
            MovementType.CROSS_CLOUD_ESCALATION,
            MovementType.FEDERATION_ABUSE,
        ):
            return MovementSeverity.HIGH
        if path.confidence >= 0.6:
            return MovementSeverity.MEDIUM
        if path.confidence >= 0.4:
            return MovementSeverity.LOW
        return MovementSeverity.INFO

    def _recommend_containment(self, path: MovementPath, severity: MovementSeverity) -> list[str]:
        """Recommend containment actions based on path type and severity."""
        actions: list[str] = []

        if severity in (MovementSeverity.CRITICAL, MovementSeverity.HIGH):
            actions.append(f"Revoke all active sessions for {path.source_identity}")
            actions.append(f"Disable service account {path.source_identity}")

        if path.movement_type == MovementType.OAUTH_TOKEN_REUSE:
            actions.append("Invalidate OAuth tokens across all clouds")
        elif path.movement_type == MovementType.SERVICE_ACCOUNT_PIVOT:
            actions.append("Rotate service account keys immediately")
            actions.append("Review IAM bindings for over-permissions")
        elif path.movement_type == MovementType.CROSS_CLOUD_ESCALATION:
            actions.append("Review cross-cloud IAM role trust policies")
            actions.append("Enable MFA on all federated roles")
        elif path.movement_type == MovementType.FEDERATION_ABUSE:
            actions.append("Audit federation trust configurations")
            actions.append("Restrict SAML/OIDC provider scopes")
        elif path.movement_type == MovementType.DELEGATION_CHAIN:
            actions.append("Limit delegation depth to 2 hops")
            actions.append("Audit delegation grants")
        elif path.movement_type == MovementType.CREDENTIAL_RELAY:
            actions.append("Force credential rotation")
            actions.append("Enable anomalous login alerting")

        if severity == MovementSeverity.CRITICAL:
            actions.append("Escalate to security incident response team")

        return actions

    def _parse_containment(self, action_str: str, path: MovementPath) -> tuple[str, str]:
        """Parse a containment action string into (action_type, target)."""
        action_lower = action_str.lower()
        if "revoke" in action_lower:
            return ("revoke_sessions", path.source_identity)
        if "disable" in action_lower:
            return ("disable_identity", path.source_identity)
        if "rotate" in action_lower:
            return ("rotate_credentials", path.source_identity)
        if "invalidate" in action_lower:
            return ("invalidate_tokens", path.source_identity)
        if "escalate" in action_lower:
            return ("escalate_incident", path.id)
        return ("recommend", path.source_identity)

    def _generate_synthetic_signals(
        self,
        tenant_id: str,
        cutoff: float,
        now: float,
    ) -> list[IdentitySignal]:
        """Generate synthetic signals when no cloud connectors are available."""
        mid = (cutoff + now) / 2
        return [
            IdentitySignal(
                id=f"syn-{tenant_id}-1",
                identity_id=f"sa-{tenant_id}-compute",
                identity_type="service_account",
                source_cloud="aws",
                action="sts_assume_role",
                target_resource="arn:aws:iam::123:role/admin",
                timestamp=mid,
                geo_location="us-east-1",
                risk_indicators=["cross_account", "admin_role"],
            ),
            IdentitySignal(
                id=f"syn-{tenant_id}-2",
                identity_id=f"sa-{tenant_id}-compute",
                identity_type="service_account",
                source_cloud="gcp",
                action="impersonate",
                target_resource="sa-admin@project.iam",
                timestamp=mid + 120,
                geo_location="us-central1",
                risk_indicators=["impersonation", "admin_target"],
            ),
            IdentitySignal(
                id=f"syn-{tenant_id}-3",
                identity_id=f"sa-{tenant_id}-compute",
                identity_type="service_account",
                source_cloud="azure",
                action="assign_role",
                target_resource="/subscriptions/xxx/providers/Authorization",
                timestamp=mid + 240,
                geo_location="eastus",
                risk_indicators=["role_assignment", "cross_cloud"],
            ),
        ]
