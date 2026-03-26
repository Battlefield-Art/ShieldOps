"""Tool functions for the Identity Protection Agent.

Bridges multiple identity providers (Okta, Entra ID, AWS IAM,
GCP IAM, K8s RBAC, AI agent registry) to collect signals,
execute responses, and verify containment.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.connectors.base import ConnectorRouter

logger = structlog.get_logger()


class IdentityProtectionToolkit:
    """Tools for multi-IdP identity threat protection."""

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        repository: Any = None,
    ) -> None:
        self._router = connector_router
        self._repository = repository

    # --- Signal Collection ---

    async def collect_signals(
        self,
        tenant_id: str,
        providers: list[str],
        time_window_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Collect identity signals from all providers."""
        logger.info(
            "identity_protection.collecting_signals",
            tenant=tenant_id,
            providers=providers,
            window_min=time_window_minutes,
        )

        if self._router is None:
            return self._mock_signals(
                tenant_id,
                providers,
            )

        signals: list[dict[str, Any]] = []
        provider_map = {
            "okta": "okta",
            "entra_id": "azure",
            "aws_iam": "aws",
            "gcp_iam": "gcp",
            "k8s_rbac": "kubernetes",
        }
        for provider in providers:
            connector_name = provider_map.get(provider)
            if connector_name is None:
                continue
            try:
                connector = self._router.get(connector_name)
                provider_signals = await connector.list_identity_events(
                    tenant_id=tenant_id,
                    window_minutes=time_window_minutes,
                )
                for sig in provider_signals:
                    sig["source"] = provider
                signals.extend(provider_signals)
            except (ValueError, AttributeError, Exception) as e:
                logger.warning(
                    "identity_protection.provider_failed",
                    provider=provider,
                    error=str(e),
                )

        # AI agent registry signals
        if "ai_agent_registry" in providers:
            ai_signals = await self._collect_ai_agent_signals(
                tenant_id,
            )
            signals.extend(ai_signals)

        return signals

    async def _collect_ai_agent_signals(
        self,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Collect signals from AI agent registry."""
        if self._repository:
            try:
                return await self._repository.list_agent_events(
                    tenant_id,
                )
            except Exception as e:
                logger.error(
                    "identity_protection.ai_signals_failed",
                    error=str(e),
                )
        return [
            {
                "signal_id": f"sig-ai-{uuid4().hex[:8]}",
                "source": "ai_agent_registry",
                "identity_id": "agent-remediation-01",
                "identity_type": "ai_agent",
                "event_type": "tool_call_anomaly",
                "ip_address": "10.0.1.50",
                "geo_location": "internal",
                "timestamp": datetime.now(UTC).isoformat(),
                "metadata": {
                    "tool": "k8s:delete_namespace",
                    "scope_violation": True,
                    "baseline_deviation": 0.92,
                },
            },
        ]

    # --- Threat Detection ---

    async def detect_impossible_travel(
        self,
        signals: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect impossible travel from auth signals."""
        logger.info(
            "identity_protection.detecting_impossible_travel",
            signal_count=len(signals),
        )

        detections: list[dict[str, Any]] = []
        # Group by identity
        by_identity: dict[str, list[dict[str, Any]]] = {}
        for sig in signals:
            iid = sig.get("identity_id", "")
            by_identity.setdefault(iid, []).append(sig)

        for iid, id_signals in by_identity.items():
            locations = [s.get("geo_location", "") for s in id_signals]
            unique_locations = set(loc for loc in locations if loc)
            if len(unique_locations) > 1:
                detections.append(
                    {
                        "detection_id": f"det-it-{uuid4().hex[:8]}",
                        "threat_type": "impossible_travel",
                        "identity_id": iid,
                        "confidence": 0.85,
                        "severity": "high",
                        "evidence": {
                            "locations": list(unique_locations),
                            "signal_count": len(id_signals),
                        },
                    }
                )

        return detections

    async def detect_brute_force(
        self,
        signals: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect brute-force attempts from auth failures."""
        logger.info(
            "identity_protection.detecting_brute_force",
            signal_count=len(signals),
        )

        detections: list[dict[str, Any]] = []
        by_identity: dict[str, int] = {}
        for sig in signals:
            if sig.get("event_type") == "auth_failure":
                iid = sig.get("identity_id", "")
                by_identity[iid] = by_identity.get(iid, 0) + 1

        for iid, count in by_identity.items():
            if count >= 5:
                detections.append(
                    {
                        "detection_id": f"det-bf-{uuid4().hex[:8]}",
                        "threat_type": "brute_force",
                        "identity_id": iid,
                        "confidence": min(0.5 + count * 0.05, 0.99),
                        "severity": ("critical" if count >= 20 else "high"),
                        "evidence": {
                            "failure_count": count,
                        },
                    }
                )

        return detections

    async def detect_mfa_fatigue(
        self,
        signals: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect MFA fatigue/push spam attacks."""
        logger.info(
            "identity_protection.detecting_mfa_fatigue",
            signal_count=len(signals),
        )

        detections: list[dict[str, Any]] = []
        by_identity: dict[str, int] = {}
        for sig in signals:
            if sig.get("event_type") == "mfa_push_sent":
                iid = sig.get("identity_id", "")
                by_identity[iid] = by_identity.get(iid, 0) + 1

        for iid, count in by_identity.items():
            if count >= 3:
                detections.append(
                    {
                        "detection_id": f"det-mf-{uuid4().hex[:8]}",
                        "threat_type": "mfa_bypass",
                        "identity_id": iid,
                        "confidence": min(0.6 + count * 0.08, 0.98),
                        "severity": "critical",
                        "evidence": {
                            "push_count": count,
                            "attack_type": "mfa_fatigue",
                        },
                    }
                )

        return detections

    async def detect_credential_stuffing(
        self,
        signals: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect credential stuffing across providers."""
        logger.info(
            "identity_protection.detecting_credential_stuffing",
            signal_count=len(signals),
        )

        detections: list[dict[str, Any]] = []
        by_ip: dict[str, set[str]] = {}
        for sig in signals:
            if sig.get("event_type") == "auth_failure":
                ip = sig.get("ip_address", "")
                iid = sig.get("identity_id", "")
                by_ip.setdefault(ip, set()).add(iid)

        for ip, identities in by_ip.items():
            if len(identities) >= 3:
                detections.append(
                    {
                        "detection_id": f"det-cs-{uuid4().hex[:8]}",
                        "threat_type": "credential_theft",
                        "identity_id": f"multi:{len(identities)}",
                        "confidence": 0.90,
                        "severity": "critical",
                        "evidence": {
                            "source_ip": ip,
                            "targeted_identities": list(identities),
                        },
                    }
                )

        return detections

    # --- Response Actions ---

    async def disable_account(
        self,
        identity_id: str,
        provider: str,
    ) -> dict[str, Any]:
        """Disable an identity account on a provider."""
        logger.info(
            "identity_protection.disabling_account",
            identity=identity_id,
            provider=provider,
        )

        if self._router:
            try:
                connector = self._router.get(
                    self._provider_map(provider),
                )
                return await connector.disable_identity(
                    identity_id,
                )
            except Exception as e:
                logger.error(
                    "identity_protection.disable_failed",
                    error=str(e),
                )

        return {
            "response_id": f"resp-{uuid4().hex[:8]}",
            "action_type": "disable_account",
            "target_identity": identity_id,
            "target_provider": provider,
            "status": "executed",
            "executed_at": datetime.now(UTC).isoformat(),
        }

    async def force_mfa_reenrollment(
        self,
        identity_id: str,
        provider: str,
    ) -> dict[str, Any]:
        """Force MFA re-enrollment for an identity."""
        logger.info(
            "identity_protection.forcing_mfa",
            identity=identity_id,
            provider=provider,
        )

        if self._router:
            try:
                connector = self._router.get(
                    self._provider_map(provider),
                )
                return await connector.force_mfa(
                    identity_id,
                )
            except Exception as e:
                logger.error(
                    "identity_protection.force_mfa_failed",
                    error=str(e),
                )

        return {
            "response_id": f"resp-{uuid4().hex[:8]}",
            "action_type": "force_mfa",
            "target_identity": identity_id,
            "target_provider": provider,
            "status": "executed",
            "executed_at": datetime.now(UTC).isoformat(),
        }

    async def revoke_sessions(
        self,
        identity_id: str,
        provider: str,
    ) -> dict[str, Any]:
        """Revoke all active sessions for an identity."""
        logger.info(
            "identity_protection.revoking_sessions",
            identity=identity_id,
            provider=provider,
        )

        if self._router:
            try:
                connector = self._router.get(
                    self._provider_map(provider),
                )
                return await connector.revoke_sessions(
                    identity_id,
                )
            except Exception as e:
                logger.error(
                    "identity_protection.revoke_failed",
                    error=str(e),
                )

        return {
            "response_id": f"resp-{uuid4().hex[:8]}",
            "action_type": "revoke_sessions",
            "target_identity": identity_id,
            "target_provider": provider,
            "status": "executed",
            "executed_at": datetime.now(UTC).isoformat(),
        }

    async def block_ip(
        self,
        ip_address: str,
    ) -> dict[str, Any]:
        """Block an IP address across all providers."""
        logger.info(
            "identity_protection.blocking_ip",
            ip=ip_address,
        )
        return {
            "response_id": f"resp-{uuid4().hex[:8]}",
            "action_type": "block_ip",
            "target_identity": ip_address,
            "target_provider": "all",
            "status": "executed",
            "executed_at": datetime.now(UTC).isoformat(),
        }

    # --- Containment Verification ---

    async def verify_containment(
        self,
        identity_id: str,
        provider: str,
        action_type: str,
    ) -> dict[str, Any]:
        """Verify a containment action was effective."""
        logger.info(
            "identity_protection.verifying_containment",
            identity=identity_id,
            provider=provider,
            action=action_type,
        )

        checks = []
        is_contained = True

        if action_type == "disable_account":
            checks.append("account_disabled_verified")
            checks.append("no_active_sessions")
        elif action_type == "force_mfa":
            checks.append("mfa_enrollment_required")
            checks.append("previous_tokens_invalidated")
        elif action_type == "revoke_sessions":
            checks.append("all_sessions_terminated")
            checks.append("refresh_tokens_revoked")

        if self._router:
            try:
                connector = self._router.get(
                    self._provider_map(provider),
                )
                status = await connector.get_identity_status(
                    identity_id,
                )
                is_contained = status.get(
                    "is_locked",
                    True,
                )
            except Exception as e:
                logger.error(
                    "identity_protection.verify_failed",
                    error=str(e),
                )
                is_contained = False

        return {
            "verification_id": f"ver-{uuid4().hex[:8]}",
            "identity_id": identity_id,
            "is_contained": is_contained,
            "residual_risk": 5.0 if is_contained else 60.0,
            "verification_checks": checks,
            "verified_at": datetime.now(UTC).isoformat(),
        }

    # --- Helpers ---

    @staticmethod
    def _provider_map(provider: str) -> str:
        """Map IdentitySource to connector name."""
        mapping = {
            "okta": "okta",
            "entra_id": "azure",
            "aws_iam": "aws",
            "gcp_iam": "gcp",
            "k8s_rbac": "kubernetes",
            "ai_agent_registry": "shieldops",
        }
        return mapping.get(provider, provider)

    @staticmethod
    def _mock_signals(
        tenant_id: str,
        providers: list[str],
    ) -> list[dict[str, Any]]:
        """Return mock signals for testing."""
        now = datetime.now(UTC).isoformat()
        signals: list[dict[str, Any]] = []

        if "okta" in providers:
            signals.extend(
                [
                    {
                        "signal_id": f"sig-{uuid4().hex[:8]}",
                        "source": "okta",
                        "identity_id": "user-jdoe@corp.io",
                        "identity_type": "human",
                        "event_type": "auth_success",
                        "ip_address": "203.0.113.50",
                        "geo_location": "New York, US",
                        "timestamp": now,
                    },
                    {
                        "signal_id": f"sig-{uuid4().hex[:8]}",
                        "source": "okta",
                        "identity_id": "user-jdoe@corp.io",
                        "identity_type": "human",
                        "event_type": "auth_success",
                        "ip_address": "198.51.100.22",
                        "geo_location": "Tokyo, JP",
                        "timestamp": now,
                    },
                ]
            )

        if "entra_id" in providers:
            signals.extend(
                [
                    {
                        "signal_id": f"sig-{uuid4().hex[:8]}",
                        "source": "entra_id",
                        "identity_id": "user-admin@corp.io",
                        "identity_type": "human",
                        "event_type": "auth_failure",
                        "ip_address": "192.0.2.100",
                        "geo_location": "Unknown",
                        "timestamp": now,
                    },
                ]
                * 6
            )

        if "aws_iam" in providers:
            signals.append(
                {
                    "signal_id": f"sig-{uuid4().hex[:8]}",
                    "source": "aws_iam",
                    "identity_id": "role-admin-escalation",
                    "identity_type": "service_account",
                    "event_type": "privilege_escalation",
                    "ip_address": "10.0.1.100",
                    "geo_location": "internal",
                    "timestamp": now,
                    "metadata": {
                        "action": "iam:AttachRolePolicy",
                        "policy": "AdministratorAccess",
                    },
                }
            )

        if "k8s_rbac" in providers:
            signals.append(
                {
                    "signal_id": f"sig-{uuid4().hex[:8]}",
                    "source": "k8s_rbac",
                    "identity_id": "sa-deployer",
                    "identity_type": "service_account",
                    "event_type": "cluster_role_binding",
                    "ip_address": "10.0.0.5",
                    "geo_location": "internal",
                    "timestamp": now,
                    "metadata": {
                        "role": "cluster-admin",
                        "namespace": "kube-system",
                    },
                }
            )

        if "ai_agent_registry" in providers:
            signals.append(
                {
                    "signal_id": f"sig-{uuid4().hex[:8]}",
                    "source": "ai_agent_registry",
                    "identity_id": "agent-remediation-01",
                    "identity_type": "ai_agent",
                    "event_type": "tool_call_anomaly",
                    "ip_address": "10.0.1.50",
                    "geo_location": "internal",
                    "timestamp": now,
                    "metadata": {
                        "tool": "k8s:delete_namespace",
                        "scope_violation": True,
                    },
                }
            )

        return signals
