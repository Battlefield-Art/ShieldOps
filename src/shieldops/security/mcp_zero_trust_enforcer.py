"""MCP Zero Trust Enforcer — trust evaluation and policy enforcement for MCP servers."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TrustLevel(StrEnum):
    UNTRUSTED = "untrusted"
    PARTIALLY_TRUSTED = "partially_trusted"
    TRUSTED = "trusted"
    VERIFIED = "verified"
    PRIVILEGED = "privileged"


class EnforcementAction(StrEnum):
    REQUIRE_AUTH = "require_auth"
    ENCRYPT_TRANSPORT = "encrypt_transport"
    VALIDATE_CERTIFICATE = "validate_certificate"
    CHECK_INTEGRITY = "check_integrity"
    DENY_ACCESS = "deny_access"


class ComplianceStatus(StrEnum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    EXEMPT = "exempt"
    UNKNOWN = "unknown"


# --- Models ---


class MCPTrustRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    server_id: str = ""
    endpoint: str = ""
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    auth_configured: bool = False
    transport_encrypted: bool = False
    cert_valid: bool = False
    last_verified: float = Field(default_factory=time.time)
    compliance_status: ComplianceStatus = ComplianceStatus.UNKNOWN
    violations: list[str] = Field(default_factory=list)


class ZeroTrustPolicy(BaseModel):
    require_oauth2: bool = True
    require_tls: bool = True
    require_cert_pinning: bool = False
    require_audit_log: bool = True
    max_token_ttl_hours: int = 24
    require_scoped_permissions: bool = True


class ZeroTrustReport(BaseModel):
    total_servers: int = 0
    compliant_count: int = 0
    non_compliant_count: int = 0
    by_trust_level: dict[str, int] = Field(default_factory=dict)
    by_compliance: dict[str, int] = Field(default_factory=dict)
    unencrypted_count: int = 0
    unauthenticated_count: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class MCPZeroTrustEnforcer:
    """Zero-trust evaluation and enforcement for MCP server connections."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._servers: list[MCPTrustRecord] = []
        self._default_policy = ZeroTrustPolicy()
        logger.info("mcp_zero_trust_enforcer.initialized", max_records=max_records)

    # -- server registration -------------------------------------------------

    def register_server(
        self,
        server_id: str,
        endpoint: str = "",
        auth_configured: bool = False,
        transport_encrypted: bool = False,
        cert_info: dict[str, Any] | None = None,
    ) -> MCPTrustRecord:
        cert_valid = bool(cert_info and cert_info.get("valid", False)) if cert_info else False
        record = MCPTrustRecord(
            server_id=server_id,
            endpoint=endpoint,
            auth_configured=auth_configured,
            transport_encrypted=transport_encrypted,
            cert_valid=cert_valid,
        )
        self._servers.append(record)
        if len(self._servers) > self._max_records:
            self._servers = self._servers[-self._max_records :]
        logger.info(
            "mcp_zero_trust_enforcer.server_registered",
            server_id=server_id,
            endpoint=endpoint,
            auth=auth_configured,
            encrypted=transport_encrypted,
        )
        return record

    def get_server(self, server_id: str) -> MCPTrustRecord | None:
        for s in self._servers:
            if s.server_id == server_id:
                return s
        return None

    def list_servers(
        self, trust_level: TrustLevel | None = None, limit: int = 50
    ) -> list[MCPTrustRecord]:
        results = list(self._servers)
        if trust_level is not None:
            results = [s for s in results if s.trust_level == trust_level]
        return results[-limit:]

    # -- trust evaluation ----------------------------------------------------

    def evaluate_trust(self, server_id: str) -> dict[str, Any]:
        """Evaluate trust level and compliance status for a server."""
        server = self.get_server(server_id)
        if server is None:
            return {"server_id": server_id, "status": "not_found"}

        violations: list[str] = []
        score = 0

        if server.auth_configured:
            score += 30
        else:
            violations.append("no_authentication_configured")

        if server.transport_encrypted:
            score += 30
        else:
            violations.append("transport_not_encrypted")

        if server.cert_valid:
            score += 20
        else:
            violations.append("certificate_invalid_or_missing")

        # Check age of last verification
        hours_since = (time.time() - server.last_verified) / 3600
        if hours_since < 24:
            score += 20
        elif hours_since < 168:
            score += 10
            violations.append("verification_stale_over_24h")
        else:
            violations.append("verification_stale_over_7d")

        # Determine trust level
        if score >= 90:
            trust_level = TrustLevel.VERIFIED
        elif score >= 70:
            trust_level = TrustLevel.TRUSTED
        elif score >= 40:
            trust_level = TrustLevel.PARTIALLY_TRUSTED
        else:
            trust_level = TrustLevel.UNTRUSTED

        # Determine compliance
        if not violations:
            compliance = ComplianceStatus.COMPLIANT
        elif len(violations) <= 1:
            compliance = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            compliance = ComplianceStatus.NON_COMPLIANT

        server.trust_level = trust_level
        server.compliance_status = compliance
        server.violations = violations
        server.last_verified = time.time()

        logger.info(
            "mcp_zero_trust_enforcer.trust_evaluated",
            server_id=server_id,
            trust_level=trust_level.value,
            compliance=compliance.value,
            score=score,
        )

        return {
            "server_id": server_id,
            "trust_level": trust_level.value,
            "compliance_status": compliance.value,
            "score": score,
            "violations": violations,
        }

    # -- policy enforcement --------------------------------------------------

    def enforce_policy(
        self, server_id: str, policy: ZeroTrustPolicy | None = None
    ) -> dict[str, Any]:
        """Enforce a zero-trust policy against a server and return violations."""
        server = self.get_server(server_id)
        if server is None:
            return {"server_id": server_id, "status": "not_found"}

        pol = policy or self._default_policy
        violations: list[str] = []
        actions: list[str] = []

        if pol.require_oauth2 and not server.auth_configured:
            violations.append("oauth2_not_configured")
            actions.append(EnforcementAction.REQUIRE_AUTH.value)

        if pol.require_tls and not server.transport_encrypted:
            violations.append("tls_not_enabled")
            actions.append(EnforcementAction.ENCRYPT_TRANSPORT.value)

        if pol.require_cert_pinning and not server.cert_valid:
            violations.append("cert_pinning_not_valid")
            actions.append(EnforcementAction.VALIDATE_CERTIFICATE.value)

        compliant = len(violations) == 0
        return {
            "server_id": server_id,
            "compliant": compliant,
            "violations": violations,
            "enforcement_actions": actions,
        }

    # -- domain operations ---------------------------------------------------

    def detect_unencrypted_connections(self) -> list[dict[str, Any]]:
        """Find servers communicating over plaintext transport."""
        unencrypted: list[dict[str, Any]] = []
        for s in self._servers:
            if not s.transport_encrypted:
                unencrypted.append(
                    {
                        "server_id": s.server_id,
                        "endpoint": s.endpoint,
                        "trust_level": s.trust_level.value,
                        "action_required": EnforcementAction.ENCRYPT_TRANSPORT.value,
                    }
                )
        return unencrypted

    def detect_unauthenticated_servers(self) -> list[dict[str, Any]]:
        """Find servers without authentication."""
        unauthenticated: list[dict[str, Any]] = []
        for s in self._servers:
            if not s.auth_configured:
                unauthenticated.append(
                    {
                        "server_id": s.server_id,
                        "endpoint": s.endpoint,
                        "trust_level": s.trust_level.value,
                        "action_required": EnforcementAction.REQUIRE_AUTH.value,
                    }
                )
        return unauthenticated

    def promote_trust_level(self, server_id: str, level: TrustLevel) -> dict[str, Any]:
        """Manually promote a server trust level (with audit trail)."""
        server = self.get_server(server_id)
        if server is None:
            return {"status": "not_found"}
        old_level = server.trust_level
        server.trust_level = level
        logger.info(
            "mcp_zero_trust_enforcer.trust_promoted",
            server_id=server_id,
            old_level=old_level.value,
            new_level=level.value,
        )
        return {
            "server_id": server_id,
            "old_trust_level": old_level.value,
            "new_trust_level": level.value,
        }

    # -- report / stats ------------------------------------------------------

    def generate_zero_trust_report(self) -> ZeroTrustReport:
        by_trust: dict[str, int] = {}
        by_compliance: dict[str, int] = {}
        for s in self._servers:
            by_trust[s.trust_level.value] = by_trust.get(s.trust_level.value, 0) + 1
            by_compliance[s.compliance_status.value] = (
                by_compliance.get(s.compliance_status.value, 0) + 1
            )

        unencrypted = len(self.detect_unencrypted_connections())
        unauthenticated = len(self.detect_unauthenticated_servers())
        compliant = by_compliance.get(ComplianceStatus.COMPLIANT.value, 0)
        non_compliant = by_compliance.get(ComplianceStatus.NON_COMPLIANT.value, 0)

        recs: list[str] = []
        if unencrypted > 0:
            recs.append(f"{unencrypted} server(s) using plaintext transport — enable TLS")
        if unauthenticated > 0:
            recs.append(
                f"{unauthenticated} server(s) without authentication — configure OAuth2/mTLS"
            )
        untrusted = by_trust.get(TrustLevel.UNTRUSTED.value, 0)
        if untrusted > 0:
            recs.append(f"{untrusted} server(s) at UNTRUSTED level — remediate or remove")
        if not recs:
            recs.append("All MCP servers meet zero-trust requirements")

        return ZeroTrustReport(
            total_servers=len(self._servers),
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            by_trust_level=by_trust,
            by_compliance=by_compliance,
            unencrypted_count=unencrypted,
            unauthenticated_count=unauthenticated,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        trust_dist: dict[str, int] = {}
        for s in self._servers:
            key = s.trust_level.value
            trust_dist[key] = trust_dist.get(key, 0) + 1
        return {
            "total_servers": len(self._servers),
            "trust_distribution": trust_dist,
            "unencrypted": sum(1 for s in self._servers if not s.transport_encrypted),
            "unauthenticated": sum(1 for s in self._servers if not s.auth_configured),
        }

    def clear_data(self) -> dict[str, str]:
        self._servers.clear()
        logger.info("mcp_zero_trust_enforcer.cleared")
        return {"status": "cleared"}
