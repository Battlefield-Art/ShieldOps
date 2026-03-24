"""Credential Policy Engine — centralized policy management for credential lifecycle."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PolicyScope(StrEnum):
    GLOBAL = "global"
    ENVIRONMENT = "environment"
    AGENT_SPECIFIC = "agent_specific"
    PROVIDER_SPECIFIC = "provider_specific"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    RATE_LIMIT = "rate_limit"


class ComplianceStatus(StrEnum):
    COMPLIANT = "compliant"
    VIOLATION = "violation"
    WARNING = "warning"
    NOT_EVALUATED = "not_evaluated"


# --- Models ---


class CredentialPolicy(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    scope: PolicyScope = PolicyScope.GLOBAL
    target: str = ""
    max_ttl_seconds: int = 7200
    max_scope_level: str = "read_write"
    allowed_providers: list[str] = Field(default_factory=list)
    max_concurrent_credentials: int = 10
    require_justification: bool = False
    action_on_violation: PolicyAction = PolicyAction.DENY
    created_at: float = Field(default_factory=time.time)


class PolicyEvaluation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: str = ""
    agent_id: str = ""
    request_scope: str = ""
    request_ttl: int = 0
    status: ComplianceStatus = ComplianceStatus.NOT_EVALUATED
    violations: list[str] = Field(default_factory=list)
    evaluated_at: float = Field(default_factory=time.time)


class CredentialPolicyReport(BaseModel):
    total_policies: int = 0
    total_evaluations: int = 0
    compliant_count: int = 0
    violation_count: int = 0
    by_scope: dict[str, int] = Field(default_factory=dict)
    policy_conflicts: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


_SCOPE_LEVELS = ["read_only", "read_write", "admin", "custom"]


# --- Engine ---


class CredentialPolicyEngine:
    """Centralized policy management for credential lifecycle."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._policies: list[CredentialPolicy] = []
        self._evaluations: list[PolicyEvaluation] = []
        logger.info("credential_policy_engine.initialized", max_records=max_records)

    def add_policy(
        self,
        name: str,
        scope: PolicyScope = PolicyScope.GLOBAL,
        target: str = "*",
        max_ttl_seconds: int = 7200,
        max_scope_level: str = "read_write",
        allowed_providers: list[str] | None = None,
        max_concurrent_credentials: int = 10,
        action_on_violation: PolicyAction = PolicyAction.DENY,
    ) -> CredentialPolicy:
        policy = CredentialPolicy(
            name=name,
            scope=scope,
            target=target,
            max_ttl_seconds=max_ttl_seconds,
            max_scope_level=max_scope_level,
            allowed_providers=allowed_providers or [],
            max_concurrent_credentials=max_concurrent_credentials,
            action_on_violation=action_on_violation,
        )
        self._policies.append(policy)
        return policy

    def get_applicable_policies(
        self, agent_id: str = "", provider: str = ""
    ) -> list[CredentialPolicy]:
        results: list[CredentialPolicy] = []
        for p in self._policies:
            if (
                p.scope == PolicyScope.GLOBAL
                or p.scope == PolicyScope.AGENT_SPECIFIC
                and p.target == agent_id
                or p.scope == PolicyScope.PROVIDER_SPECIFIC
                and p.target == provider
            ):
                results.append(p)
        return results

    def evaluate(
        self,
        agent_id: str,
        request_scope: str = "read_only",
        request_ttl: int = 3600,
        provider: str = "",
    ) -> PolicyEvaluation:
        policies = self.get_applicable_policies(agent_id=agent_id, provider=provider)
        violations: list[str] = []
        for p in policies:
            if request_ttl > p.max_ttl_seconds:
                violations.append(
                    f"ttl {request_ttl}s exceeds policy '{p.name}' max {p.max_ttl_seconds}s"
                )
            req_idx = _SCOPE_LEVELS.index(request_scope) if request_scope in _SCOPE_LEVELS else 0
            max_idx = (
                _SCOPE_LEVELS.index(p.max_scope_level) if p.max_scope_level in _SCOPE_LEVELS else 0
            )
            if req_idx > max_idx:
                violations.append(
                    f"scope '{request_scope}' exceeds policy '{p.name}' max '{p.max_scope_level}'"
                )
            if p.allowed_providers and provider and provider not in p.allowed_providers:
                violations.append(f"provider '{provider}' not allowed by policy '{p.name}'")
        status = ComplianceStatus.VIOLATION if violations else ComplianceStatus.COMPLIANT
        evaluation = PolicyEvaluation(
            policy_id=policies[0].id if policies else "",
            agent_id=agent_id,
            request_scope=request_scope,
            request_ttl=request_ttl,
            status=status,
            violations=violations,
        )
        self._evaluations.append(evaluation)
        if len(self._evaluations) > self._max_records:
            self._evaluations = self._evaluations[-self._max_records :]
        return evaluation

    def detect_policy_conflicts(self) -> list[dict[str, Any]]:
        conflicts: list[dict[str, Any]] = []
        seen: dict[str, list[CredentialPolicy]] = {}
        for p in self._policies:
            key = f"{p.scope.value}:{p.target}"
            seen.setdefault(key, []).append(p)
        for key, group in seen.items():
            if len(group) < 2:
                continue
            ttls = {p.max_ttl_seconds for p in group}
            scopes = {p.max_scope_level for p in group}
            if len(ttls) > 1 or len(scopes) > 1:
                conflicts.append(
                    {
                        "key": key,
                        "policies": [p.name for p in group],
                        "conflicting_ttls": sorted(ttls),
                        "conflicting_scopes": sorted(scopes),
                    }
                )
        return conflicts

    def generate_report(self) -> CredentialPolicyReport:
        by_scope: dict[str, int] = {}
        for p in self._policies:
            by_scope[p.scope.value] = by_scope.get(p.scope.value, 0) + 1
        compliant = sum(1 for e in self._evaluations if e.status == ComplianceStatus.COMPLIANT)
        violations = sum(1 for e in self._evaluations if e.status == ComplianceStatus.VIOLATION)
        conflicts = len(self.detect_policy_conflicts())
        recs: list[str] = []
        if violations > 0:
            recs.append(f"{violations} policy violation(s) detected")
        if conflicts > 0:
            recs.append(f"{conflicts} policy conflict(s) need resolution")
        if not recs:
            recs.append("Credential policies are consistent and compliant")
        return CredentialPolicyReport(
            total_policies=len(self._policies),
            total_evaluations=len(self._evaluations),
            compliant_count=compliant,
            violation_count=violations,
            by_scope=by_scope,
            policy_conflicts=conflicts,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_policies": len(self._policies),
            "total_evaluations": len(self._evaluations),
            "compliant": sum(
                1 for e in self._evaluations if e.status == ComplianceStatus.COMPLIANT
            ),
            "violations": sum(
                1 for e in self._evaluations if e.status == ComplianceStatus.VIOLATION
            ),
        }

    def clear_data(self) -> dict[str, str]:
        self._policies.clear()
        self._evaluations.clear()
        return {"status": "cleared"}
