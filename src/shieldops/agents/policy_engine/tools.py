"""Policy Engine Agent — Tool functions for OPA Rego policy management."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    CoverageGap,
    DriftSeverity,
    GeneratedPolicy,
    PolicyDrift,
    PolicyStatus,
    PolicyType,
    ReconciliationAction,
    SecurityRequirement,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# OPA Rego policy templates for common policy types
# ---------------------------------------------------------------------------

POLICY_TEMPLATES: dict[PolicyType, str] = {
    PolicyType.AGENT_BEHAVIOR: """\
package shieldops.agent_firewall

import rego.v1

default allow := false

# Allow agent actions within blast-radius limits
allow if {{
    input.agent_id != ""
    input.action in {allowed_actions}
    input.blast_radius <= {max_blast_radius}
    not _is_destructive
}}

_is_destructive if {{
    input.action in ["delete_database", "drop_table", "modify_iam_root"]
}}

# Require human approval for medium-confidence actions
require_approval if {{
    input.confidence >= 0.5
    input.confidence < 0.85
}}

# Deny actions below confidence threshold
deny[msg] if {{
    input.confidence < 0.5
    msg := sprintf("Action confidence %v below threshold 0.5", [input.confidence])
}}
""",
    PolicyType.ACCESS_CONTROL: """\
package shieldops.access_control

import rego.v1

default allow := false

# Allow access when role matches required permission
allow if {{
    some role in input.user.roles
    some perm in data.role_permissions[role]
    perm == input.required_permission
}}

# Enforce tenant isolation
deny[msg] if {{
    input.user.tenant_id != input.resource.tenant_id
    msg := "Cross-tenant access denied"
}}

# Deny access to admin resources without admin role
deny[msg] if {{
    input.resource.classification == "admin"
    not _has_admin_role
    msg := "Admin role required for admin resources"
}}

_has_admin_role if {{
    some role in input.user.roles
    role == "admin"
}}
""",
    PolicyType.DATA_PROTECTION: """\
package shieldops.data_protection

import rego.v1

default allow := false

# Allow data access when classification is permitted for the role
allow if {{
    input.data_classification in data.allowed_classifications[input.user.role]
    not _contains_pii
}}

# Block access to PII unless explicitly authorized
deny[msg] if {{
    _contains_pii
    not input.user.pii_authorized
    msg := "PII access requires explicit authorization"
}}

_contains_pii if {{
    input.data_classification in ["pii", "phi", "financial"]
}}

# Enforce encryption at rest for sensitive data
deny[msg] if {{
    input.data_classification in ["pii", "phi", "financial", "confidential"]
    not input.storage.encrypted_at_rest
    msg := sprintf(
        "Data classification %v requires encryption at rest",
        [input.data_classification],
    )
}}
""",
    PolicyType.NETWORK: """\
package shieldops.network

import rego.v1

default allow := false

# Allow traffic matching network policy rules
allow if {{
    some rule in data.network_rules
    rule.source == input.source_zone
    rule.destination == input.destination_zone
    input.port in rule.allowed_ports
    input.protocol in rule.allowed_protocols
}}

# Deny all traffic from untrusted zones to restricted zones
deny[msg] if {{
    input.source_zone == "untrusted"
    input.destination_zone == "restricted"
    msg := "Traffic from untrusted to restricted zones is prohibited"
}}

# Rate limit enforcement
deny[msg] if {{
    input.request_count > data.rate_limits[input.source_zone]
    msg := sprintf(
        "Rate limit exceeded: %v requests from zone %v",
        [input.request_count, input.source_zone],
    )
}}
""",
    PolicyType.COMPLIANCE: """\
package shieldops.compliance

import rego.v1

default compliant := false

# Resource is compliant when all required controls are met
compliant if {{
    _has_encryption
    _has_audit_logging
    _has_access_controls
}}

_has_encryption if {{
    input.resource.encryption_enabled == true
    input.resource.encryption_algorithm in ["AES-256", "AES-256-GCM"]
}}

_has_audit_logging if {{
    input.resource.audit_logging == true
    input.resource.log_retention_days >= {min_retention_days}
}}

_has_access_controls if {{
    input.resource.rbac_enabled == true
    count(input.resource.access_policies) > 0
}}

violation[msg] if {{
    not _has_encryption
    msg := "Resource must have AES-256 encryption enabled"
}}

violation[msg] if {{
    not _has_audit_logging
    msg := sprintf(
        "Audit logging required with >= %v day retention",
        [{min_retention_days}],
    )
}}
""",
    PolicyType.RESOURCE_QUOTA: """\
package shieldops.resource_quota

import rego.v1

default allow := false

# Allow resource creation within quota limits
allow if {{
    input.current_usage + input.requested < data.quotas[input.resource_type]
    input.requested > 0
}}

# Deny if exceeding hard quota
deny[msg] if {{
    input.current_usage + input.requested >= data.quotas[input.resource_type]
    msg := sprintf(
        "Quota exceeded for %v: usage=%v, requested=%v, limit=%v",
        [
            input.resource_type,
            input.current_usage,
            input.requested,
            data.quotas[input.resource_type],
        ],
    )
}}

# Warn if approaching soft quota (80% threshold)
warn[msg] if {{
    usage_pct := (input.current_usage + input.requested) / data.quotas[input.resource_type]
    usage_pct >= 0.8
    usage_pct < 1.0
    msg := sprintf(
        "Approaching quota limit for %v: %v%% utilized",
        [input.resource_type, round(usage_pct * 100)],
    )
}}
""",
}

# ---------------------------------------------------------------------------
# Compliance framework requirement templates
# ---------------------------------------------------------------------------

_FRAMEWORK_REQUIREMENTS: dict[str, list[dict[str, Any]]] = {
    "soc2": [
        {
            "title": "Logical Access Controls",
            "description": "Implement role-based access controls for all systems",
            "control_id": "CC6.1",
            "priority": "high",
            "policy_type": PolicyType.ACCESS_CONTROL,
        },
        {
            "title": "Data Encryption",
            "description": "Encrypt sensitive data at rest and in transit",
            "control_id": "CC6.7",
            "priority": "high",
            "policy_type": PolicyType.DATA_PROTECTION,
        },
        {
            "title": "Change Management",
            "description": "Enforce approval workflows for infrastructure changes",
            "control_id": "CC8.1",
            "priority": "medium",
            "policy_type": PolicyType.AGENT_BEHAVIOR,
        },
        {
            "title": "System Monitoring",
            "description": "Continuous monitoring of system operations and security",
            "control_id": "CC7.2",
            "priority": "high",
            "policy_type": PolicyType.COMPLIANCE,
        },
    ],
    "hipaa": [
        {
            "title": "PHI Access Controls",
            "description": "Restrict access to protected health information",
            "control_id": "164.312(a)",
            "priority": "critical",
            "policy_type": PolicyType.DATA_PROTECTION,
        },
        {
            "title": "Audit Controls",
            "description": "Record and examine access to PHI systems",
            "control_id": "164.312(b)",
            "priority": "high",
            "policy_type": PolicyType.COMPLIANCE,
        },
        {
            "title": "Transmission Security",
            "description": "Protect PHI during electronic transmission",
            "control_id": "164.312(e)",
            "priority": "high",
            "policy_type": PolicyType.NETWORK,
        },
    ],
    "pci_dss": [
        {
            "title": "Network Segmentation",
            "description": "Segment cardholder data environment from other networks",
            "control_id": "PCI-1.3",
            "priority": "critical",
            "policy_type": PolicyType.NETWORK,
        },
        {
            "title": "Strong Access Control",
            "description": "Restrict access to cardholder data by business need",
            "control_id": "PCI-7.1",
            "priority": "high",
            "policy_type": PolicyType.ACCESS_CONTROL,
        },
        {
            "title": "Resource Monitoring",
            "description": "Track and monitor all access to network resources",
            "control_id": "PCI-10.1",
            "priority": "high",
            "policy_type": PolicyType.COMPLIANCE,
        },
    ],
    "nist_800_53": [
        {
            "title": "Least Privilege",
            "description": "Employ least privilege for authorized access",
            "control_id": "AC-6",
            "priority": "high",
            "policy_type": PolicyType.ACCESS_CONTROL,
        },
        {
            "title": "Boundary Protection",
            "description": "Monitor and control communications at system boundary",
            "control_id": "SC-7",
            "priority": "high",
            "policy_type": PolicyType.NETWORK,
        },
        {
            "title": "Information Flow Enforcement",
            "description": "Enforce approved authorizations for data flows",
            "control_id": "AC-4",
            "priority": "medium",
            "policy_type": PolicyType.DATA_PROTECTION,
        },
    ],
    "shieldops": [
        {
            "title": "Agent Blast Radius Limits",
            "description": ("Enforce blast-radius limits on all autonomous agent actions"),
            "control_id": "SO-AGENT-001",
            "priority": "critical",
            "policy_type": PolicyType.AGENT_BEHAVIOR,
        },
        {
            "title": "Agent Confidence Thresholds",
            "description": (
                "Require human approval when agent confidence is between "
                "0.5 and 0.85; escalate below 0.5"
            ),
            "control_id": "SO-AGENT-002",
            "priority": "critical",
            "policy_type": PolicyType.AGENT_BEHAVIOR,
        },
        {
            "title": "Tenant Data Isolation",
            "description": "Prevent cross-tenant data access at the policy layer",
            "control_id": "SO-DATA-001",
            "priority": "critical",
            "policy_type": PolicyType.ACCESS_CONTROL,
        },
        {
            "title": "Resource Quota Enforcement",
            "description": (
                "Enforce per-tenant resource quotas for compute, storage, and API calls"
            ),
            "control_id": "SO-RES-001",
            "priority": "high",
            "policy_type": PolicyType.RESOURCE_QUOTA,
        },
    ],
}

# ---------------------------------------------------------------------------
# Drift detection patterns
# ---------------------------------------------------------------------------

_DRIFT_PATTERNS: list[dict[str, Any]] = [
    {
        "drift_type": "rule_modification",
        "description": "Policy rule modified outside change management",
        "severity": DriftSeverity.CRITICAL,
        "auto_reconcilable": True,
    },
    {
        "drift_type": "missing_policy",
        "description": "Defined policy not found in deployed OPA bundle",
        "severity": DriftSeverity.HIGH,
        "auto_reconcilable": True,
    },
    {
        "drift_type": "extra_policy",
        "description": "Unmanaged policy found in OPA bundle",
        "severity": DriftSeverity.MEDIUM,
        "auto_reconcilable": False,
    },
    {
        "drift_type": "data_document_drift",
        "description": "OPA data document differs from expected configuration",
        "severity": DriftSeverity.HIGH,
        "auto_reconcilable": True,
    },
    {
        "drift_type": "version_mismatch",
        "description": "Policy version in deployment differs from source of truth",
        "severity": DriftSeverity.MEDIUM,
        "auto_reconcilable": True,
    },
]


def _generate_id(prefix: str, *parts: str) -> str:
    """Generate a deterministic short ID."""
    raw = ":".join(parts)
    digest = hashlib.sha256(raw.encode()).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


class PolicyEngineToolkit:
    """Tools for OPA Rego policy generation, validation, and drift detection."""

    def __init__(
        self,
        opa_client: Any | None = None,
        policy_store: Any | None = None,
        compliance_registry: Any | None = None,
    ) -> None:
        self._opa_client = opa_client
        self._policy_store = policy_store
        self._compliance_registry = compliance_registry

    # ------------------------------------------------------------------
    # 1. Collect requirements
    # ------------------------------------------------------------------

    async def collect_requirements(self, tenant_id: str) -> list[SecurityRequirement]:
        """Collect security requirements from compliance frameworks and custom rules.

        Uses an external compliance registry when available; otherwise falls
        back to built-in framework templates.
        """
        logger.info("policy_engine.collect_requirements", tenant_id=tenant_id)

        if self._compliance_registry is not None:
            try:
                raw = await self._compliance_registry.get_requirements(
                    tenant_id=tenant_id,
                )
                return [SecurityRequirement(**r) for r in raw]
            except Exception:
                logger.exception("policy_engine.collect_requirements.registry_error")

        requirements: list[SecurityRequirement] = []
        # Gather requirements from all built-in frameworks
        for framework, reqs in _FRAMEWORK_REQUIREMENTS.items():
            for req_data in reqs:
                req_id = _generate_id("REQ", framework, req_data["control_id"])
                requirements.append(
                    SecurityRequirement(
                        id=req_id,
                        title=req_data["title"],
                        description=req_data["description"],
                        framework=framework,
                        control_id=req_data["control_id"],
                        priority=req_data["priority"],
                        automated=True,
                    )
                )

        return requirements

    # ------------------------------------------------------------------
    # 2. Generate OPA Rego policies
    # ------------------------------------------------------------------

    async def generate_rego_policies(
        self, requirements: list[SecurityRequirement]
    ) -> list[GeneratedPolicy]:
        """Generate valid OPA Rego policies from security requirements.

        Groups requirements by policy type and instantiates Rego templates
        with appropriate parameters.
        """
        logger.info(
            "policy_engine.generate_rego_policies",
            requirement_count=len(requirements),
        )

        now = time.time()

        # Group requirements by policy type
        type_groups: dict[PolicyType, list[SecurityRequirement]] = {}
        for req in requirements:
            ptype = self._infer_policy_type(req)
            type_groups.setdefault(ptype, []).append(req)

        policies: list[GeneratedPolicy] = []

        for ptype, reqs in type_groups.items():
            template = POLICY_TEMPLATES.get(ptype, "")
            if not template:
                continue

            # Customize template parameters
            rego_code = self._instantiate_template(ptype, template, reqs)
            policy_id = _generate_id("POL", ptype.value, *[r.id for r in reqs])

            policies.append(
                GeneratedPolicy(
                    id=policy_id,
                    policy_type=ptype,
                    name=f"shieldops_{ptype.value}_policy",
                    description=(
                        f"Auto-generated {ptype.value} policy covering {len(reqs)} requirements"
                    ),
                    rego_code=rego_code,
                    requirements_covered=[r.id for r in reqs],
                    status=PolicyStatus.DRAFT,
                    created_at=now,
                    last_validated=0.0,
                )
            )

        return policies

    # ------------------------------------------------------------------
    # 3. Validate coverage
    # ------------------------------------------------------------------

    async def validate_coverage(
        self,
        policies: list[GeneratedPolicy],
        requirements: list[SecurityRequirement],
    ) -> list[CoverageGap]:
        """Check which security requirements lack policy coverage.

        Returns a list of coverage gaps with severity and suggested fixes.
        """
        logger.info(
            "policy_engine.validate_coverage",
            policy_count=len(policies),
            requirement_count=len(requirements),
        )

        covered_ids: set[str] = set()
        for policy in policies:
            covered_ids.update(policy.requirements_covered)

        gaps: list[CoverageGap] = []
        for req in requirements:
            if req.id not in covered_ids:
                gap_id = _generate_id("GAP", req.id)
                severity = "critical" if req.priority in ("critical", "high") else "medium"
                ptype = self._infer_policy_type(req)
                suggested = POLICY_TEMPLATES.get(ptype, "")

                gaps.append(
                    CoverageGap(
                        id=gap_id,
                        requirement_id=req.id,
                        requirement_title=req.title,
                        gap_description=(
                            f"No policy covers requirement '{req.title}' "
                            f"({req.framework} {req.control_id})"
                        ),
                        severity=severity,
                        suggested_policy=(
                            suggested[:200] + "..." if len(suggested) > 200 else suggested
                        ),
                    )
                )

        return gaps

    # ------------------------------------------------------------------
    # 4. Detect drift
    # ------------------------------------------------------------------

    async def detect_drift(self, policies: list[GeneratedPolicy]) -> list[PolicyDrift]:
        """Compare deployed vs defined policies and detect drift.

        Uses an OPA client if available for live comparison; otherwise
        simulates drift detection using known patterns.
        """
        logger.info("policy_engine.detect_drift", policy_count=len(policies))

        if self._opa_client is not None:
            try:
                raw = await self._opa_client.compare_policies(
                    policies=[p.model_dump() for p in policies],
                )
                return [PolicyDrift(**d) for d in raw]
            except Exception:
                logger.exception("policy_engine.detect_drift.opa_error")

        # Simulate drift detection for policies in non-draft state
        drifts: list[PolicyDrift] = []
        now = time.time()

        active_policies = [p for p in policies if p.status == PolicyStatus.ACTIVE]
        if not active_policies:
            # Treat all as deployed for analysis purposes
            active_policies = policies

        for policy in active_policies:
            # Apply deterministic drift pattern based on policy hash
            policy_hash = int(hashlib.sha256(policy.id.encode()).hexdigest()[:8], 16)
            pattern_idx = policy_hash % len(_DRIFT_PATTERNS)
            pattern = _DRIFT_PATTERNS[pattern_idx]

            # Only report drift for a subset (simulate real-world rates)
            if policy_hash % 3 == 0:
                drift_id = _generate_id("DRF", policy.id, pattern["drift_type"])
                drifts.append(
                    PolicyDrift(
                        id=drift_id,
                        policy_id=policy.id,
                        policy_name=policy.name,
                        drift_type=pattern["drift_type"],
                        expected_state=f"defined:{policy.id}",
                        actual_state=f"deployed:{policy.id}:modified",
                        severity=pattern["severity"],
                        detected_at=now,
                        auto_reconcilable=pattern["auto_reconcilable"],
                    )
                )

        return drifts

    # ------------------------------------------------------------------
    # 5. Reconcile drift
    # ------------------------------------------------------------------

    async def reconcile_drift(self, drifts: list[PolicyDrift]) -> list[ReconciliationAction]:
        """Auto-reconcile driftable policy issues.

        Only reconciles drifts marked as auto_reconcilable. Non-reconcilable
        drifts are flagged for manual review.
        """
        logger.info("policy_engine.reconcile_drift", drift_count=len(drifts))

        actions: list[ReconciliationAction] = []

        for drift in drifts:
            action_id = _generate_id("REC", drift.id)

            if drift.auto_reconcilable:
                action_type = self._reconciliation_action_for(drift.drift_type)
                actions.append(
                    ReconciliationAction(
                        id=action_id,
                        drift_id=drift.id,
                        action=action_type,
                        description=(
                            f"Auto-reconcile {drift.drift_type} for "
                            f"policy '{drift.policy_name}': "
                            f"revert to defined state"
                        ),
                        applied=True,
                        success=True,
                    )
                )

                # Apply via OPA client if available
                if self._opa_client is not None:
                    try:
                        await self._opa_client.apply_policy(
                            policy_id=drift.policy_id,
                            action=action_type,
                        )
                    except Exception:
                        logger.exception("policy_engine.reconcile_drift.apply_error")
                        actions[-1].success = False
            else:
                actions.append(
                    ReconciliationAction(
                        id=action_id,
                        drift_id=drift.id,
                        action="flag_for_review",
                        description=(
                            f"Drift '{drift.drift_type}' for policy "
                            f"'{drift.policy_name}' requires manual review"
                        ),
                        applied=False,
                        success=False,
                    )
                )

        return actions

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_policy_type(req: SecurityRequirement) -> PolicyType:
        """Infer the OPA policy type from a requirement's content."""
        title_lower = req.title.lower()
        desc_lower = req.description.lower()
        combined = f"{title_lower} {desc_lower}"

        if any(kw in combined for kw in ["agent", "blast radius", "confidence", "autonomous"]):
            return PolicyType.AGENT_BEHAVIOR
        if any(kw in combined for kw in ["access control", "rbac", "privilege", "role", "tenant"]):
            return PolicyType.ACCESS_CONTROL
        if any(
            kw in combined
            for kw in [
                "encrypt",
                "pii",
                "phi",
                "data protection",
                "classification",
            ]
        ):
            return PolicyType.DATA_PROTECTION
        if any(kw in combined for kw in ["network", "segment", "boundary", "traffic", "firewall"]):
            return PolicyType.NETWORK
        if any(kw in combined for kw in ["quota", "resource", "limit", "budget"]):
            return PolicyType.RESOURCE_QUOTA
        return PolicyType.COMPLIANCE

    @staticmethod
    def _instantiate_template(
        ptype: PolicyType,
        template: str,
        reqs: list[SecurityRequirement],
    ) -> str:
        """Fill template placeholders with requirement-derived values."""
        if ptype == PolicyType.AGENT_BEHAVIOR:
            allowed = '["investigate", "remediate", "scan", "query"]'
            return template.format(allowed_actions=allowed, max_blast_radius=5)
        if ptype == PolicyType.COMPLIANCE:
            min_days = 365 if any(r.framework == "hipaa" for r in reqs) else 90
            return template.format(min_retention_days=min_days)
        # Other templates have no placeholders
        return template

    @staticmethod
    def _reconciliation_action_for(drift_type: str) -> str:
        """Map drift type to reconciliation action."""
        mapping: dict[str, str] = {
            "rule_modification": "revert_to_source",
            "missing_policy": "deploy_policy",
            "data_document_drift": "sync_data_document",
            "version_mismatch": "update_version",
            "extra_policy": "flag_for_review",
        }
        return mapping.get(drift_type, "flag_for_review")
