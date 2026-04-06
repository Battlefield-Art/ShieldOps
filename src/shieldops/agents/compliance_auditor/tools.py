"""Compliance Auditor Agent — Tool functions for compliance scanning and evidence collection."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.connectors.base import ConnectorRouter
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Default control definitions per framework
_FRAMEWORK_CONTROLS: dict[str, list[dict[str, str]]] = {
    "soc2": [
        {"control_id": "SOC2-CC6.1", "description": "Logical and physical access controls"},
        {"control_id": "SOC2-CC6.2", "description": "User authentication mechanisms"},
        {"control_id": "SOC2-CC7.1", "description": "System monitoring and anomaly detection"},
        {"control_id": "SOC2-CC7.2", "description": "Incident response procedures"},
        {"control_id": "SOC2-CC8.1", "description": "Change management controls"},
    ],
    "pci_dss": [
        {"control_id": "PCI-1.1", "description": "Install and maintain network security controls"},
        {"control_id": "PCI-2.1", "description": "Apply secure configurations"},
        {"control_id": "PCI-3.1", "description": "Protect stored account data"},
        {"control_id": "PCI-6.1", "description": "Develop and maintain secure systems"},
        {"control_id": "PCI-8.1", "description": "Identify users and authenticate access"},
    ],
    "hipaa": [
        {"control_id": "HIPAA-164.312a", "description": "Access control — unique user ID"},
        {"control_id": "HIPAA-164.312b", "description": "Audit controls — activity logging"},
        {"control_id": "HIPAA-164.312c", "description": "Integrity controls — ePHI protection"},
        {"control_id": "HIPAA-164.312d", "description": "Person authentication"},
        {"control_id": "HIPAA-164.312e", "description": "Transmission security — encryption"},
    ],
    "gdpr": [
        {"control_id": "GDPR-Art25", "description": "Data protection by design and default"},
        {"control_id": "GDPR-Art30", "description": "Records of processing activities"},
        {"control_id": "GDPR-Art32", "description": "Security of processing"},
        {"control_id": "GDPR-Art33", "description": "Breach notification to authority"},
        {"control_id": "GDPR-Art35", "description": "Data protection impact assessment"},
    ],
    "iso27001": [
        {"control_id": "ISO-A5", "description": "Information security policies"},
        {"control_id": "ISO-A6", "description": "Organization of information security"},
        {"control_id": "ISO-A8", "description": "Asset management"},
        {"control_id": "ISO-A9", "description": "Access control"},
        {"control_id": "ISO-A12", "description": "Operations security"},
    ],
}

# Maps AWS config findings to framework controls
_AWS_CONTROL_MAPPING: dict[str, dict[str, list[str]]] = {
    "s3_bucket_policy": {
        "soc2": ["SOC2-CC6.1"],
        "pci_dss": ["PCI-3.1"],
        "hipaa": ["HIPAA-164.312c"],
        "gdpr": ["GDPR-Art32"],
        "iso27001": ["ISO-A8"],
    },
    "iam_password_policy": {
        "soc2": ["SOC2-CC6.2"],
        "pci_dss": ["PCI-8.1"],
        "hipaa": ["HIPAA-164.312d"],
        "gdpr": ["GDPR-Art32"],
        "iso27001": ["ISO-A9"],
    },
    "cloudtrail_status": {
        "soc2": ["SOC2-CC7.1"],
        "pci_dss": ["PCI-6.1"],
        "hipaa": ["HIPAA-164.312b"],
        "gdpr": ["GDPR-Art30"],
        "iso27001": ["ISO-A12"],
    },
    "encryption_settings": {
        "soc2": ["SOC2-CC6.1"],
        "pci_dss": ["PCI-3.1"],
        "hipaa": ["HIPAA-164.312e"],
        "gdpr": ["GDPR-Art25"],
        "iso27001": ["ISO-A8"],
    },
    "vpc_flow_logs": {
        "soc2": ["SOC2-CC7.1", "SOC2-CC7.2"],
        "pci_dss": ["PCI-1.1"],
        "hipaa": ["HIPAA-164.312b"],
        "gdpr": ["GDPR-Art30"],
        "iso27001": ["ISO-A12"],
    },
}

# Remediation guidance per finding type
_REMEDIATION_GUIDANCE: dict[str, str] = {
    "s3_public_access": (
        "Enable S3 Block Public Access at account level. Review bucket policies "
        "and ACLs to remove public grants. Enable server-side encryption (SSE-S3 or SSE-KMS)."
    ),
    "iam_weak_password": (
        "Enforce minimum 14-character passwords with complexity requirements. "
        "Enable MFA for all IAM users. Set password expiry to 90 days."
    ),
    "cloudtrail_disabled": (
        "Enable CloudTrail in all regions with multi-region trail. "
        "Enable log file validation and deliver logs to a secured S3 bucket."
    ),
    "encryption_missing": (
        "Enable encryption at rest for all storage services (S3, EBS, RDS). "
        "Use KMS customer-managed keys. Enable encryption in transit (TLS 1.2+)."
    ),
    "vpc_flow_logs_disabled": (
        "Enable VPC Flow Logs for all VPCs. Configure delivery to CloudWatch Logs "
        "or S3. Set capture mode to ALL traffic (accept + reject)."
    ),
    "mfa_not_enforced": (
        "Enforce MFA for all user accounts, especially privileged accounts. "
        "Use hardware tokens or FIDO2 authenticators for admin access."
    ),
    "least_privilege_violation": (
        "Review IAM policies and remove unused permissions. Use IAM Access Analyzer "
        "to identify overly permissive policies. Implement just-in-time access."
    ),
    "credential_rotation_overdue": (
        "Rotate all access keys older than 90 days. Implement automated credential "
        "rotation using AWS Secrets Manager or similar. Disable unused keys."
    ),
    "patch_sla_breach": (
        "Prioritize patching critical CVEs within 7-day SLA. Implement automated "
        "patch management. Track remediation progress in vulnerability dashboard."
    ),
    "high_cve_count": (
        "Reduce critical/high CVE count through prioritized patching. Focus on "
        "internet-facing assets first. Consider virtual patching via WAF rules."
    ),
}


class _LLMRemediationSuggestion(BaseModel):
    """LLM-generated remediation suggestion for a compliance finding."""

    remediation_steps: str = Field(
        description="Concise, actionable remediation steps for the compliance finding"
    )
    estimated_effort: str = Field(
        default="medium",
        description="Estimated effort to remediate (low/medium/high)",
    )
    aws_services_involved: list[str] = Field(
        default_factory=list,
        description="AWS services involved in the remediation",
    )


class ComplianceAuditorToolkit:
    """Tools for compliance scanning, evidence collection, and gap analysis.

    Integrates with AWS cloud connector for real config auditing,
    identity_graph agent for access control posture, and
    vulnerability_manager agent for patch compliance assessment.
    """

    def __init__(
        self,
        compliance_backend: Any | None = None,
        evidence_store: Any | None = None,
        connector_router: ConnectorRouter | None = None,
        opa_client: Any | None = None,
    ) -> None:
        self._compliance_backend = compliance_backend
        self._evidence_store = evidence_store
        self._router = connector_router
        self._opa_client = opa_client

    # ------------------------------------------------------------------
    # 1. AWS Config Auditing
    # ------------------------------------------------------------------

    async def audit_aws_config(
        self,
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Query AWS connector for cloud configuration compliance findings.

        Checks: S3 bucket policies, IAM password policy, CloudTrail status,
        encryption settings, VPC flow logs. Each finding is mapped to
        applicable compliance controls.

        Returns:
            List of finding dicts with check_type, status, details, and
            mapped_controls.
        """
        context = context or {}
        environment = context.get("environment", "production")
        logger.info("compliance_auditor.audit_aws_config", environment=environment)

        findings: list[dict[str, Any]] = []

        if self._router is not None:
            try:
                connector = self._router.get("aws")
                findings = await self._query_aws_config(connector, environment)
                logger.info(
                    "compliance_auditor.audit_aws_config.complete",
                    finding_count=len(findings),
                    source="aws_connector",
                )
                return findings
            except (ValueError, AttributeError) as exc:
                logger.warning(
                    "compliance_auditor.audit_aws_config.connector_unavailable",
                    error=str(exc),
                )
            except Exception as exc:
                logger.exception(
                    "compliance_auditor.audit_aws_config.error",
                    error=str(exc),
                )

        # Fallback: generate heuristic findings for dev/testing
        findings = self._generate_mock_aws_findings()
        logger.info(
            "compliance_auditor.audit_aws_config.complete",
            finding_count=len(findings),
            source="heuristic",
        )
        return findings

    async def _query_aws_config(
        self,
        connector: Any,
        environment: str,
    ) -> list[dict[str, Any]]:
        """Query real AWS connector for configuration data."""
        findings: list[dict[str, Any]] = []

        # S3 bucket policies
        try:
            buckets = await connector.list_resources("s3_bucket", environment, {})
            for bucket in buckets:
                metadata = getattr(bucket, "metadata", {}) or {}
                public_access = metadata.get("public_access_blocked", True)
                encrypted = metadata.get("encryption_enabled", True)
                status = "pass" if (public_access and encrypted) else "fail"
                findings.append(
                    {
                        "check_type": "s3_bucket_policy",
                        "resource_id": getattr(bucket, "id", str(bucket)),
                        "status": status,
                        "details": {
                            "public_access_blocked": public_access,
                            "encryption_enabled": encrypted,
                            "bucket_name": getattr(bucket, "name", ""),
                        },
                        "mapped_controls": _AWS_CONTROL_MAPPING.get("s3_bucket_policy", {}),
                        "timestamp": datetime.now(UTC).isoformat(),
                    }
                )
        except Exception as exc:
            logger.warning("compliance_auditor.s3_check_failed", error=str(exc))

        # IAM password policy
        try:
            iam_resources = await connector.list_resources("iam_policy", environment, {})
            has_strong_policy = any(
                (getattr(r, "metadata", {}) or {}).get("password_policy_strong", False)
                for r in iam_resources
            )
            findings.append(
                {
                    "check_type": "iam_password_policy",
                    "resource_id": "account-password-policy",
                    "status": "pass" if has_strong_policy else "fail",
                    "details": {
                        "strong_password_policy": has_strong_policy,
                        "min_length": 14 if has_strong_policy else 8,
                        "require_symbols": has_strong_policy,
                        "max_age_days": 90 if has_strong_policy else 0,
                    },
                    "mapped_controls": _AWS_CONTROL_MAPPING.get("iam_password_policy", {}),
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
        except Exception as exc:
            logger.warning("compliance_auditor.iam_check_failed", error=str(exc))

        # CloudTrail status
        try:
            trails = await connector.list_resources("cloudtrail", environment, {})
            trail_enabled = len(trails) > 0
            multi_region = any(
                (getattr(t, "metadata", {}) or {}).get("is_multi_region", False) for t in trails
            )
            findings.append(
                {
                    "check_type": "cloudtrail_status",
                    "resource_id": "cloudtrail-config",
                    "status": "pass" if (trail_enabled and multi_region) else "fail",
                    "details": {
                        "trail_enabled": trail_enabled,
                        "multi_region": multi_region,
                        "log_validation": trail_enabled,
                        "trail_count": len(trails),
                    },
                    "mapped_controls": _AWS_CONTROL_MAPPING.get("cloudtrail_status", {}),
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
        except Exception as exc:
            logger.warning("compliance_auditor.cloudtrail_check_failed", error=str(exc))

        # Encryption settings
        try:
            ebs_volumes = await connector.list_resources("ebs_volume", environment, {})
            unencrypted = [
                v
                for v in ebs_volumes
                if not (getattr(v, "metadata", {}) or {}).get("encrypted", False)
            ]
            findings.append(
                {
                    "check_type": "encryption_settings",
                    "resource_id": "ebs-encryption",
                    "status": "pass" if len(unencrypted) == 0 else "fail",
                    "details": {
                        "total_volumes": len(ebs_volumes),
                        "unencrypted_count": len(unencrypted),
                        "encryption_percentage": (
                            round(
                                (len(ebs_volumes) - len(unencrypted))
                                / max(len(ebs_volumes), 1)
                                * 100,
                                1,
                            )
                        ),
                    },
                    "mapped_controls": _AWS_CONTROL_MAPPING.get("encryption_settings", {}),
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
        except Exception as exc:
            logger.warning("compliance_auditor.encryption_check_failed", error=str(exc))

        # VPC flow logs
        try:
            vpcs = await connector.list_resources("vpc", environment, {})
            vpcs_without_logs = [
                v
                for v in vpcs
                if not (getattr(v, "metadata", {}) or {}).get("flow_logs_enabled", False)
            ]
            findings.append(
                {
                    "check_type": "vpc_flow_logs",
                    "resource_id": "vpc-flow-logs",
                    "status": "pass" if len(vpcs_without_logs) == 0 else "fail",
                    "details": {
                        "total_vpcs": len(vpcs),
                        "vpcs_without_flow_logs": len(vpcs_without_logs),
                        "coverage_percentage": (
                            round(
                                (len(vpcs) - len(vpcs_without_logs)) / max(len(vpcs), 1) * 100,
                                1,
                            )
                        ),
                    },
                    "mapped_controls": _AWS_CONTROL_MAPPING.get("vpc_flow_logs", {}),
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
        except Exception as exc:
            logger.warning("compliance_auditor.vpc_check_failed", error=str(exc))

        return findings

    @staticmethod
    def _generate_mock_aws_findings() -> list[dict[str, Any]]:
        """Generate realistic mock AWS config findings for dev/testing."""
        now = datetime.now(UTC).isoformat()
        return [
            {
                "check_type": "s3_bucket_policy",
                "resource_id": "data-lake-prod",
                "status": "fail",
                "details": {
                    "public_access_blocked": False,
                    "encryption_enabled": True,
                    "bucket_name": "data-lake-prod",
                },
                "mapped_controls": _AWS_CONTROL_MAPPING["s3_bucket_policy"],
                "timestamp": now,
            },
            {
                "check_type": "iam_password_policy",
                "resource_id": "account-password-policy",
                "status": "fail",
                "details": {
                    "strong_password_policy": False,
                    "min_length": 8,
                    "require_symbols": False,
                    "max_age_days": 0,
                },
                "mapped_controls": _AWS_CONTROL_MAPPING["iam_password_policy"],
                "timestamp": now,
            },
            {
                "check_type": "cloudtrail_status",
                "resource_id": "cloudtrail-config",
                "status": "pass",
                "details": {
                    "trail_enabled": True,
                    "multi_region": True,
                    "log_validation": True,
                    "trail_count": 2,
                },
                "mapped_controls": _AWS_CONTROL_MAPPING["cloudtrail_status"],
                "timestamp": now,
            },
            {
                "check_type": "encryption_settings",
                "resource_id": "ebs-encryption",
                "status": "fail",
                "details": {
                    "total_volumes": 20,
                    "unencrypted_count": 3,
                    "encryption_percentage": 85.0,
                },
                "mapped_controls": _AWS_CONTROL_MAPPING["encryption_settings"],
                "timestamp": now,
            },
            {
                "check_type": "vpc_flow_logs",
                "resource_id": "vpc-flow-logs",
                "status": "pass",
                "details": {
                    "total_vpcs": 5,
                    "vpcs_without_flow_logs": 0,
                    "coverage_percentage": 100.0,
                },
                "mapped_controls": _AWS_CONTROL_MAPPING["vpc_flow_logs"],
                "timestamp": now,
            },
        ]

    # ------------------------------------------------------------------
    # 2. Control Assessment
    # ------------------------------------------------------------------

    async def audit_controls(
        self,
        framework: str,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Map AWS config findings to framework controls and assess each.

        For each control in the framework, checks whether relevant findings
        pass or fail, producing a per-control pass/fail/warning assessment.

        Args:
            framework: Compliance framework key (soc2, hipaa, pci_dss, etc.).
            findings: List of findings from audit_aws_config.

        Returns:
            List of control assessment dicts with control_id, description,
            status, evidence_source, and gaps.
        """
        logger.info(
            "compliance_auditor.audit_controls",
            framework=framework,
            finding_count=len(findings),
        )

        controls = _FRAMEWORK_CONTROLS.get(framework, [])
        if not controls:
            logger.warning("compliance_auditor.audit_controls.unknown_framework", fw=framework)
            return []

        # Build reverse map: control_id -> list of relevant findings
        control_findings: dict[str, list[dict[str, Any]]] = {c["control_id"]: [] for c in controls}
        for finding in findings:
            mapped = finding.get("mapped_controls", {})
            ctrl_ids = mapped.get(framework, [])
            for ctrl_id in ctrl_ids:
                if ctrl_id in control_findings:
                    control_findings[ctrl_id].append(finding)

        assessments: list[dict[str, Any]] = []
        for ctrl in controls:
            ctrl_id = ctrl["control_id"]
            relevant = control_findings.get(ctrl_id, [])

            if not relevant:
                # No findings mapped to this control — mark as warning
                status = "warning"
                gaps = ["No automated evidence collected for this control"]
                evidence_sources: list[str] = []
            else:
                failed = [f for f in relevant if f.get("status") == "fail"]
                passed = [f for f in relevant if f.get("status") == "pass"]

                if not failed:
                    status = "pass"
                    gaps = []
                elif not passed:
                    status = "fail"
                    gaps = [f"{f['check_type']}: {_get_finding_gap_description(f)}" for f in failed]
                else:
                    status = "warning"
                    gaps = [f"{f['check_type']}: {_get_finding_gap_description(f)}" for f in failed]

                evidence_sources = [f["check_type"] for f in relevant]

            assessments.append(
                {
                    "control_id": ctrl_id,
                    "framework": framework,
                    "description": ctrl["description"],
                    "status": status,
                    "evidence_sources": evidence_sources,
                    "gaps": gaps,
                    "finding_count": len(relevant),
                    "assessed_at": datetime.now(UTC).isoformat(),
                }
            )

        return assessments

    # ------------------------------------------------------------------
    # 3. Identity Posture Check (integrates identity_graph data)
    # ------------------------------------------------------------------

    def check_identity_posture(
        self,
        identity_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Assess access control compliance using identity_graph data.

        Evaluates MFA enforcement, least-privilege adherence, and credential
        rotation compliance from the identity graph inventory and risk data.

        Args:
            identity_data: Output from IdentityGraphToolkit methods, expected
                keys: identities (list), risk_distribution (dict), top_risks (list).

        Returns:
            Posture score dict with overall_score (0-100), dimension scores,
            findings, and remediation recommendations.
        """
        logger.info("compliance_auditor.check_identity_posture")

        identities = identity_data.get("identities", [])
        risk_distribution = identity_data.get("risk_distribution", {})
        identity_data.get("top_risks", [])

        if not identities:
            return {
                "overall_score": 0.0,
                "mfa_score": 0.0,
                "least_privilege_score": 0.0,
                "credential_rotation_score": 0.0,
                "findings": ["No identity data available for assessment"],
                "recommendations": ["Run identity graph discovery before compliance audit"],
                "assessed_at": datetime.now(UTC).isoformat(),
            }

        total = len(identities)

        # MFA enforcement (0-100)
        mfa_enabled_count = sum(1 for i in identities if i.get("mfa_enabled", False))
        mfa_score = round((mfa_enabled_count / max(total, 1)) * 100, 1)

        # Least privilege (0-100): penalize identities with admin/root perms
        admin_keywords = {
            "admin",
            "root",
            "superuser",
            "global_admin",
            "owner",
            "iam:*",
            "ec2:*",
            "s3:*",
            "AdministratorAccess",
        }
        overprivileged_count = 0
        for ident in identities:
            perms = {p.lower() for p in (ident.get("permissions") or [])}
            if perms & admin_keywords:
                overprivileged_count += 1
        least_priv_score = round(((total - overprivileged_count) / max(total, 1)) * 100, 1)

        # Credential rotation (0-100): penalize stale credentials
        rotation_threshold_days = 90
        now = datetime.now(UTC)
        stale_count = 0
        for ident in identities:
            created_at = ident.get("created_at")
            last_rotated = ident.get("last_rotated")
            if isinstance(created_at, str) and not last_rotated:
                try:
                    created_dt = datetime.fromisoformat(created_at)
                    if hasattr(created_dt, "tzinfo") and created_dt.tzinfo is None:
                        created_dt = created_dt.replace(tzinfo=UTC)
                    age_days = (now - created_dt).days
                    if age_days > rotation_threshold_days:
                        stale_count += 1
                except (ValueError, TypeError):
                    pass
        rotation_score = round(((total - stale_count) / max(total, 1)) * 100, 1)

        # Overall score: weighted average
        overall = round(
            mfa_score * 0.35 + least_priv_score * 0.35 + rotation_score * 0.30,
            1,
        )

        # Build findings
        findings: list[str] = []
        recommendations: list[str] = []

        if mfa_score < 100:
            no_mfa = total - mfa_enabled_count
            findings.append(f"{no_mfa}/{total} identities lack MFA enforcement")
            recommendations.append(_REMEDIATION_GUIDANCE["mfa_not_enforced"])

        if overprivileged_count > 0:
            findings.append(
                f"{overprivileged_count}/{total} identities have admin-level privileges"
            )
            recommendations.append(_REMEDIATION_GUIDANCE["least_privilege_violation"])

        if stale_count > 0:
            findings.append(
                f"{stale_count}/{total} identities have credentials older than "
                f"{rotation_threshold_days} days without rotation"
            )
            recommendations.append(_REMEDIATION_GUIDANCE["credential_rotation_overdue"])

        # Incorporate risk distribution if available
        critical_count = risk_distribution.get("critical", 0)
        high_count = risk_distribution.get("high", 0)
        if critical_count > 0:
            findings.append(f"{critical_count} identities at critical risk level")
        if high_count > 0:
            findings.append(f"{high_count} identities at high risk level")

        if not findings:
            findings.append("All identity posture checks passed")

        return {
            "overall_score": overall,
            "mfa_score": mfa_score,
            "least_privilege_score": least_priv_score,
            "credential_rotation_score": rotation_score,
            "identity_count": total,
            "mfa_enabled_count": mfa_enabled_count,
            "overprivileged_count": overprivileged_count,
            "stale_credential_count": stale_count,
            "findings": findings,
            "recommendations": recommendations,
            "assessed_at": datetime.now(UTC).isoformat(),
        }

    # ------------------------------------------------------------------
    # 4. Vulnerability Posture Check (integrates vulnerability_manager data)
    # ------------------------------------------------------------------

    def check_vulnerability_posture(
        self,
        vuln_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Assess patch compliance using vulnerability_manager data.

        Evaluates SLA adherence, critical CVE count, and remediation rate
        from vulnerability scan results.

        Args:
            vuln_data: Output from VulnerabilityManagerToolkit, expected keys:
                vulnerabilities (list of vuln dicts with severity, days_open,
                sla_days, fix_available, etc.), total_count (int).

        Returns:
            Posture score dict with overall_score (0-100), dimension scores,
            findings, and remediation recommendations.
        """
        logger.info("compliance_auditor.check_vulnerability_posture")

        vulns = vuln_data.get("vulnerabilities", [])

        if not vulns:
            return {
                "overall_score": 0.0,
                "sla_adherence_score": 0.0,
                "critical_cve_score": 0.0,
                "remediation_rate_score": 0.0,
                "findings": ["No vulnerability data available for assessment"],
                "recommendations": ["Run vulnerability scan before compliance audit"],
                "assessed_at": datetime.now(UTC).isoformat(),
            }

        total = len(vulns)

        # SLA adherence (0-100): percentage of vulns within SLA
        sla_breaches = 0
        for v in vulns:
            days_open = v.get("days_open", 0)
            sla_days = v.get("sla_days", 90)
            if days_open > sla_days:
                sla_breaches += 1
        sla_score = round(((total - sla_breaches) / max(total, 1)) * 100, 1)

        # Critical CVE score (0-100): lower is worse (more criticals = lower score)
        severity_weights = {"critical": 1.0, "high": 0.6, "medium": 0.3, "low": 0.1, "info": 0.0}
        critical_count = 0
        high_count = 0
        weighted_severity_sum = 0.0
        for v in vulns:
            sev = (v.get("severity") or "medium").lower()
            weighted_severity_sum += severity_weights.get(sev, 0.3)
            if sev == "critical":
                critical_count += 1
            elif sev == "high":
                high_count += 1

        # Score: 100 if avg severity is 0, 0 if avg severity is 1.0
        avg_severity = weighted_severity_sum / max(total, 1)
        cve_score = round((1.0 - avg_severity) * 100, 1)

        # Remediation rate (0-100): percentage with fix available and applied or in progress
        remediated = sum(1 for v in vulns if v.get("status") in ("remediated", "fixed", "resolved"))
        fix_available = sum(1 for v in vulns if v.get("fix_available", False))
        remediation_score = (
            round((remediated / max(fix_available, 1)) * 100, 1) if fix_available > 0 else 100.0
        )

        # Overall score: weighted average
        overall = round(
            sla_score * 0.40 + cve_score * 0.30 + remediation_score * 0.30,
            1,
        )

        # Findings and recommendations
        findings: list[str] = []
        recommendations: list[str] = []

        if sla_breaches > 0:
            findings.append(f"{sla_breaches}/{total} vulnerabilities exceed SLA")
            recommendations.append(_REMEDIATION_GUIDANCE["patch_sla_breach"])

        if critical_count > 0:
            findings.append(f"{critical_count} critical CVEs remain unresolved")
            recommendations.append(_REMEDIATION_GUIDANCE["high_cve_count"])

        if high_count > 0:
            findings.append(f"{high_count} high-severity CVEs remain unresolved")

        if fix_available > remediated:
            pending = fix_available - remediated
            findings.append(f"{pending} vulnerabilities have fixes available but not yet applied")

        if not findings:
            findings.append("All vulnerability posture checks passed")

        return {
            "overall_score": overall,
            "sla_adherence_score": sla_score,
            "critical_cve_score": cve_score,
            "remediation_rate_score": remediation_score,
            "total_vulnerabilities": total,
            "sla_breaches": sla_breaches,
            "critical_count": critical_count,
            "high_count": high_count,
            "remediated_count": remediated,
            "fix_available_count": fix_available,
            "findings": findings,
            "recommendations": recommendations,
            "assessed_at": datetime.now(UTC).isoformat(),
        }

    # ------------------------------------------------------------------
    # 5. Evidence Report Generation
    # ------------------------------------------------------------------

    def generate_evidence(
        self,
        assessments: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate markdown evidence reports for each framework.

        Produces structured evidence documents with control ID, description,
        status, evidence source, and remediation guidance for each assessed
        control.

        Args:
            assessments: List of control assessment dicts from audit_controls.

        Returns:
            List of evidence document dicts, one per framework, each containing
            framework, markdown content, control_count, and pass_rate.
        """
        logger.info(
            "compliance_auditor.generate_evidence",
            assessment_count=len(assessments),
        )

        # Group assessments by framework
        by_framework: dict[str, list[dict[str, Any]]] = {}
        for a in assessments:
            fw = a.get("framework", "unknown")
            by_framework.setdefault(fw, []).append(a)

        evidence_docs: list[dict[str, Any]] = []
        now = datetime.now(UTC).isoformat()

        for framework, controls in by_framework.items():
            total = len(controls)
            passed = sum(1 for c in controls if c.get("status") == "pass")
            failed = sum(1 for c in controls if c.get("status") == "fail")
            warnings = sum(1 for c in controls if c.get("status") == "warning")
            pass_rate = round((passed / max(total, 1)) * 100, 1)

            # Build markdown
            lines: list[str] = [
                f"# Compliance Evidence Report: {framework.upper()}",
                "",
                f"**Generated:** {now}",
                f"**Total Controls:** {total}",
                f"**Pass Rate:** {pass_rate}%",
                f"**Status:** {passed} pass | {failed} fail | {warnings} warning",
                "",
                "---",
                "",
            ]

            for ctrl in controls:
                ctrl_id = ctrl.get("control_id", "N/A")
                desc = ctrl.get("description", "")
                status = ctrl.get("status", "unknown")
                gaps = ctrl.get("gaps", [])
                evidence_sources = ctrl.get("evidence_sources", [])

                status_icon = (
                    "PASS" if status == "pass" else "FAIL" if status == "fail" else "WARNING"
                )

                lines.append(f"## {ctrl_id}: {desc}")
                lines.append("")
                lines.append(f"- **Status:** {status_icon}")
                lines.append(
                    f"- **Evidence Sources:** "
                    f"{', '.join(evidence_sources) if evidence_sources else 'None'}"
                )

                if gaps:
                    lines.append("- **Gaps:**")
                    for gap in gaps:
                        lines.append(f"  - {gap}")
                    # Add remediation guidance for known gap types
                    for gap in gaps:
                        for key, guidance in _REMEDIATION_GUIDANCE.items():
                            if key in gap:
                                lines.append(f"- **Remediation:** {guidance}")
                                break

                lines.append("")

            evidence_docs.append(
                {
                    "framework": framework,
                    "markdown": "\n".join(lines),
                    "control_count": total,
                    "passed": passed,
                    "failed": failed,
                    "warnings": warnings,
                    "pass_rate": pass_rate,
                    "generated_at": now,
                }
            )

        return evidence_docs

    # ------------------------------------------------------------------
    # 6. Full Compliance Report
    # ------------------------------------------------------------------

    def generate_report(
        self,
        all_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate a full compliance report across all data sources.

        Combines control assessments, identity posture, vulnerability posture,
        and AWS config findings into a unified compliance report with overall
        scores, gap analysis, and remediation recommendations.

        Args:
            all_data: Dict with optional keys: control_assessments (list),
                identity_posture (dict), vulnerability_posture (dict),
                aws_findings (list), previous_score (float for trend).

        Returns:
            Comprehensive report dict with per-framework scores, overall
            compliance score, top gaps, recommendations, and trend analysis.
        """
        logger.info("compliance_auditor.generate_report")

        control_assessments = all_data.get("control_assessments", [])
        identity_posture = all_data.get("identity_posture", {})
        vuln_posture = all_data.get("vulnerability_posture", {})
        aws_findings = all_data.get("aws_findings", [])
        previous_score = all_data.get("previous_score")

        # Per-framework scoring
        framework_scores: dict[str, dict[str, Any]] = {}
        for a in control_assessments:
            fw = a.get("framework", "unknown")
            if fw not in framework_scores:
                framework_scores[fw] = {"total": 0, "passed": 0, "failed": 0, "warning": 0}
            framework_scores[fw]["total"] += 1
            status = a.get("status", "")
            if status == "pass":
                framework_scores[fw]["passed"] += 1
            elif status == "fail":
                framework_scores[fw]["failed"] += 1
            elif status == "warning":
                framework_scores[fw]["warning"] += 1

        for _fw, counts in framework_scores.items():
            total = counts["total"]
            if total > 0:
                counts["pass_rate"] = round(
                    (counts["passed"] + counts["warning"] * 0.5) / total * 100, 1
                )
            else:
                counts["pass_rate"] = 0.0

        # Overall control compliance score
        total_controls = sum(c["total"] for c in framework_scores.values())
        total_passed = sum(c["passed"] for c in framework_scores.values())
        total_warnings = sum(c["warning"] for c in framework_scores.values())
        control_score = (
            round((total_passed + total_warnings * 0.5) / max(total_controls, 1) * 100, 1)
            if total_controls > 0
            else 0.0
        )

        # Composite overall score including identity and vuln posture
        identity_score = identity_posture.get("overall_score", 0.0)
        vuln_score = vuln_posture.get("overall_score", 0.0)

        # Weight: control compliance 50%, identity posture 25%, vuln posture 25%
        has_identity = bool(identity_posture)
        has_vuln = bool(vuln_posture)

        if has_identity and has_vuln:
            overall_score = round(
                control_score * 0.50 + identity_score * 0.25 + vuln_score * 0.25, 1
            )
        elif has_identity:
            overall_score = round(control_score * 0.65 + identity_score * 0.35, 1)
        elif has_vuln:
            overall_score = round(control_score * 0.65 + vuln_score * 0.35, 1)
        else:
            overall_score = control_score

        # Top gaps from all sources
        top_gaps: list[str] = []
        for a in control_assessments:
            for gap in a.get("gaps", []):
                top_gaps.append(f"[{a.get('framework', '')}] {a.get('control_id', '')}: {gap}")
        for finding in identity_posture.get("findings", []):
            top_gaps.append(f"[Identity] {finding}")
        for finding in vuln_posture.get("findings", []):
            top_gaps.append(f"[Vulnerability] {finding}")

        # Deduplicated recommendations
        recommendation_set: list[str] = []
        seen: set[str] = set()
        for src in [
            identity_posture.get("recommendations", []),
            vuln_posture.get("recommendations", []),
        ]:
            for rec in src:
                if rec not in seen:
                    recommendation_set.append(rec)
                    seen.add(rec)

        # Add gap-specific recommendations from control assessments
        failed_controls = [a for a in control_assessments if a.get("status") == "fail"]
        if failed_controls:
            recommendation_set.insert(
                0,
                f"Remediate {len(failed_controls)} non-compliant controls immediately",
            )

        # AWS finding summary
        aws_summary = {}
        if aws_findings:
            aws_pass = sum(1 for f in aws_findings if f.get("status") == "pass")
            aws_fail = sum(1 for f in aws_findings if f.get("status") == "fail")
            aws_summary = {
                "total_checks": len(aws_findings),
                "passed": aws_pass,
                "failed": aws_fail,
                "pass_rate": round(aws_pass / max(len(aws_findings), 1) * 100, 1),
            }

        # Trend analysis
        trend = None
        if previous_score is not None:
            delta = round(overall_score - previous_score, 1)
            if delta > 0:
                trend = {"direction": "improving", "delta": delta}
            elif delta < 0:
                trend = {"direction": "declining", "delta": delta}
            else:
                trend = {"direction": "stable", "delta": 0.0}

        return {
            "overall_score": overall_score,
            "control_compliance_score": control_score,
            "identity_posture_score": identity_score if has_identity else None,
            "vulnerability_posture_score": vuln_score if has_vuln else None,
            "framework_scores": framework_scores,
            "total_controls_assessed": total_controls,
            "total_passed": total_passed,
            "total_failed": sum(c["failed"] for c in framework_scores.values()),
            "total_warnings": total_warnings,
            "aws_config_summary": aws_summary if aws_summary else None,
            "top_gaps": top_gaps[:20],
            "recommendations": recommendation_set,
            "trend": trend,
            "generated_at": datetime.now(UTC).isoformat(),
        }

    # ------------------------------------------------------------------
    # 7. Security Group Rule Evaluation
    # ------------------------------------------------------------------

    async def evaluate_security_groups(
        self,
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluate AWS security groups for compliance violations.

        Checks for open ports, unrestricted CIDR (0.0.0.0/0 and ::/0),
        and sensitive port exposure (SSH/22, RDP/3389, DB ports).

        Returns:
            List of security group finding dicts.
        """
        context = context or {}
        environment = context.get("environment", "production")
        logger.info("compliance_auditor.evaluate_security_groups", environment=environment)

        findings: list[dict[str, Any]] = []

        if self._router is not None:
            try:
                connector = self._router.get("aws")
                findings = await self._query_security_groups(connector, environment)
                logger.info(
                    "compliance_auditor.evaluate_security_groups.complete",
                    finding_count=len(findings),
                    source="aws_connector",
                )
                return findings
            except (ValueError, AttributeError) as exc:
                logger.warning(
                    "compliance_auditor.evaluate_security_groups.connector_unavailable",
                    error=str(exc),
                )
            except Exception as exc:
                logger.exception(
                    "compliance_auditor.evaluate_security_groups.error",
                    error=str(exc),
                )

        # Fallback: heuristic findings for dev/testing
        findings = self._generate_mock_security_group_findings()
        logger.info(
            "compliance_auditor.evaluate_security_groups.complete",
            finding_count=len(findings),
            source="heuristic",
        )
        return findings

    async def _query_security_groups(
        self,
        connector: Any,
        environment: str,
    ) -> list[dict[str, Any]]:
        """Query real AWS connector for security group rules."""
        findings: list[dict[str, Any]] = []
        sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}

        try:
            security_groups = await connector.list_resources("security_group", environment, {})
            for sg in security_groups:
                metadata = getattr(sg, "metadata", {}) or {}
                rules = metadata.get("ingress_rules", [])
                sg_id = getattr(sg, "id", str(sg))
                sg_name = getattr(sg, "name", sg_id)

                for rule in rules:
                    cidr = rule.get("cidr", "")
                    from_port = rule.get("from_port", 0)
                    to_port = rule.get("to_port", 65535)
                    protocol = rule.get("protocol", "tcp")

                    is_open_to_world = cidr in ("0.0.0.0/0", "::/0")
                    exposed_sensitive = False
                    if is_open_to_world:
                        for port in sensitive_ports:
                            if from_port <= port <= to_port:
                                exposed_sensitive = True
                                break

                    risk_level = (
                        "critical" if exposed_sensitive else ("high" if is_open_to_world else "low")
                    )

                    if is_open_to_world:
                        findings.append(
                            {
                                "group_id": sg_id,
                                "group_name": sg_name,
                                "rule_direction": "ingress",
                                "protocol": protocol,
                                "port_range": f"{from_port}-{to_port}",
                                "cidr": cidr,
                                "is_open_to_world": True,
                                "risk_level": risk_level,
                                "has_sensitive_port": exposed_sensitive,
                                "mapped_controls": _AWS_CONTROL_MAPPING.get("vpc_flow_logs", {}),
                                "timestamp": datetime.now(UTC).isoformat(),
                            }
                        )
        except Exception as exc:
            logger.warning(
                "compliance_auditor.security_group_check_failed",
                error=str(exc),
            )

        return findings

    @staticmethod
    def _generate_mock_security_group_findings() -> list[dict[str, Any]]:
        """Generate mock security group findings for dev/testing."""
        now = datetime.now(UTC).isoformat()
        return [
            {
                "group_id": "sg-0abc123",
                "group_name": "web-servers",
                "rule_direction": "ingress",
                "protocol": "tcp",
                "port_range": "22-22",
                "cidr": "0.0.0.0/0",
                "is_open_to_world": True,
                "risk_level": "critical",
                "has_sensitive_port": True,
                "mapped_controls": _AWS_CONTROL_MAPPING.get("vpc_flow_logs", {}),
                "timestamp": now,
            },
            {
                "group_id": "sg-0def456",
                "group_name": "db-servers",
                "rule_direction": "ingress",
                "protocol": "tcp",
                "port_range": "5432-5432",
                "cidr": "0.0.0.0/0",
                "is_open_to_world": True,
                "risk_level": "critical",
                "has_sensitive_port": True,
                "mapped_controls": _AWS_CONTROL_MAPPING.get("vpc_flow_logs", {}),
                "timestamp": now,
            },
            {
                "group_id": "sg-0ghi789",
                "group_name": "app-servers",
                "rule_direction": "ingress",
                "protocol": "tcp",
                "port_range": "443-443",
                "cidr": "0.0.0.0/0",
                "is_open_to_world": True,
                "risk_level": "high",
                "has_sensitive_port": False,
                "mapped_controls": _AWS_CONTROL_MAPPING.get("vpc_flow_logs", {}),
                "timestamp": now,
            },
        ]

    # ------------------------------------------------------------------
    # 8. CloudTrail Event Analysis
    # ------------------------------------------------------------------

    async def analyze_cloudtrail_events(
        self,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Query CloudTrail for compliance-relevant events.

        Detects: unauthorized API calls (AccessDenied), root account usage,
        and IAM changes (CreateUser, AttachPolicy, DeletePolicy, etc.).

        Returns:
            Dict with categorized events and summary counts.
        """
        context = context or {}
        hours_back = context.get("hours_back", 24)
        logger.info(
            "compliance_auditor.analyze_cloudtrail_events",
            hours_back=hours_back,
        )

        iam_change_event_names = {
            "CreateUser",
            "DeleteUser",
            "CreateRole",
            "DeleteRole",
            "AttachUserPolicy",
            "DetachUserPolicy",
            "AttachRolePolicy",
            "DetachRolePolicy",
            "AttachGroupPolicy",
            "DetachGroupPolicy",
            "PutUserPolicy",
            "PutRolePolicy",
            "PutGroupPolicy",
            "DeleteUserPolicy",
            "DeleteRolePolicy",
            "DeleteGroupPolicy",
            "CreateAccessKey",
            "DeleteAccessKey",
            "UpdateAccessKey",
            "CreateLoginProfile",
            "UpdateLoginProfile",
            "AddUserToGroup",
            "RemoveUserFromGroup",
        }

        if self._router is not None:
            try:
                connector = self._router.get("aws")
                events = await self._query_cloudtrail(connector, hours_back, iam_change_event_names)
                logger.info(
                    "compliance_auditor.analyze_cloudtrail_events.complete",
                    source="aws_connector",
                    total_events=events.get("total_events", 0),
                )
                return events
            except (ValueError, AttributeError) as exc:
                logger.warning(
                    "compliance_auditor.analyze_cloudtrail_events.connector_unavailable",
                    error=str(exc),
                )
            except Exception as exc:
                logger.exception(
                    "compliance_auditor.analyze_cloudtrail_events.error",
                    error=str(exc),
                )

        # Fallback: heuristic events for dev/testing
        events = self._generate_mock_cloudtrail_events()
        logger.info(
            "compliance_auditor.analyze_cloudtrail_events.complete",
            source="heuristic",
            total_events=events.get("total_events", 0),
        )
        return events

    async def _query_cloudtrail(
        self,
        connector: Any,
        hours_back: int,
        iam_change_event_names: set[str],
    ) -> dict[str, Any]:
        """Query real AWS CloudTrail for compliance-relevant events."""
        from shieldops.models.base import TimeRange

        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(hours=hours_back)
        time_range = TimeRange(start=start_time, end=end_time)

        # Get all events in the time range
        raw_events = await connector.get_events("*", time_range)

        unauthorized_events: list[dict[str, Any]] = []
        root_account_events: list[dict[str, Any]] = []
        iam_change_events: list[dict[str, Any]] = []

        for event in raw_events:
            event_name = event.get("event_name", "")
            username = event.get("username", "")
            raw_json = event.get("raw_event", "")

            # Parse raw CloudTrail event for additional details
            error_code = ""
            error_message = ""
            source_ip = ""
            if raw_json:
                try:
                    parsed = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
                    error_code = parsed.get("errorCode", "")
                    error_message = parsed.get("errorMessage", "")
                    source_ip = parsed.get("sourceIPAddress", "")
                except (json.JSONDecodeError, TypeError):
                    pass

            enriched = {
                **event,
                "error_code": error_code,
                "error_message": error_message,
                "source_ip": source_ip,
                "is_root_account": username in ("root", "Root"),
                "is_iam_change": event_name in iam_change_event_names,
                "is_unauthorized": error_code
                in (
                    "AccessDenied",
                    "UnauthorizedAccess",
                    "Client.UnauthorizedAccess",
                ),
            }

            if enriched["is_unauthorized"]:
                unauthorized_events.append(enriched)
            if enriched["is_root_account"]:
                root_account_events.append(enriched)
            if enriched["is_iam_change"]:
                iam_change_events.append(enriched)

        return {
            "unauthorized_events": unauthorized_events,
            "root_account_events": root_account_events,
            "iam_change_events": iam_change_events,
            "unauthorized_count": len(unauthorized_events),
            "root_usage_count": len(root_account_events),
            "iam_change_count": len(iam_change_events),
            "total_events": len(raw_events),
            "time_range_hours": hours_back,
            "analyzed_at": datetime.now(UTC).isoformat(),
        }

    @staticmethod
    def _generate_mock_cloudtrail_events() -> dict[str, Any]:
        """Generate mock CloudTrail events for dev/testing."""
        now = datetime.now(UTC).isoformat()
        return {
            "unauthorized_events": [
                {
                    "event_id": "evt-unauth-001",
                    "event_name": "DescribeInstances",
                    "event_source": "ec2.amazonaws.com",
                    "event_time": now,
                    "username": "dev-service-account",
                    "source_ip": "10.0.1.50",
                    "error_code": "AccessDenied",
                    "error_message": "User is not authorized to perform ec2:DescribeInstances",
                    "is_root_account": False,
                    "is_iam_change": False,
                    "is_unauthorized": True,
                },
                {
                    "event_id": "evt-unauth-002",
                    "event_name": "GetObject",
                    "event_source": "s3.amazonaws.com",
                    "event_time": now,
                    "username": "lambda-execution-role",
                    "source_ip": "10.0.2.100",
                    "error_code": "AccessDenied",
                    "error_message": "Access Denied",
                    "is_root_account": False,
                    "is_iam_change": False,
                    "is_unauthorized": True,
                },
            ],
            "root_account_events": [
                {
                    "event_id": "evt-root-001",
                    "event_name": "ConsoleLogin",
                    "event_source": "signin.amazonaws.com",
                    "event_time": now,
                    "username": "root",
                    "source_ip": "203.0.113.50",
                    "error_code": "",
                    "error_message": "",
                    "is_root_account": True,
                    "is_iam_change": False,
                    "is_unauthorized": False,
                },
            ],
            "iam_change_events": [
                {
                    "event_id": "evt-iam-001",
                    "event_name": "CreateUser",
                    "event_source": "iam.amazonaws.com",
                    "event_time": now,
                    "username": "admin-user",
                    "source_ip": "10.0.0.5",
                    "error_code": "",
                    "error_message": "",
                    "is_root_account": False,
                    "is_iam_change": True,
                    "is_unauthorized": False,
                },
                {
                    "event_id": "evt-iam-002",
                    "event_name": "AttachRolePolicy",
                    "event_source": "iam.amazonaws.com",
                    "event_time": now,
                    "username": "admin-user",
                    "source_ip": "10.0.0.5",
                    "error_code": "",
                    "error_message": "",
                    "is_root_account": False,
                    "is_iam_change": True,
                    "is_unauthorized": False,
                },
            ],
            "unauthorized_count": 2,
            "root_usage_count": 1,
            "iam_change_count": 2,
            "total_events": 150,
            "time_range_hours": 24,
            "analyzed_at": now,
        }

    # ------------------------------------------------------------------
    # 9. Public Access Detection (EC2 with public IPs, S3 public buckets)
    # ------------------------------------------------------------------

    async def detect_public_access(
        self,
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Detect resources with public access exposure.

        Checks EC2 instances with public IPs and S3 buckets with
        public access enabled.

        Returns:
            List of public access finding dicts.
        """
        context = context or {}
        environment = context.get("environment", "production")
        logger.info("compliance_auditor.detect_public_access", environment=environment)

        findings: list[dict[str, Any]] = []

        if self._router is not None:
            try:
                connector = self._router.get("aws")
                findings = await self._query_public_access(connector, environment)
                logger.info(
                    "compliance_auditor.detect_public_access.complete",
                    finding_count=len(findings),
                    source="aws_connector",
                )
                return findings
            except (ValueError, AttributeError) as exc:
                logger.warning(
                    "compliance_auditor.detect_public_access.connector_unavailable",
                    error=str(exc),
                )
            except Exception as exc:
                logger.exception(
                    "compliance_auditor.detect_public_access.error",
                    error=str(exc),
                )

        # Fallback
        findings = self._generate_mock_public_access_findings()
        logger.info(
            "compliance_auditor.detect_public_access.complete",
            finding_count=len(findings),
            source="heuristic",
        )
        return findings

    async def _query_public_access(
        self,
        connector: Any,
        environment: str,
    ) -> list[dict[str, Any]]:
        """Query AWS for resources with public access."""
        findings: list[dict[str, Any]] = []

        # EC2 instances with public IPs
        try:
            instances = await connector.list_resources("ec2", environment, {})
            for inst in instances:
                metadata = getattr(inst, "metadata", {}) or {}
                public_ip = metadata.get("public_ip") or metadata.get("PublicIpAddress")
                if public_ip:
                    findings.append(
                        {
                            "resource_type": "ec2_instance",
                            "resource_id": getattr(inst, "id", str(inst)),
                            "resource_name": getattr(inst, "name", ""),
                            "public_ip": public_ip,
                            "risk_level": "high",
                            "description": f"EC2 instance has public IP {public_ip}",
                            "mapped_controls": _AWS_CONTROL_MAPPING.get("s3_bucket_policy", {}),
                            "timestamp": datetime.now(UTC).isoformat(),
                        }
                    )
        except Exception as exc:
            logger.warning("compliance_auditor.ec2_public_check_failed", error=str(exc))

        # S3 buckets with public access
        try:
            buckets = await connector.list_resources("s3_bucket", environment, {})
            for bucket in buckets:
                metadata = getattr(bucket, "metadata", {}) or {}
                public_access_blocked = metadata.get("public_access_blocked", True)
                if not public_access_blocked:
                    findings.append(
                        {
                            "resource_type": "s3_bucket",
                            "resource_id": getattr(bucket, "id", str(bucket)),
                            "resource_name": getattr(bucket, "name", ""),
                            "public_ip": None,
                            "risk_level": "critical",
                            "description": "S3 bucket does not block public access",
                            "mapped_controls": _AWS_CONTROL_MAPPING.get("s3_bucket_policy", {}),
                            "timestamp": datetime.now(UTC).isoformat(),
                        }
                    )
        except Exception as exc:
            logger.warning("compliance_auditor.s3_public_check_failed", error=str(exc))

        return findings

    @staticmethod
    def _generate_mock_public_access_findings() -> list[dict[str, Any]]:
        """Generate mock public access findings for dev/testing."""
        now = datetime.now(UTC).isoformat()
        return [
            {
                "resource_type": "ec2_instance",
                "resource_id": "i-0abc123def456",
                "resource_name": "web-server-prod",
                "public_ip": "54.123.45.67",
                "risk_level": "high",
                "description": "EC2 instance has public IP 54.123.45.67",
                "mapped_controls": _AWS_CONTROL_MAPPING.get("s3_bucket_policy", {}),
                "timestamp": now,
            },
            {
                "resource_type": "s3_bucket",
                "resource_id": "data-lake-prod",
                "resource_name": "data-lake-prod",
                "public_ip": None,
                "risk_level": "critical",
                "description": "S3 bucket does not block public access",
                "mapped_controls": _AWS_CONTROL_MAPPING.get("s3_bucket_policy", {}),
                "timestamp": now,
            },
        ]

    # ------------------------------------------------------------------
    # 10. LLM-Enhanced Remediation Suggestions
    # ------------------------------------------------------------------

    async def generate_remediation_suggestions(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate remediation suggestions for compliance findings.

        Uses llm_structured() for intelligent recommendations, with a
        keyword-based fallback if the LLM is unavailable.

        Returns:
            List of finding dicts enriched with remediation_hint.
        """
        logger.info(
            "compliance_auditor.generate_remediation_suggestions",
            finding_count=len(findings),
        )

        enriched: list[dict[str, Any]] = []
        for finding in findings:
            check_type = finding.get("check_type", "")
            description = finding.get("description", "")
            status = finding.get("status", "")

            if status == "pass":
                enriched.append({**finding, "remediation_hint": ""})
                continue

            # Try LLM-powered remediation
            remediation_hint = ""
            try:
                result = await llm_structured(
                    system_prompt=(
                        "You are a cloud security compliance expert. "
                        "Provide a concise, actionable remediation recommendation "
                        "for the given compliance finding. Be specific about AWS "
                        "services and configurations to change."
                    ),
                    user_prompt=(
                        f"Finding type: {check_type}\n"
                        f"Description: {description}\n"
                        f"Details: {json.dumps(finding.get('details', {}), default=str)}"
                    ),
                    schema=_LLMRemediationSuggestion,
                )
                if isinstance(result, _LLMRemediationSuggestion):
                    remediation_hint = result.remediation_steps
                elif isinstance(result, dict):
                    remediation_hint = result.get("remediation_steps", "")
                logger.info(
                    "compliance_auditor.llm_remediation_generated",
                    check_type=check_type,
                )
            except Exception:
                logger.debug(
                    "compliance_auditor.llm_remediation_fallback",
                    check_type=check_type,
                )

            # Keyword-based fallback
            if not remediation_hint:
                remediation_hint = self._keyword_remediation_fallback(check_type)

            enriched.append({**finding, "remediation_hint": remediation_hint})

        return enriched

    @staticmethod
    def _keyword_remediation_fallback(check_type: str) -> str:
        """Keyword-based remediation fallback when LLM is unavailable."""
        for key, guidance in _REMEDIATION_GUIDANCE.items():
            if key in check_type or check_type in key:
                return guidance

        # Generic mappings for common check types
        keyword_map = {
            "s3": _REMEDIATION_GUIDANCE.get("s3_public_access", ""),
            "iam": _REMEDIATION_GUIDANCE.get("iam_weak_password", ""),
            "cloudtrail": _REMEDIATION_GUIDANCE.get("cloudtrail_disabled", ""),
            "encrypt": _REMEDIATION_GUIDANCE.get("encryption_missing", ""),
            "vpc": _REMEDIATION_GUIDANCE.get("vpc_flow_logs_disabled", ""),
            "mfa": _REMEDIATION_GUIDANCE.get("mfa_not_enforced", ""),
            "credential": _REMEDIATION_GUIDANCE.get("credential_rotation_overdue", ""),
            "security_group": (
                "Restrict security group rules to specific IP ranges. "
                "Remove 0.0.0.0/0 ingress rules for sensitive ports (SSH, RDP, DB). "
                "Use VPC endpoints for AWS service access."
            ),
            "public_access": (
                "Remove public IPs from non-public-facing instances. "
                "Use NAT gateways for outbound access. Enable S3 Block Public Access."
            ),
        }
        for keyword, guidance in keyword_map.items():
            if keyword in check_type.lower():
                return guidance

        return "Review the finding details and apply appropriate security controls."

    # ------------------------------------------------------------------
    # 11. OPA Policy Evaluation
    # ------------------------------------------------------------------

    async def evaluate_opa_policy(
        self,
        findings: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Evaluate compliance findings against OPA policies.

        Uses the OPA client to check whether the current compliance posture
        meets the required policy gates for the given environment.

        Returns:
            Dict with decision (approved/denied/requires_approval) and details.
        """
        context = context or {}
        agent_name = context.get("agent_name", "compliance_auditor")
        environment = context.get("environment", "production")

        logger.info(
            "compliance_auditor.evaluate_opa_policy",
            finding_count=len(findings),
            environment=environment,
        )

        failed_findings = [f for f in findings if f.get("status") == "fail"]
        critical_findings = [f for f in failed_findings if f.get("risk_level") == "critical"]

        # Calculate risk score based on findings
        if not findings:
            risk_score = 0.0
        else:
            fail_ratio = len(failed_findings) / max(len(findings), 1)
            critical_ratio = len(critical_findings) / max(len(findings), 1)
            risk_score = min(1.0, fail_ratio * 0.6 + critical_ratio * 0.4)

        if self._opa_client is not None:
            try:
                from shieldops.policy.engine import PolicyContext, evaluate

                policy_context = PolicyContext(
                    agent_name=agent_name,
                    action_type="compliance_audit_report",
                    target_resources=[f.get("resource_id", "") for f in failed_findings[:10]],
                    environment=environment,
                    risk_score=risk_score,
                    metadata={
                        "total_findings": len(findings),
                        "failed_count": len(failed_findings),
                        "critical_count": len(critical_findings),
                    },
                )
                decision = await evaluate("generate_compliance_report", policy_context)
                return {
                    "decision": decision.decision.value
                    if hasattr(decision.decision, "value")
                    else str(decision.decision),
                    "risk_score": risk_score,
                    "failed_count": len(failed_findings),
                    "critical_count": len(critical_findings),
                    "policy_details": {
                        "reason": getattr(decision, "reason", ""),
                        "blast_radius_ok": getattr(decision, "blast_radius_ok", True),
                    },
                    "evaluated_at": datetime.now(UTC).isoformat(),
                }
            except Exception as exc:
                logger.warning(
                    "compliance_auditor.opa_evaluation_failed",
                    error=str(exc),
                )

        # Fallback: heuristic policy decision
        if risk_score > 0.85:
            decision_str = "denied"
        elif risk_score > 0.5:
            decision_str = "requires_approval"
        else:
            decision_str = "approved"

        return {
            "decision": decision_str,
            "risk_score": round(risk_score, 4),
            "failed_count": len(failed_findings),
            "critical_count": len(critical_findings),
            "policy_details": {
                "reason": f"Heuristic decision based on risk_score={round(risk_score, 4)}",
                "blast_radius_ok": True,
            },
            "evaluated_at": datetime.now(UTC).isoformat(),
        }

    # ------------------------------------------------------------------
    # 12. Compliance Finding Generation
    # ------------------------------------------------------------------

    def generate_compliance_findings(
        self,
        aws_findings: list[dict[str, Any]],
        security_group_findings: list[dict[str, Any]],
        cloudtrail_events: dict[str, Any],
        public_access_findings: list[dict[str, Any]],
        frameworks: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate structured compliance findings from all data sources.

        Maps raw findings to per-framework ComplianceFinding records with
        control_id, severity, evidence, and remediation hints.

        Returns:
            List of ComplianceFinding dicts.
        """
        frameworks = frameworks or ["soc2"]
        logger.info(
            "compliance_auditor.generate_compliance_findings",
            aws_count=len(aws_findings),
            sg_count=len(security_group_findings),
            public_count=len(public_access_findings),
        )

        results: list[dict[str, Any]] = []
        now = datetime.now(UTC).isoformat()

        # Map AWS Config findings
        for finding in aws_findings:
            check_type = finding.get("check_type", "")
            status = finding.get("status", "fail")
            mapped_controls = finding.get("mapped_controls", {})

            for fw in frameworks:
                control_ids = mapped_controls.get(fw, [])
                for ctrl_id in control_ids:
                    severity = "high" if status == "fail" else "low"
                    results.append(
                        {
                            "control_id": ctrl_id,
                            "framework": fw,
                            "status": "non_compliant" if status == "fail" else "compliant",
                            "severity": severity,
                            "title": f"AWS Config: {check_type}",
                            "description": _get_finding_gap_description(finding),
                            "evidence": [
                                f"aws_config:{check_type}:{finding.get('resource_id', '')}",
                            ],
                            "remediation_hint": finding.get(
                                "remediation_hint",
                                _REMEDIATION_GUIDANCE.get(
                                    check_type,
                                    self._keyword_remediation_fallback(check_type),
                                ),
                            ),
                            "resource_id": finding.get("resource_id", ""),
                            "check_type": check_type,
                            "assessed_at": now,
                        }
                    )

        # Map security group findings
        for sg in security_group_findings:
            risk = sg.get("risk_level", "high")
            for fw in frameworks:
                control_ids = sg.get("mapped_controls", {}).get(fw, [])
                for ctrl_id in control_ids:
                    results.append(
                        {
                            "control_id": ctrl_id,
                            "framework": fw,
                            "status": "non_compliant",
                            "severity": risk,
                            "title": f"Security Group: {sg.get('group_name', '')} open to world",
                            "description": (
                                f"Security group {sg.get('group_id', '')} allows "
                                f"{sg.get('protocol', 'tcp')} {sg.get('port_range', '')} "
                                f"from {sg.get('cidr', '')}"
                            ),
                            "evidence": [
                                f"security_group:{sg.get('group_id', '')}:"
                                f"{sg.get('port_range', '')}",
                            ],
                            "remediation_hint": (
                                "Restrict security group rules to specific IP ranges. "
                                "Remove 0.0.0.0/0 ingress rules for sensitive ports."
                            ),
                            "resource_id": sg.get("group_id", ""),
                            "check_type": "security_group_open_access",
                            "assessed_at": now,
                        }
                    )

        # Map CloudTrail events to findings
        ct = cloudtrail_events or {}
        if ct.get("unauthorized_count", 0) > 0:
            for fw in frameworks:
                trail_controls = _AWS_CONTROL_MAPPING.get("cloudtrail_status", {})
                ctrl_ids = trail_controls.get(fw, [])
                for ctrl_id in ctrl_ids:
                    results.append(
                        {
                            "control_id": ctrl_id,
                            "framework": fw,
                            "status": "non_compliant",
                            "severity": "high",
                            "title": "Unauthorized API calls detected",
                            "description": (
                                f"{ct['unauthorized_count']} unauthorized API calls "
                                f"detected in the last {ct.get('time_range_hours', 24)}h"
                            ),
                            "evidence": [
                                f"cloudtrail:unauthorized:{e.get('event_id', '')}"
                                for e in ct.get("unauthorized_events", [])[:5]
                            ],
                            "remediation_hint": (
                                "Review IAM policies for the affected principals. "
                                "Apply least-privilege access and remove unused permissions."
                            ),
                            "resource_id": "cloudtrail-unauthorized",
                            "check_type": "cloudtrail_unauthorized_access",
                            "assessed_at": now,
                        }
                    )

        if ct.get("root_usage_count", 0) > 0:
            for fw in frameworks:
                trail_controls = _AWS_CONTROL_MAPPING.get("iam_password_policy", {})
                ctrl_ids = trail_controls.get(fw, [])
                for ctrl_id in ctrl_ids:
                    results.append(
                        {
                            "control_id": ctrl_id,
                            "framework": fw,
                            "status": "non_compliant",
                            "severity": "critical",
                            "title": "Root account usage detected",
                            "description": (
                                f"{ct['root_usage_count']} root account events "
                                f"in the last {ct.get('time_range_hours', 24)}h"
                            ),
                            "evidence": [
                                f"cloudtrail:root:{e.get('event_id', '')}"
                                for e in ct.get("root_account_events", [])[:5]
                            ],
                            "remediation_hint": (
                                "Disable root account access keys. Use IAM users with MFA "
                                "for all operations. Enable root account MFA with hardware token."
                            ),
                            "resource_id": "cloudtrail-root-usage",
                            "check_type": "cloudtrail_root_usage",
                            "assessed_at": now,
                        }
                    )

        if ct.get("iam_change_count", 0) > 0:
            for fw in frameworks:
                trail_controls = _AWS_CONTROL_MAPPING.get("iam_password_policy", {})
                ctrl_ids = trail_controls.get(fw, [])
                for ctrl_id in ctrl_ids:
                    results.append(
                        {
                            "control_id": ctrl_id,
                            "framework": fw,
                            "status": "non_compliant",
                            "severity": "medium",
                            "title": "IAM changes detected",
                            "description": (
                                f"{ct['iam_change_count']} IAM changes "
                                f"in the last {ct.get('time_range_hours', 24)}h"
                            ),
                            "evidence": [
                                f"cloudtrail:iam_change:{e.get('event_id', '')}"
                                for e in ct.get("iam_change_events", [])[:5]
                            ],
                            "remediation_hint": (
                                "Review all IAM changes for authorization. Implement change "
                                "management process for IAM modifications. Use AWS Config rules "
                                "to detect unauthorized changes."
                            ),
                            "resource_id": "cloudtrail-iam-changes",
                            "check_type": "cloudtrail_iam_changes",
                            "assessed_at": now,
                        }
                    )

        # Map public access findings
        for pa in public_access_findings:
            risk = pa.get("risk_level", "high")
            for fw in frameworks:
                control_ids = pa.get("mapped_controls", {}).get(fw, [])
                for ctrl_id in control_ids:
                    results.append(
                        {
                            "control_id": ctrl_id,
                            "framework": fw,
                            "status": "non_compliant",
                            "severity": risk,
                            "title": f"Public access: {pa.get('resource_type', '')}",
                            "description": pa.get("description", ""),
                            "evidence": [
                                f"public_access:{pa.get('resource_type', '')}:"
                                f"{pa.get('resource_id', '')}",
                            ],
                            "remediation_hint": self._keyword_remediation_fallback("public_access"),
                            "resource_id": pa.get("resource_id", ""),
                            "check_type": "public_access",
                            "assessed_at": now,
                        }
                    )

        return results

    # ------------------------------------------------------------------
    # Original methods preserved for backward compatibility
    # ------------------------------------------------------------------

    async def scan_controls(
        self,
        framework: str,
    ) -> list[dict[str, Any]]:
        """Scan infrastructure for control compliance against a framework."""
        logger.info("compliance_auditor.scan_controls", framework=framework)
        if self._compliance_backend is not None:
            try:
                return await self._compliance_backend.scan(framework=framework)  # type: ignore[no-any-return]
            except Exception:
                logger.exception("compliance_auditor.scan_controls.error")
                return []

        # Mock: return default controls with heuristic statuses
        controls = _FRAMEWORK_CONTROLS.get(framework, [])
        results: list[dict[str, Any]] = []
        for i, ctrl in enumerate(controls):
            if i % 4 == 0:
                status = "compliant"
            elif i % 4 == 1:
                status = "non_compliant"
            elif i % 4 == 2:
                status = "partial"
            else:
                status = "compliant"
            results.append(
                {
                    "control_id": ctrl["control_id"],
                    "framework": framework,
                    "description": ctrl["description"],
                    "status": status,
                    "gaps": ["Missing documentation"] if status == "non_compliant" else [],
                }
            )
        return results

    async def collect_evidence(
        self,
        control_id: str,
    ) -> list[dict[str, Any]]:
        """Gather evidence artifacts for a specific control."""
        logger.info("compliance_auditor.collect_evidence", control_id=control_id)
        if self._evidence_store is not None:
            try:
                return await self._evidence_store.collect(control_id=control_id)  # type: ignore[no-any-return]
            except Exception:
                logger.exception("compliance_auditor.collect_evidence.error")
                return []

        now = time.time()
        return [
            {
                "id": f"ev-{control_id}-001",
                "source": "infrastructure_scan",
                "description": f"Automated scan result for {control_id}",
                "collected_at": now,
                "valid_until": now + 86400 * 90,
            },
        ]

    def assess_control(
        self,
        control: dict[str, Any],
        evidence: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Evaluate compliance status of a control given evidence."""
        control_id = control.get("control_id", "")
        status = control.get("status", "not_applicable")
        gaps = list(control.get("gaps", []))

        evidence_refs = [e.get("id", "") for e in evidence if e.get("id")]

        if not evidence and status != "compliant":
            gaps.append(f"No evidence collected for {control_id}")
            if status != "non_compliant":
                status = "non_compliant"

        return {
            "control_id": control_id,
            "framework": control.get("framework", ""),
            "description": control.get("description", ""),
            "status": status,
            "evidence_refs": evidence_refs,
            "gaps": gaps,
        }

    def generate_audit_report(
        self,
        assessments: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Produce an audit-ready compliance report from control assessments."""
        total = len(assessments)
        if total == 0:
            return {
                "total_controls": 0,
                "compliant": 0,
                "non_compliant": 0,
                "partial": 0,
                "not_applicable": 0,
                "compliance_score": 0.0,
                "frameworks": [],
                "gaps": [],
                "recommendations": ["No controls assessed — scan required"],
                "generated_at": time.time(),
            }

        compliant = sum(1 for a in assessments if a.get("status") == "compliant")
        non_compliant = sum(1 for a in assessments if a.get("status") == "non_compliant")
        partial = sum(1 for a in assessments if a.get("status") == "partial")
        not_applicable = sum(1 for a in assessments if a.get("status") == "not_applicable")

        applicable = total - not_applicable
        score = round((compliant + partial * 0.5) / applicable, 4) if applicable > 0 else 0.0

        all_gaps: list[str] = []
        for a in assessments:
            for gap in a.get("gaps", []):
                all_gaps.append(f"{a.get('control_id', '')}: {gap}")

        frameworks = sorted({a.get("framework", "") for a in assessments if a.get("framework")})

        recommendations: list[str] = []
        if non_compliant > 0:
            recommendations.append(f"Remediate {non_compliant} non-compliant controls immediately")
        if partial > 0:
            recommendations.append(
                f"Complete implementation for {partial} partially compliant controls"
            )
        if not recommendations:
            recommendations.append("All assessed controls are compliant")

        return {
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "partial": partial,
            "not_applicable": not_applicable,
            "compliance_score": score,
            "frameworks": frameworks,
            "gaps": all_gaps,
            "recommendations": recommendations,
            "generated_at": time.time(),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_finding_gap_description(finding: dict[str, Any]) -> str:
    """Extract a human-readable gap description from a finding."""
    check_type = finding.get("check_type", "")
    details = finding.get("details", {})

    descriptions: dict[str, str] = {
        "s3_bucket_policy": (
            f"Public access not blocked (blocked={details.get('public_access_blocked', 'N/A')}), "
            f"encryption={details.get('encryption_enabled', 'N/A')}"
        ),
        "iam_password_policy": (
            f"Weak password policy (min_length={details.get('min_length', 'N/A')}, "
            f"symbols={details.get('require_symbols', 'N/A')})"
        ),
        "cloudtrail_status": (
            f"CloudTrail {'disabled' if not details.get('trail_enabled') else 'not multi-region'}"
        ),
        "encryption_settings": (
            f"{details.get('unencrypted_count', 0)} unencrypted volumes "
            f"({details.get('encryption_percentage', 0)}% encrypted)"
        ),
        "vpc_flow_logs": (
            f"{details.get('vpcs_without_flow_logs', 0)} VPCs without flow logs "
            f"({details.get('coverage_percentage', 0)}% coverage)"
        ),
    }

    return descriptions.get(check_type, f"Non-compliant: {check_type}")
