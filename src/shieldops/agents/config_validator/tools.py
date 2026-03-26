"""Tool functions for the Config Validator Agent.

Provides golden baseline definitions and functions to collect, compare,
and remediate infrastructure configurations across multiple sources.
"""

import hashlib
import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.config_validator.models import (
    ConfigDrift,
    ConfigSnapshot,
    ConfigSource,
    DriftSeverity,
    ImpactAssessment,
    RemediationAction,
)

logger = structlog.get_logger()


class ConfigValidatorToolkit:
    """Collection of tools available to the config validator agent.

    Holds golden baseline definitions and provides async functions
    to collect live configs, compare them, and apply remediations.
    """

    GOLDEN_BASELINES: dict[str, dict[str, Any]] = {
        "kubernetes/deployment": {
            "spec.replicas": "3",
            "spec.strategy.type": "RollingUpdate",
            "spec.template.spec.securityContext.runAsNonRoot": "true",
            "spec.template.spec.containers[0].resources.limits.memory": "512Mi",
            "spec.template.spec.containers[0].resources.limits.cpu": "500m",
            "spec.template.spec.containers[0].readinessProbe": "defined",
            "spec.template.spec.containers[0].livenessProbe": "defined",
        },
        "kubernetes/service": {
            "spec.type": "ClusterIP",
            "metadata.labels.app": "required",
        },
        "terraform/aws_s3_bucket": {
            "versioning.enabled": "true",
            "server_side_encryption_configuration.rule"
            ".apply_server_side_encryption_by_default.sse_algorithm": "aws:kms",
            "logging.target_bucket": "defined",
            "acl": "private",
        },
        "terraform/aws_rds_instance": {
            "storage_encrypted": "true",
            "multi_az": "true",
            "backup_retention_period": "7",
            "deletion_protection": "true",
        },
        "helm/values": {
            "replicaCount": "3",
            "resources.limits.memory": "512Mi",
            "resources.limits.cpu": "500m",
            "podSecurityContext.runAsNonRoot": "true",
            "ingress.tls.enabled": "true",
        },
        "docker/dockerfile": {
            "base_image_pinned": "true",
            "user_non_root": "true",
            "healthcheck": "defined",
            "no_secrets_in_env": "true",
        },
        "application/env": {
            "LOG_LEVEL": "info",
            "TLS_ENABLED": "true",
            "CORS_ORIGINS": "restricted",
            "DEBUG": "false",
        },
        "cloud_iam/policy": {
            "mfa_enforced": "true",
            "max_session_duration": "3600",
            "password_policy.min_length": "14",
            "root_account_mfa": "true",
            "unused_credentials_disabled": "true",
        },
    }

    def __init__(self, tenant_id: str = "") -> None:
        self._tenant_id = tenant_id

    async def collect_configs(self, tenant_id: str) -> list[ConfigSnapshot]:
        """Collect current configuration snapshots from all sources.

        In production this would query Kubernetes API, Terraform state,
        Helm releases, Docker registries, and cloud IAM APIs.
        """
        logger.info("collecting_configs", tenant_id=tenant_id)
        now = time.time()
        snapshots: list[ConfigSnapshot] = []

        source_resources: dict[ConfigSource, list[str]] = {
            ConfigSource.KUBERNETES: [
                "deployment/api-server",
                "deployment/worker",
                "service/api-gateway",
            ],
            ConfigSource.TERRAFORM: [
                "aws_s3_bucket/data-lake",
                "aws_rds_instance/primary-db",
            ],
            ConfigSource.HELM: ["release/shieldops"],
            ConfigSource.DOCKER: ["image/shieldops-api"],
            ConfigSource.APPLICATION: ["config/shieldops-api"],
            ConfigSource.CLOUD_IAM: ["policy/admin-role"],
        }

        for source, resources in source_resources.items():
            for resource_name in resources:
                config_hash = hashlib.sha256(
                    f"{tenant_id}:{source}:{resource_name}:{now}".encode()
                ).hexdigest()[:16]
                snapshots.append(
                    ConfigSnapshot(
                        id=f"snap-{uuid4().hex[:12]}",
                        source=source,
                        resource_name=resource_name,
                        config_hash=config_hash,
                        last_validated=now,
                        compliant=True,  # Will be updated by comparison
                        service=resource_name.split("/")[-1],
                    )
                )

        logger.info("configs_collected", count=len(snapshots), tenant_id=tenant_id)
        return snapshots

    async def compare_baselines(
        self,
        snapshots: list[ConfigSnapshot],
    ) -> list[ConfigSnapshot]:
        """Compare collected snapshots against golden baselines.

        Returns updated snapshots with compliant flag set. In production
        this would fetch live values from each connector and diff them.
        """
        logger.info("comparing_baselines", snapshot_count=len(snapshots))

        for snapshot in snapshots:
            baseline_key = f"{snapshot.source}/{snapshot.resource_name.split('/')[0]}"
            baseline = self.GOLDEN_BASELINES.get(baseline_key)
            if baseline is None:
                # No baseline defined — mark as compliant by default
                snapshot.compliant = True
            else:
                # Simulate comparison — in production, compare actual field values
                snapshot.compliant = snapshot.config_hash[-1] not in ("a", "b", "c")

        return snapshots

    async def detect_drift(
        self,
        snapshots: list[ConfigSnapshot],
    ) -> list[ConfigDrift]:
        """Detect configuration drift for non-compliant snapshots.

        Returns structured drift records with field paths and expected
        vs actual values. In production this would perform deep diffs.
        """
        drifts: list[ConfigDrift] = []
        now = time.time()

        severity_map: dict[ConfigSource, DriftSeverity] = {
            ConfigSource.CLOUD_IAM: DriftSeverity.CRITICAL,
            ConfigSource.KUBERNETES: DriftSeverity.HIGH,
            ConfigSource.TERRAFORM: DriftSeverity.HIGH,
            ConfigSource.DOCKER: DriftSeverity.MEDIUM,
            ConfigSource.HELM: DriftSeverity.MEDIUM,
            ConfigSource.APPLICATION: DriftSeverity.LOW,
        }

        for snapshot in snapshots:
            if snapshot.compliant:
                continue

            baseline_key = f"{snapshot.source}/{snapshot.resource_name.split('/')[0]}"
            baseline = self.GOLDEN_BASELINES.get(baseline_key, {})

            # Simulate detecting drifted fields
            for field_path, expected in list(baseline.items())[:2]:
                drifts.append(
                    ConfigDrift(
                        id=f"drift-{uuid4().hex[:12]}",
                        snapshot_id=snapshot.id,
                        source=snapshot.source,
                        field_path=field_path,
                        expected_value=expected,
                        actual_value="<drifted>",
                        severity=severity_map.get(snapshot.source, DriftSeverity.MEDIUM),
                        auto_fixable=snapshot.source
                        in (
                            ConfigSource.KUBERNETES,
                            ConfigSource.HELM,
                            ConfigSource.APPLICATION,
                        ),
                        introduced_at=now - 3600,  # Assume 1hr ago
                    )
                )

        logger.info("drift_detected", drift_count=len(drifts))
        return drifts

    async def assess_impact(
        self,
        drifts: list[ConfigDrift],
        snapshots: list[ConfigSnapshot],
    ) -> list[ImpactAssessment]:
        """Assess the impact of detected configuration drifts.

        Maps drifts to affected services and evaluates security,
        availability, and compliance impact.
        """
        assessments: list[ImpactAssessment] = []
        snapshot_map = {s.id: s for s in snapshots}

        for drift in drifts:
            snapshot = snapshot_map.get(drift.snapshot_id)
            affected = [snapshot.service] if snapshot else ["unknown"]

            security_impact = "none"
            availability_impact = "none"
            compliance_impact = "none"

            if drift.severity == DriftSeverity.CRITICAL:
                security_impact = "high — IAM or encryption controls weakened"
                compliance_impact = "high — may violate SOC 2 / PCI-DSS"
            elif drift.severity == DriftSeverity.HIGH:
                security_impact = "medium — security context or resource limits changed"
                availability_impact = "medium — may affect service stability"
            elif drift.severity == DriftSeverity.MEDIUM:
                availability_impact = "low — non-critical config changed"

            assessments.append(
                ImpactAssessment(
                    id=f"impact-{uuid4().hex[:12]}",
                    drift_id=drift.id,
                    affected_services=affected,
                    security_impact=security_impact,
                    availability_impact=availability_impact,
                    compliance_impact=compliance_impact,
                )
            )

        logger.info("impact_assessed", count=len(assessments))
        return assessments

    async def remediate_drift(
        self,
        drifts: list[ConfigDrift],
    ) -> list[RemediationAction]:
        """Attempt auto-remediation for fixable drifts.

        Only applies fixes for drifts marked as auto_fixable. Returns
        remediation actions with status. In production this would call
        kubectl apply, helm upgrade, terraform apply, etc.
        """
        actions: list[RemediationAction] = []

        for drift in drifts:
            if not drift.auto_fixable:
                actions.append(
                    RemediationAction(
                        id=f"rem-{uuid4().hex[:12]}",
                        drift_id=drift.id,
                        action="manual_review",
                        description=(
                            f"Manual review required for {drift.source}:{drift.field_path}"
                        ),
                        applied=False,
                        success=False,
                        rollback_available=False,
                    )
                )
                continue

            action_type = {
                ConfigSource.KUBERNETES: "kubectl_apply",
                ConfigSource.HELM: "helm_upgrade",
                ConfigSource.APPLICATION: "config_update",
            }.get(drift.source, "manual_review")

            actions.append(
                RemediationAction(
                    id=f"rem-{uuid4().hex[:12]}",
                    drift_id=drift.id,
                    action=action_type,
                    description=(
                        f"Set {drift.field_path} from '{drift.actual_value}' "
                        f"to '{drift.expected_value}' via {action_type}"
                    ),
                    applied=True,
                    success=True,
                    rollback_available=True,
                )
            )

        logger.info(
            "remediation_complete",
            total=len(actions),
            applied=sum(1 for a in actions if a.applied),
        )
        return actions
