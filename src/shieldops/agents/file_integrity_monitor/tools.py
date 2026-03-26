"""Tool functions for the File Integrity Monitor Agent.

Provides baseline scanning, hash-based change detection,
and automated response capabilities for monitored files.
"""

import hashlib
import time
from uuid import uuid4

import structlog

from shieldops.agents.file_integrity_monitor.models import (
    ChangeType,
    FileBaseline,
    FileChange,
    FIMResponse,
    ImpactAssessment,
    ImpactLevel,
)

logger = structlog.get_logger()


class FileIntegrityMonitorToolkit:
    """Tools for file integrity monitoring.

    Provides async functions to scan baselines, detect
    changes via hash comparison, assess impact, and
    execute automated responses (alert, rollback,
    quarantine).
    """

    # Monitored path categories and their default paths
    MONITORED_PATHS: dict[str, list[str]] = {
        "system_config": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/etc/pam.d/common-auth",
            "/etc/hosts",
            "/etc/resolv.conf",
        ],
        "security_config": [
            "/etc/ssl/certs/ca-certificates.crt",
            "/root/.ssh/authorized_keys",
            "/etc/iptables/rules.v4",
            "/etc/audit/auditd.conf",
            "/etc/selinux/config",
        ],
        "ai_model_files": [
            "/opt/models/rag-index/faiss.index",
            "/opt/models/rag-index/metadata.json",
            "/opt/models/embeddings/model.safetensors",
            "/opt/models/fine-tuned/adapter_config.json",
            "/opt/models/fine-tuned/adapter_model.bin",
        ],
        "rag_data": [
            "/opt/rag/vector-store/index.faiss",
            "/opt/rag/vector-store/docstore.json",
            "/opt/rag/documents/corpus.jsonl",
            "/opt/rag/config/retrieval.yaml",
        ],
        "k8s_manifests": [
            "/etc/kubernetes/manifests/kube-apiserver.yaml",
            "/etc/kubernetes/manifests/etcd.yaml",
            "/etc/kubernetes/pki/ca.crt",
            "/etc/kubernetes/admin.conf",
        ],
        "terraform_state": [
            "/opt/terraform/terraform.tfstate",
            "/opt/terraform/terraform.tfstate.backup",
            "/opt/terraform/.terraform.lock.hcl",
        ],
        "application_config": [
            "/opt/shieldops/config/app.yaml",
            "/opt/shieldops/config/agents.yaml",
            "/opt/shieldops/config/opa-policies/",
            "/opt/shieldops/.env",
        ],
        "mcp_config": [
            "/opt/mcp/server-manifest.json",
            "/opt/mcp/tool-permissions.yaml",
            "/opt/mcp/oauth-config.json",
        ],
    }

    # Impact classification by path prefix
    IMPACT_MAP: dict[str, ImpactLevel] = {
        "/etc/passwd": ImpactLevel.CRITICAL_SYSTEM,
        "/etc/shadow": ImpactLevel.CRITICAL_SYSTEM,
        "/etc/sudoers": ImpactLevel.CRITICAL_SYSTEM,
        "/etc/ssh/": ImpactLevel.SECURITY_CONFIG,
        "/etc/ssl/": ImpactLevel.SECURITY_CONFIG,
        "/root/.ssh/": ImpactLevel.SECURITY_CONFIG,
        "/etc/kubernetes/pki/": ImpactLevel.SECURITY_CONFIG,
        "/etc/kubernetes/": ImpactLevel.APPLICATION_CONFIG,
        "/opt/models/": ImpactLevel.CRITICAL_SYSTEM,
        "/opt/rag/": ImpactLevel.CRITICAL_SYSTEM,
        "/opt/mcp/": ImpactLevel.SECURITY_CONFIG,
        "/opt/terraform/": ImpactLevel.SECURITY_CONFIG,
        "/opt/shieldops/": ImpactLevel.APPLICATION_CONFIG,
    }

    def __init__(self, tenant_id: str = "") -> None:
        self._tenant_id = tenant_id

    def _classify_path(self, path: str) -> ImpactLevel:
        """Classify a file path by impact level."""
        for prefix, level in self.IMPACT_MAP.items():
            if path.startswith(prefix):
                return level
        return ImpactLevel.DATA_FILE

    def _category_for_path(self, path: str) -> str:
        """Determine the monitoring category for a path."""
        for category, paths in self.MONITORED_PATHS.items():
            for monitored in paths:
                if path.startswith(monitored.rstrip("/")):
                    return category
        return "unknown"

    async def scan_baselines(
        self,
        tenant_id: str,
        paths: list[str] | None = None,
    ) -> list[FileBaseline]:
        """Scan monitored paths and build baseline hashes.

        In production this would stat/hash real files via
        the Linux connector or K8s exec.
        """
        logger.info(
            "fim_scanning_baselines",
            tenant_id=tenant_id,
        )
        now = time.time()
        baselines: list[FileBaseline] = []

        scan_paths: list[str] = []
        if paths:
            scan_paths = paths
        else:
            for cat_paths in self.MONITORED_PATHS.values():
                scan_paths.extend(cat_paths)

        for file_path in scan_paths:
            file_hash = hashlib.sha256(f"{tenant_id}:{file_path}:baseline".encode()).hexdigest()

            baselines.append(
                FileBaseline(
                    id=f"bl-{uuid4().hex[:12]}",
                    path=file_path,
                    sha256_hash=file_hash,
                    size_bytes=hash(file_path) % 50000 + 100,
                    permissions="0644",
                    owner="root",
                    group="root",
                    last_modified=now - 86400,
                    monitored_category=self._category_for_path(file_path),
                )
            )

        logger.info(
            "fim_baselines_scanned",
            count=len(baselines),
        )
        return baselines

    async def detect_changes(
        self,
        baselines: list[FileBaseline],
    ) -> list[FileChange]:
        """Detect file changes by comparing current state
        against baselines.

        In production this would re-hash files and compare
        against stored baselines. Simulates realistic change
        detection for demonstration.
        """
        changes: list[FileChange] = []
        now = time.time()

        # Simulate changes on subset of files
        change_scenarios: dict[str, tuple[ChangeType, str]] = {
            "/etc/passwd": (
                ChangeType.MODIFIED,
                "New user 'svc-backdoor' appended",
            ),
            "/root/.ssh/authorized_keys": (
                ChangeType.MODIFIED,
                "Unknown SSH public key added",
            ),
            "/opt/models/rag-index/faiss.index": (
                ChangeType.MODIFIED,
                "Vector index rebuilt with altered embeddings",
            ),
            "/opt/mcp/tool-permissions.yaml": (
                ChangeType.MODIFIED,
                "Tool 'execute_command' permission escalated",
            ),
            "/opt/terraform/terraform.tfstate": (
                ChangeType.MODIFIED,
                "State file modified outside terraform apply",
            ),
            "/etc/sudoers": (
                ChangeType.PERMISSIONS_CHANGED,
                "Permissions changed from 0440 to 0666",
            ),
        }

        for baseline in baselines:
            scenario = change_scenarios.get(baseline.path)
            if scenario is None:
                continue

            change_type, diff_summary = scenario

            new_hash = hashlib.sha256(f"{baseline.path}:changed:{now}".encode()).hexdigest()

            old_perms = baseline.permissions
            new_perms = old_perms
            if change_type == ChangeType.PERMISSIONS_CHANGED:
                new_perms = "0666"

            changes.append(
                FileChange(
                    id=f"chg-{uuid4().hex[:12]}",
                    baseline_id=baseline.id,
                    path=baseline.path,
                    change_type=change_type,
                    old_hash=baseline.sha256_hash,
                    new_hash=new_hash,
                    old_permissions=old_perms,
                    new_permissions=new_perms,
                    old_owner=baseline.owner,
                    new_owner=baseline.owner,
                    detected_at=now,
                    diff_summary=diff_summary,
                )
            )

        logger.info(
            "fim_changes_detected",
            count=len(changes),
        )
        return changes

    async def assess_impact(
        self,
        changes: list[FileChange],
        baselines: list[FileBaseline],
    ) -> list[ImpactAssessment]:
        """Assess impact of detected file changes.

        Maps changes to affected services and evaluates
        security and compliance impact.
        """
        assessments: list[ImpactAssessment] = []
        baseline_map = {b.id: b for b in baselines}

        for change in changes:
            baseline = baseline_map.get(change.baseline_id)
            impact = self._classify_path(change.path)

            affected: list[str] = []
            if baseline:
                affected = [baseline.monitored_category]

            security_impact = "none"
            compliance_impact = "none"
            blast_radius = "isolated"
            requires_rollback = False

            if impact == ImpactLevel.CRITICAL_SYSTEM:
                security_impact = "critical — system integrity compromised"
                compliance_impact = "high — SOC 2 CC6.1, PCI-DSS 11.5"
                blast_radius = "cluster-wide"
                requires_rollback = True
            elif impact == ImpactLevel.SECURITY_CONFIG:
                security_impact = "high — security controls modified"
                compliance_impact = "medium — HIPAA 164.312(c)(1)"
                blast_radius = "service-level"
                requires_rollback = True
            elif impact == ImpactLevel.APPLICATION_CONFIG:
                security_impact = "medium — application behavior changed"
                blast_radius = "service-level"

            assessments.append(
                ImpactAssessment(
                    id=f"imp-{uuid4().hex[:12]}",
                    change_id=change.id,
                    affected_services=affected,
                    security_impact=security_impact,
                    compliance_impact=compliance_impact,
                    blast_radius=blast_radius,
                    requires_rollback=requires_rollback,
                )
            )

        logger.info(
            "fim_impact_assessed",
            count=len(assessments),
        )
        return assessments

    async def execute_responses(
        self,
        changes: list[FileChange],
        assessments: list[ImpactAssessment],
    ) -> list[FIMResponse]:
        """Execute automated responses for detected changes.

        Response actions: alert, quarantine, rollback,
        isolate_host, escalate. In production this would
        call connectors for real remediation.
        """
        responses: list[FIMResponse] = []
        assessment_map = {a.change_id: a for a in assessments}

        for change in changes:
            assessment = assessment_map.get(change.id)
            if assessment is None:
                continue

            if assessment.requires_rollback:
                responses.append(
                    FIMResponse(
                        id=f"resp-{uuid4().hex[:12]}",
                        change_id=change.id,
                        action="rollback",
                        description=(
                            f"Restore {change.path} to baseline hash {change.old_hash[:16]}..."
                        ),
                        executed=True,
                        success=True,
                        rollback_available=True,
                    )
                )
                responses.append(
                    FIMResponse(
                        id=f"resp-{uuid4().hex[:12]}",
                        change_id=change.id,
                        action="alert",
                        description=(
                            f"Critical change alert for {change.path}: {change.diff_summary}"
                        ),
                        executed=True,
                        success=True,
                        rollback_available=False,
                    )
                )
            else:
                responses.append(
                    FIMResponse(
                        id=f"resp-{uuid4().hex[:12]}",
                        change_id=change.id,
                        action="alert",
                        description=(f"Change detected on {change.path}: {change.diff_summary}"),
                        executed=True,
                        success=True,
                        rollback_available=False,
                    )
                )

        logger.info(
            "fim_responses_executed",
            count=len(responses),
            rollbacks=sum(1 for r in responses if r.action == "rollback"),
        )
        return responses
