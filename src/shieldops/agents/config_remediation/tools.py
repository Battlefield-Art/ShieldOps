"""Tool functions for the Config Remediation Agent."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.config_remediation.models import (
    ConfigScan,
    FixApplication,
    FixPlan,
    FixStatus,
    FixVerification,
    MisconfigType,
    Misconfiguration,
)

logger = structlog.get_logger()


class ConfigRemediationToolkit:
    """Tools for config scanning and remediation."""

    def __init__(
        self,
        opa_client: Any = None,
        cloud_client: Any = None,
    ) -> None:
        self._opa = opa_client
        self._cloud = cloud_client

    async def scan_configurations(
        self,
        cloud_provider: str,
    ) -> list[ConfigScan]:
        """Scan cloud configurations for misconfigs."""
        # Simulated — production calls cloud APIs
        scans = [
            ConfigScan(
                resource_type="security_group",
                resource_id="sg-abc123",
                cloud_provider=cloud_provider,
                region="us-east-1",
                config_snapshot={"ingress": [{"port": 22, "cidr": "0.0.0.0/0"}]},
            ),
            ConfigScan(
                resource_type="s3_bucket",
                resource_id="data-bucket-prod",
                cloud_provider=cloud_provider,
                region="us-east-1",
                config_snapshot={
                    "public_access": True,
                    "encryption": False,
                },
            ),
            ConfigScan(
                resource_type="iam_policy",
                resource_id="policy-admin-wide",
                cloud_provider=cloud_provider,
                region="global",
                config_snapshot={
                    "effect": "Allow",
                    "action": "*",
                    "resource": "*",
                },
            ),
        ]
        logger.info(
            "configs_scanned",
            count=len(scans),
            provider=cloud_provider,
        )
        return scans

    async def identify_misconfigs(
        self,
        scans: list[ConfigScan],
    ) -> list[Misconfiguration]:
        """Identify misconfigurations from scan results."""
        misconfigs: list[Misconfiguration] = []

        for scan in scans:
            cfg = scan.config_snapshot
            if scan.resource_type == "security_group":
                ingress = cfg.get("ingress", [])
                for rule in ingress:  # type: ignore[union-attr]
                    if isinstance(rule, dict):
                        cidr = rule.get("cidr", "")
                        if cidr == "0.0.0.0/0":
                            misconfigs.append(
                                Misconfiguration(
                                    scan_id=scan.id,
                                    misconfig_type=(MisconfigType.OVERPERMISSIVE_SG),
                                    resource_id=(scan.resource_id),
                                    severity="critical",
                                    description=("SG allows 0.0.0.0/0 ingress"),
                                    current_value=cidr,
                                    expected_value=("10.0.0.0/8"),
                                )
                            )

            if scan.resource_type == "s3_bucket":
                if cfg.get("public_access"):
                    misconfigs.append(
                        Misconfiguration(
                            scan_id=scan.id,
                            misconfig_type=(MisconfigType.PUBLIC_STORAGE),
                            resource_id=scan.resource_id,
                            severity="critical",
                            description=("S3 bucket is publicly accessible"),
                            current_value="public",
                            expected_value="private",
                        )
                    )
                if not cfg.get("encryption"):
                    misconfigs.append(
                        Misconfiguration(
                            scan_id=scan.id,
                            misconfig_type=(MisconfigType.MISSING_ENCRYPTION),
                            resource_id=scan.resource_id,
                            severity="high",
                            description=("S3 bucket lacks encryption"),
                            current_value="none",
                            expected_value="AES-256",
                        )
                    )

            if scan.resource_type == "iam_policy" and cfg.get("action") == "*":
                misconfigs.append(
                    Misconfiguration(
                        scan_id=scan.id,
                        misconfig_type=(MisconfigType.WEAK_IAM),
                        resource_id=scan.resource_id,
                        severity="critical",
                        description=("IAM policy grants wildcard permissions"),
                        current_value="*",
                        expected_value=("least-privilege"),
                    )
                )

        logger.info("misconfigs_identified", count=len(misconfigs))
        return misconfigs

    async def generate_fix(
        self,
        misconfig: Misconfiguration,
    ) -> FixPlan:
        """Generate a fix plan for a misconfiguration."""
        fix = FixPlan(
            misconfig_id=misconfig.id,
            resource_id=misconfig.resource_id,
            fix_type=misconfig.misconfig_type.value,
            fix_description=(f"Fix {misconfig.misconfig_type}: {misconfig.description}"),
            api_call=(f"update_{misconfig.resource_id}({misconfig.expected_value})"),
            rollback_command=(f"revert_{misconfig.resource_id}({misconfig.current_value})"),
            status=FixStatus.PLANNED,
        )
        return fix

    async def apply_fix(
        self,
        fix: FixPlan,
    ) -> FixApplication:
        """Apply a fix to the cloud resource."""
        # Simulated — production calls cloud APIs
        app = FixApplication(
            fix_id=fix.id,
            resource_id=fix.resource_id,
            applied_at=time.time(),
            success=True,
            change_id=f"chg-{fix.id[:8]}",
        )
        logger.info(
            "fix_applied",
            fix_id=fix.id,
            resource_id=fix.resource_id,
        )
        return app

    async def verify_fix(
        self,
        fix: FixPlan,
    ) -> FixVerification:
        """Verify a fix was applied correctly."""
        # Simulated — production re-scans the resource
        ver = FixVerification(
            fix_id=fix.id,
            resource_id=fix.resource_id,
            still_misconfigured=False,
            new_value=fix.fix_description,
            verified=True,
            details="Re-scan confirms fix applied.",
        )
        logger.info(
            "fix_verified",
            fix_id=fix.id,
            verified=True,
        )
        return ver

    async def check_opa_approval(
        self,
        fix: FixPlan,
    ) -> bool:
        """Check OPA policy approval for a fix."""
        if self._opa is None:
            return True
        try:
            result = await self._opa.evaluate(
                "remediation/allow",
                {
                    "fix_type": fix.fix_type,
                    "resource_id": fix.resource_id,
                },
            )
            return bool(result.get("allow", False))
        except Exception as e:
            logger.error("opa_approval_failed", error=str(e))
            return False
