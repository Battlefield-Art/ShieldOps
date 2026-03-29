"""Firewall Rule Auditor Agent — Tool functions for rule collection and analysis."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    AuditFinding,
    FirewallProvider,
    FirewallRule,
    RuleRisk,
    RuleViolation,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Known-bad patterns per provider
# ---------------------------------------------------------------------------
_VIOLATION_CHECKS: list[dict[str, Any]] = [
    {
        "type": "overly_permissive_inbound",
        "description": "Inbound rule allows 0.0.0.0/0 on sensitive port",
        "risk": RuleRisk.CRITICAL,
        "compliance_refs": ["CIS-AWS-4.1", "PCI-DSS-1.3.2", "NIST-AC-4"],
        "check": lambda r: (
            r.direction == "inbound"
            and r.source in ("0.0.0.0/0", "::/0", "*")
            and r.action == "allow"
            and r.port_range not in ("80", "443")
        ),
        "recommendation": "Restrict source CIDR to specific IPs or ranges",
        "auto_fixable": False,
    },
    {
        "type": "overly_permissive_all_ports",
        "description": "Rule allows all ports (0-65535) from any source",
        "risk": RuleRisk.CRITICAL,
        "compliance_refs": ["CIS-AWS-4.2", "PCI-DSS-1.2.1"],
        "check": lambda r: (
            r.source in ("0.0.0.0/0", "::/0", "*")
            and r.action == "allow"
            and r.port_range in ("0-65535", "all", "*")
        ),
        "recommendation": "Remove all-port rules; specify required ports only",
        "auto_fixable": False,
    },
    {
        "type": "unused_rule",
        "description": "Rule has not been hit in over 90 days",
        "risk": RuleRisk.MEDIUM,
        "compliance_refs": ["CIS-AWS-4.3", "NIST-CM-7"],
        "check": lambda r: r.last_hit > 0 and (time.time() - r.last_hit) > 90 * 86400,
        "recommendation": "Remove unused rule to reduce attack surface",
        "auto_fixable": True,
    },
    {
        "type": "missing_description",
        "description": "Rule has no description — violates tagging policy",
        "risk": RuleRisk.LOW,
        "compliance_refs": ["CIS-AWS-4.4"],
        "check": lambda r: not r.description.strip(),
        "recommendation": "Add meaningful description for audit trail",
        "auto_fixable": True,
    },
    {
        "type": "ssh_open_to_world",
        "description": "SSH (port 22) open to 0.0.0.0/0",
        "risk": RuleRisk.HIGH,
        "compliance_refs": [
            "CIS-AWS-4.1",
            "CIS-AZ-4.1.1",
            "PCI-DSS-1.3.2",
        ],
        "check": lambda r: (
            r.direction == "inbound"
            and r.source in ("0.0.0.0/0", "::/0", "*")
            and r.action == "allow"
            and r.port_range == "22"
        ),
        "recommendation": "Restrict SSH to bastion or VPN CIDR only",
        "auto_fixable": False,
    },
    {
        "type": "rdp_open_to_world",
        "description": "RDP (port 3389) open to 0.0.0.0/0",
        "risk": RuleRisk.HIGH,
        "compliance_refs": [
            "CIS-AZ-4.1.1",
            "PCI-DSS-1.3.2",
            "NIST-AC-17",
        ],
        "check": lambda r: (
            r.direction == "inbound"
            and r.source in ("0.0.0.0/0", "::/0", "*")
            and r.action == "allow"
            and r.port_range == "3389"
        ),
        "recommendation": "Restrict RDP to corporate VPN CIDR only",
        "auto_fixable": False,
    },
]

# ---------------------------------------------------------------------------
# Simulated rule templates per provider
# ---------------------------------------------------------------------------
_RULE_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "aws_sg": [
        {
            "group_prefix": "sg-",
            "direction": "inbound",
            "protocol": "tcp",
            "port_range": "443",
            "source": "0.0.0.0/0",
            "action": "allow",
            "desc": "HTTPS inbound",
        },
        {
            "group_prefix": "sg-",
            "direction": "inbound",
            "protocol": "tcp",
            "port_range": "22",
            "source": "0.0.0.0/0",
            "action": "allow",
            "desc": "SSH open",
        },
        {
            "group_prefix": "sg-",
            "direction": "inbound",
            "protocol": "tcp",
            "port_range": "0-65535",
            "source": "0.0.0.0/0",
            "action": "allow",
            "desc": "",
        },
        {
            "group_prefix": "sg-",
            "direction": "inbound",
            "protocol": "tcp",
            "port_range": "5432",
            "source": "10.0.0.0/8",
            "action": "allow",
            "desc": "Postgres internal",
        },
        {
            "group_prefix": "sg-",
            "direction": "outbound",
            "protocol": "tcp",
            "port_range": "443",
            "source": "",
            "destination": "0.0.0.0/0",
            "action": "allow",
            "desc": "HTTPS outbound",
        },
    ],
    "azure_nsg": [
        {
            "group_prefix": "nsg-",
            "direction": "inbound",
            "protocol": "tcp",
            "port_range": "443",
            "source": "*",
            "action": "allow",
            "desc": "HTTPS inbound",
        },
        {
            "group_prefix": "nsg-",
            "direction": "inbound",
            "protocol": "tcp",
            "port_range": "3389",
            "source": "*",
            "action": "allow",
            "desc": "RDP open",
        },
        {
            "group_prefix": "nsg-",
            "direction": "inbound",
            "protocol": "tcp",
            "port_range": "22",
            "source": "10.0.0.0/8",
            "action": "allow",
            "desc": "SSH internal",
        },
    ],
    "gcp_firewall": [
        {
            "group_prefix": "fw-",
            "direction": "inbound",
            "protocol": "tcp",
            "port_range": "80",
            "source": "0.0.0.0/0",
            "action": "allow",
            "desc": "HTTP inbound",
        },
        {
            "group_prefix": "fw-",
            "direction": "inbound",
            "protocol": "tcp",
            "port_range": "22",
            "source": "0.0.0.0/0",
            "action": "allow",
            "desc": "",
        },
        {
            "group_prefix": "fw-",
            "direction": "inbound",
            "protocol": "tcp",
            "port_range": "443",
            "source": "0.0.0.0/0",
            "action": "allow",
            "desc": "HTTPS inbound",
        },
    ],
}

_REGIONS: dict[str, list[str]] = {
    "aws_sg": ["us-east-1", "us-west-2", "eu-west-1"],
    "azure_nsg": ["eastus", "westeurope", "southeastasia"],
    "gcp_firewall": ["us-central1", "europe-west1", "asia-east1"],
}


def _rule_hash(provider: str, idx: int) -> str:
    raw = f"{provider}-rule-{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class FirewallAuditToolkit:
    """Tools for collecting and auditing firewall rules across providers."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
    ) -> None:
        self._cloud_clients = cloud_clients

    # ---------------------------------------------------------------
    # 1. Collect firewall rules
    # ---------------------------------------------------------------
    async def collect_rules(
        self,
        tenant_id: str,
        providers: list[str],
    ) -> list[FirewallRule]:
        """Enumerate firewall rules across requested providers."""
        logger.info(
            "firewall_audit.collect_rules",
            tenant_id=tenant_id,
            providers=providers,
        )

        if self._cloud_clients is not None:
            try:
                raw = await self._cloud_clients.list_firewall_rules(
                    tenant_id=tenant_id,
                    providers=providers,
                )
                return [FirewallRule(**r) for r in raw]
            except Exception:  # noqa: S112
                logger.exception("firewall_audit.collect_rules.client_error")

        # Mock fallback
        rules: list[FirewallRule] = []
        for prov_key in providers:
            templates = _RULE_TEMPLATES.get(prov_key, [])
            regions = _REGIONS.get(prov_key, ["global"])

            for idx, tpl in enumerate(templates):
                rid = _rule_hash(prov_key, idx)
                region = random.choice(regions)  # noqa: S311
                last_hit_offset = random.randint(0, 180) * 86400  # noqa: S311
                rules.append(
                    FirewallRule(
                        id=f"{tpl['group_prefix']}{rid}",
                        provider=FirewallProvider(prov_key),
                        group_id=f"{tpl['group_prefix']}{rid[:6]}",
                        group_name=f"{prov_key}-group-{idx}",
                        direction=tpl["direction"],
                        protocol=tpl["protocol"],
                        port_range=tpl["port_range"],
                        source=tpl.get("source", ""),
                        destination=tpl.get("destination", ""),
                        action=tpl["action"],
                        description=tpl.get("desc", ""),
                        region=region,
                        last_hit=(
                            time.time() - last_hit_offset
                            if random.random() > 0.3  # noqa: S311
                            else 0.0
                        ),
                        tags={
                            "env": random.choice(  # noqa: S311
                                ["production", "staging", "dev"]
                            ),
                        },
                    )
                )

        logger.info(
            "firewall_audit.collect_rules.done",
            rule_count=len(rules),
        )
        return rules

    # ---------------------------------------------------------------
    # 2. Detect violations
    # ---------------------------------------------------------------
    async def detect_violations(
        self,
        rules: list[FirewallRule],
    ) -> list[RuleViolation]:
        """Run violation checks against collected rules."""
        logger.info(
            "firewall_audit.detect_violations",
            rule_count=len(rules),
        )

        violations: list[RuleViolation] = []
        for rule in rules:
            for check in _VIOLATION_CHECKS:
                try:
                    if check["check"](rule):
                        violations.append(
                            RuleViolation(
                                id=str(uuid.uuid4())[:8],
                                rule_id=rule.id,
                                provider=rule.provider,
                                violation_type=check["type"],
                                risk=check["risk"],
                                description=(
                                    f"{check['description']} — {rule.id} ({rule.port_range})"
                                ),
                                recommendation=check["recommendation"],
                                compliance_refs=check["compliance_refs"],
                                auto_fixable=check["auto_fixable"],
                            )
                        )
                except Exception:  # noqa: S112
                    continue

        logger.info(
            "firewall_audit.detect_violations.done",
            violation_count=len(violations),
        )
        return violations

    # ---------------------------------------------------------------
    # 3. Check compliance mapping
    # ---------------------------------------------------------------
    async def check_compliance(
        self,
        violations: list[RuleViolation],
    ) -> list[dict[str, Any]]:
        """Map violations to compliance frameworks."""
        logger.info(
            "firewall_audit.check_compliance",
            violation_count=len(violations),
        )

        framework_hits: dict[str, int] = {}
        for v in violations:
            for ref in v.compliance_refs:
                framework = ref.split("-")[0] if "-" in ref else ref
                framework_hits[framework] = framework_hits.get(framework, 0) + 1

        results: list[dict[str, Any]] = []
        for fw, count in framework_hits.items():
            results.append(
                {
                    "framework": fw,
                    "violation_count": count,
                    "status": "fail" if count > 0 else "pass",
                }
            )

        return results

    # ---------------------------------------------------------------
    # 4. Generate fix recommendations
    # ---------------------------------------------------------------
    async def recommend_fixes(
        self,
        violations: list[RuleViolation],
    ) -> list[AuditFinding]:
        """Aggregate violations into actionable findings with fixes."""
        logger.info(
            "firewall_audit.recommend_fixes",
            violation_count=len(violations),
        )

        # Group by violation type
        by_type: dict[str, list[RuleViolation]] = {}
        for v in violations:
            by_type.setdefault(v.violation_type, []).append(v)

        findings: list[AuditFinding] = []
        for vtype, vs in by_type.items():
            highest_risk = max(
                vs,
                key=lambda x: list(RuleRisk).index(x.risk),
            )
            findings.append(
                AuditFinding(
                    id=str(uuid.uuid4())[:8],
                    violation_ids=[v.id for v in vs],
                    title=f"{vtype.replace('_', ' ').title()}",
                    risk=highest_risk.risk,
                    affected_rules=len(vs),
                    fix_action=highest_risk.recommendation,
                    applied=False,
                    success=False,
                )
            )

        # Sort by risk
        risk_order = list(RuleRisk)
        findings.sort(key=lambda f: risk_order.index(f.risk))

        logger.info(
            "firewall_audit.recommend_fixes.done",
            finding_count=len(findings),
        )
        return findings
