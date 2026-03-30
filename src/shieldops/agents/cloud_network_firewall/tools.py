"""Cloud Network Firewall Agent — Tool functions for rule collection and analysis."""

from __future__ import annotations

import hashlib
import random
import uuid
from typing import Any

import structlog

from .models import (
    CloudPlatform,
    CoverageAnalysis,
    FirewallRule,
    OverpermissiveRule,
    RuleOptimization,
    RuleSeverity,
    ShadowRule,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Simulated rule templates per platform
# ---------------------------------------------------------------------------
_RULE_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "aws_sg": [
        {
            "rule_name": "allow-ssh",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range": "22",
            "source_cidr": "0.0.0.0/0",
            "action": "allow",
        },
        {
            "rule_name": "allow-https",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range": "443",
            "source_cidr": "0.0.0.0/0",
            "action": "allow",
        },
        {
            "rule_name": "allow-http",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range": "80",
            "source_cidr": "0.0.0.0/0",
            "action": "allow",
        },
        {
            "rule_name": "allow-all-internal",
            "direction": "ingress",
            "protocol": "-1",
            "port_range": "0-65535",
            "source_cidr": "10.0.0.0/8",
            "action": "allow",
        },
        {
            "rule_name": "allow-db",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range": "5432",
            "source_cidr": "10.0.1.0/24",
            "action": "allow",
        },
        {
            "rule_name": "allow-rdp",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range": "3389",
            "source_cidr": "0.0.0.0/0",
            "action": "allow",
        },
        {
            "rule_name": "egress-all",
            "direction": "egress",
            "protocol": "-1",
            "port_range": "0-65535",
            "source_cidr": "",
            "destination_cidr": "0.0.0.0/0",
            "action": "allow",
        },
    ],
    "gcp_firewall": [
        {
            "rule_name": "allow-ssh-gcp",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range": "22",
            "source_cidr": "0.0.0.0/0",
            "action": "allow",
            "priority": 1000,
        },
        {
            "rule_name": "allow-https-gcp",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range": "443",
            "source_cidr": "0.0.0.0/0",
            "action": "allow",
            "priority": 1000,
        },
        {
            "rule_name": "deny-all-ingress",
            "direction": "ingress",
            "protocol": "-1",
            "port_range": "0-65535",
            "source_cidr": "0.0.0.0/0",
            "action": "deny",
            "priority": 65534,
        },
        {
            "rule_name": "allow-internal-gcp",
            "direction": "ingress",
            "protocol": "-1",
            "port_range": "0-65535",
            "source_cidr": "10.128.0.0/9",
            "action": "allow",
            "priority": 1000,
        },
        {
            "rule_name": "allow-icmp-gcp",
            "direction": "ingress",
            "protocol": "icmp",
            "port_range": "",
            "source_cidr": "0.0.0.0/0",
            "action": "allow",
            "priority": 1000,
        },
    ],
    "azure_nsg": [
        {
            "rule_name": "AllowHTTPS",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range": "443",
            "source_cidr": "*",
            "action": "allow",
            "priority": 100,
        },
        {
            "rule_name": "AllowHTTP",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range": "80",
            "source_cidr": "*",
            "action": "allow",
            "priority": 110,
        },
        {
            "rule_name": "AllowSSH",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range": "22",
            "source_cidr": "*",
            "action": "allow",
            "priority": 120,
        },
        {
            "rule_name": "DenyAllInbound",
            "direction": "ingress",
            "protocol": "*",
            "port_range": "*",
            "source_cidr": "*",
            "action": "deny",
            "priority": 4096,
        },
        {
            "rule_name": "AllowVnetInbound",
            "direction": "ingress",
            "protocol": "*",
            "port_range": "*",
            "source_cidr": "VirtualNetwork",
            "action": "allow",
            "priority": 65000,
        },
    ],
    "k8s_network_policy": [
        {
            "rule_name": "allow-web-ingress",
            "direction": "ingress",
            "protocol": "tcp",
            "port_range": "8080",
            "source_cidr": "0.0.0.0/0",
            "action": "allow",
        },
        {
            "rule_name": "allow-dns-egress",
            "direction": "egress",
            "protocol": "udp",
            "port_range": "53",
            "source_cidr": "",
            "destination_cidr": "0.0.0.0/0",
            "action": "allow",
        },
        {
            "rule_name": "deny-default",
            "direction": "ingress",
            "protocol": "-1",
            "port_range": "",
            "source_cidr": "0.0.0.0/0",
            "action": "deny",
        },
    ],
}

_REGIONS: dict[str, list[str]] = {
    "aws_sg": ["us-east-1", "us-west-2", "eu-west-1"],
    "gcp_firewall": [
        "us-central1",
        "europe-west1",
        "asia-east1",
    ],
    "azure_nsg": ["eastus", "westeurope", "southeastasia"],
    "k8s_network_policy": ["default-cluster"],
}

_GROUP_PREFIXES: dict[str, str] = {
    "aws_sg": "sg-",
    "gcp_firewall": "fw-",
    "azure_nsg": "nsg-",
    "k8s_network_policy": "netpol-",
}


def _rule_hash(platform: str, name: str, idx: int) -> str:
    """Deterministic rule id."""
    raw = f"{platform}-{name}-{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class CloudNetworkFirewallToolkit:
    """Tools for multi-cloud firewall rule analysis."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
    ) -> None:
        self._cloud_clients = cloud_clients

    # ---------------------------------------------------------------
    # 1. Collect firewall rules
    # ---------------------------------------------------------------
    async def collect_firewall_rules(
        self,
        tenant_id: str,
        platforms: list[str],
    ) -> list[FirewallRule]:
        """Collect firewall rules across cloud platforms.

        Uses live cloud clients when available; falls back to
        simulated rule inventories for testing.
        """
        logger.info(
            "cnf.collect_firewall_rules",
            tenant_id=tenant_id,
            platforms=platforms,
        )

        if self._cloud_clients is not None:
            try:
                raw = await self._cloud_clients.list_rules(
                    tenant_id=tenant_id,
                    platforms=platforms,
                )
                return [FirewallRule(**r) for r in raw]
            except Exception:
                logger.exception("cnf.collect_firewall_rules.client_error")

        rules: list[FirewallRule] = []
        for plat_key in platforms:
            templates = _RULE_TEMPLATES.get(plat_key, [])
            regions = _REGIONS.get(plat_key, ["global"])
            prefix = _GROUP_PREFIXES.get(plat_key, "rule-")
            groups = random.randint(2, 4)  # noqa: S311

            for g_idx in range(groups):
                group_id = f"{prefix}{_rule_hash(plat_key, 'grp', g_idx)}"
                region = random.choice(regions)  # noqa: S311

                for t_idx, tpl in enumerate(templates):
                    rid = _rule_hash(plat_key, tpl["rule_name"], g_idx * 100 + t_idx)
                    hit = random.randint(0, 50000)  # noqa: S311
                    rules.append(
                        FirewallRule(
                            id=f"rule-{rid}",
                            platform=CloudPlatform(plat_key),
                            group_id=group_id,
                            rule_name=tpl["rule_name"],
                            direction=tpl["direction"],
                            protocol=tpl["protocol"],
                            port_range=tpl.get("port_range", ""),
                            source_cidr=tpl.get("source_cidr", ""),
                            destination_cidr=tpl.get("destination_cidr", ""),
                            action=tpl["action"],
                            priority=tpl.get("priority", 1000),
                            description=f"Simulated {tpl['rule_name']}",
                            region=region,
                            tags={
                                "env": random.choice(  # noqa: S311
                                    ["prod", "staging", "dev"]
                                ),
                            },
                            hit_count=hit,
                            last_hit=0.0 if hit == 0 else 1.0,
                        )
                    )

        logger.info(
            "cnf.collect_firewall_rules.done",
            rule_count=len(rules),
        )
        return rules

    # ---------------------------------------------------------------
    # 2. Analyze coverage
    # ---------------------------------------------------------------
    async def analyze_coverage(
        self,
        rules: list[FirewallRule],
    ) -> list[CoverageAnalysis]:
        """Analyze firewall rule coverage per security group."""
        logger.info(
            "cnf.analyze_coverage",
            rule_count=len(rules),
        )

        groups: dict[str, list[FirewallRule]] = {}
        for r in rules:
            groups.setdefault(r.group_id, []).append(r)

        results: list[CoverageAnalysis] = []
        for gid, grp_rules in groups.items():
            ingress = [r for r in grp_rules if r.direction == "ingress"]
            egress = [r for r in grp_rules if r.direction == "egress"]
            allows = [r for r in grp_rules if r.action == "allow"]
            denies = [r for r in grp_rules if r.action == "deny"]
            protocols = list({r.protocol for r in grp_rules})
            unused = sum(1 for r in grp_rules if r.hit_count == 0)

            total = len(grp_rules)
            used = total - unused
            coverage = round((used / total * 100) if total else 0.0, 1)

            results.append(
                CoverageAnalysis(
                    id=str(uuid.uuid4())[:8],
                    platform=grp_rules[0].platform,
                    group_id=gid,
                    total_rules=total,
                    ingress_rules=len(ingress),
                    egress_rules=len(egress),
                    allow_rules=len(allows),
                    deny_rules=len(denies),
                    protocols_covered=protocols,
                    port_coverage_pct=coverage,
                    unused_rules=unused,
                    coverage_score=coverage,
                )
            )

        logger.info(
            "cnf.analyze_coverage.done",
            group_count=len(results),
        )
        return results

    # ---------------------------------------------------------------
    # 3. Detect overpermissive rules
    # ---------------------------------------------------------------
    async def detect_overpermissive(
        self,
        rules: list[FirewallRule],
    ) -> list[OverpermissiveRule]:
        """Detect overly permissive firewall rules."""
        logger.info(
            "cnf.detect_overpermissive",
            rule_count=len(rules),
        )

        web_ports = {"80", "443", "8080", "8443"}
        findings: list[OverpermissiveRule] = []

        for r in rules:
            if r.action != "allow":
                continue

            severity = None
            reason = ""
            recommendation = ""
            risk = 0.0

            src = r.source_cidr
            is_open = src in ("0.0.0.0/0", "*", "::/0")
            is_wide_port = r.port_range in (
                "0-65535",
                "*",
                "",
            ) and r.protocol in ("-1", "*")
            is_non_web = r.port_range not in web_ports

            if is_open and is_wide_port:
                severity = RuleSeverity.CRITICAL
                reason = "All ports open to internet"
                recommendation = "Restrict to specific ports and CIDRs"
                risk = 98.0
            elif is_open and r.port_range == "3389":
                severity = RuleSeverity.CRITICAL
                reason = "RDP open to internet"
                recommendation = "Restrict RDP to VPN CIDR"
                risk = 95.0
            elif is_open and r.port_range == "22":
                severity = RuleSeverity.HIGH
                reason = "SSH open to internet"
                recommendation = "Restrict SSH to bastion/VPN CIDR"
                risk = 80.0
            elif is_open and is_non_web and r.port_range:
                severity = RuleSeverity.HIGH
                reason = f"Port {r.port_range} open to internet"
                recommendation = f"Restrict port {r.port_range} to known source CIDRs"
                risk = 70.0
            elif is_wide_port and not is_open:
                severity = RuleSeverity.MEDIUM
                reason = "All ports allowed from internal CIDR"
                recommendation = "Restrict to required ports only"
                risk = 45.0

            if severity is not None:
                noise = random.uniform(-3.0, 3.0)  # noqa: S311
                risk = round(max(0.0, min(100.0, risk + noise)), 1)
                findings.append(
                    OverpermissiveRule(
                        id=str(uuid.uuid4())[:8],
                        rule_id=r.id,
                        platform=r.platform,
                        severity=severity,
                        reason=reason,
                        source_cidr=r.source_cidr,
                        port_range=r.port_range,
                        protocol=r.protocol,
                        recommendation=recommendation,
                        risk_score=risk,
                        auto_fixable=severity not in (RuleSeverity.CRITICAL,),
                    )
                )

        logger.info(
            "cnf.detect_overpermissive.done",
            finding_count=len(findings),
        )
        return findings

    # ---------------------------------------------------------------
    # 4. Find shadow rules
    # ---------------------------------------------------------------
    async def find_shadow_rules(
        self,
        rules: list[FirewallRule],
    ) -> list[ShadowRule]:
        """Find shadow rules masked by higher-priority rules."""
        logger.info(
            "cnf.find_shadow_rules",
            rule_count=len(rules),
        )

        groups: dict[str, list[FirewallRule]] = {}
        for r in rules:
            groups.setdefault(r.group_id, []).append(r)

        shadows: list[ShadowRule] = []
        for grp_rules in groups.values():
            sorted_rules = sorted(grp_rules, key=lambda x: x.priority)
            for i, lower in enumerate(sorted_rules):
                for higher in sorted_rules[:i]:
                    if higher.direction != lower.direction:
                        continue
                    if not self._cidr_overlaps(higher.source_cidr, lower.source_cidr):
                        continue
                    if not self._port_overlaps(higher.port_range, lower.port_range):
                        continue
                    if higher.action != lower.action:
                        impact = (
                            "Deny rule shadowed by allow"
                            if lower.action == "deny"
                            else "Allow rule shadowed by deny"
                        )
                        shadows.append(
                            ShadowRule(
                                id=str(uuid.uuid4())[:8],
                                shadowed_rule_id=lower.id,
                                shadowing_rule_id=higher.id,
                                platform=lower.platform,
                                reason=(f"Rule {lower.rule_name} shadowed by {higher.rule_name}"),
                                shadowed_action=lower.action,
                                shadowing_action=higher.action,
                                impact=impact,
                                removable=lower.hit_count == 0,
                            )
                        )

        logger.info(
            "cnf.find_shadow_rules.done",
            shadow_count=len(shadows),
        )
        return shadows

    # ---------------------------------------------------------------
    # 5. Optimize rules
    # ---------------------------------------------------------------
    async def optimize_rules(
        self,
        rules: list[FirewallRule],
        overpermissive: list[OverpermissiveRule],
        shadow: list[ShadowRule],
    ) -> list[RuleOptimization]:
        """Generate optimization recommendations."""
        logger.info("cnf.optimize_rules")

        opts: list[RuleOptimization] = []

        # Recommend removing shadow rules that are safe
        for sr in shadow:
            if sr.removable:
                opts.append(
                    RuleOptimization(
                        id=str(uuid.uuid4())[:8],
                        platform=sr.platform,
                        optimization_type="remove",
                        affected_rule_ids=[sr.shadowed_rule_id],
                        description=(f"Remove shadowed rule {sr.shadowed_rule_id}"),
                        risk_reduction=5.0,
                        auto_applicable=True,
                    )
                )

        # Recommend restricting overpermissive rules
        for op in overpermissive:
            if op.auto_fixable:
                opts.append(
                    RuleOptimization(
                        id=str(uuid.uuid4())[:8],
                        platform=op.platform,
                        optimization_type="restrict",
                        affected_rule_ids=[op.rule_id],
                        description=op.recommendation,
                        risk_reduction=op.risk_score * 0.6,
                        auto_applicable=True,
                    )
                )
            else:
                opts.append(
                    RuleOptimization(
                        id=str(uuid.uuid4())[:8],
                        platform=op.platform,
                        optimization_type="restrict",
                        affected_rule_ids=[op.rule_id],
                        description=op.recommendation,
                        risk_reduction=op.risk_score * 0.4,
                        auto_applicable=False,
                    )
                )

        # Recommend merging duplicate rules
        groups: dict[str, list[FirewallRule]] = {}
        for r in rules:
            key = f"{r.group_id}:{r.direction}:{r.protocol}:{r.action}"
            groups.setdefault(key, []).append(r)

        for _key, grp in groups.items():
            if len(grp) >= 3:
                opts.append(
                    RuleOptimization(
                        id=str(uuid.uuid4())[:8],
                        platform=grp[0].platform,
                        optimization_type="merge",
                        affected_rule_ids=[r.id for r in grp],
                        description=(f"Merge {len(grp)} similar rules in {grp[0].group_id}"),
                        risk_reduction=3.0,
                        auto_applicable=False,
                    )
                )

        logger.info(
            "cnf.optimize_rules.done",
            optimization_count=len(opts),
        )
        return opts

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------
    @staticmethod
    def _cidr_overlaps(a: str, b: str) -> bool:
        """Check if two CIDRs overlap (simplified)."""
        if not a or not b:
            return False
        if a in ("0.0.0.0/0", "*", "::/0"):
            return True
        if b in ("0.0.0.0/0", "*", "::/0"):
            return True
        return a == b

    @staticmethod
    def _port_overlaps(a: str, b: str) -> bool:
        """Check if two port ranges overlap (simplified)."""
        wildcards = ("0-65535", "*", "", "-1")
        if a in wildcards or b in wildcards:
            return True
        return a == b
