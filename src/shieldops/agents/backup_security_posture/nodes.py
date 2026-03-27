"""Backup Security Posture Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BackupInventory,
    BackupPostureStage,
    BackupVulnerability,
    HardeningPriority,
    HardeningRecommendation,
    ReasoningStep,
    RecoveryTest,
    SecurityConfig,
)
from .tools import BackupSecurityPostureToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Inventory Backup Infrastructure
# ------------------------------------------------------------------


async def inventory_backup_infra(
    state: dict[str, Any],
    toolkit: BackupSecurityPostureToolkit,
) -> dict[str, Any]:
    """Inventory backup infrastructure."""
    logger.info("backup_posture.node.inventory")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    inventory = await toolkit.inventory_backup_infra(tenant_id)
    data = [i.model_dump() for i in inventory]

    note = f"Inventoried {len(inventory)} backup assets"

    try:
        from .prompts import (
            SYSTEM_INVENTORY,
            InventoryInsight,
        )

        ctx = json.dumps(
            {
                "assets": [
                    {
                        "name": i.name,
                        "component": (i.component.value),
                        "provider": i.provider,
                        "immutable": i.immutable,
                    }
                    for i in inventory[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            InventoryInsight,
            await llm_structured(
                system_prompt=SYSTEM_INVENTORY,
                user_prompt=(f"Backup inventory:\n{ctx}"),
                schema=InventoryInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="backup_posture",
            node="inventory",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="backup_posture",
            node="inventory",
        )

    return {
        "stage": (BackupPostureStage.ASSESS_SECURITY_CONFIG.value),
        "inventory": data,
        "total_backup_assets": len(inventory),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="inventory_backup_infra",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Assess Security Config
# ------------------------------------------------------------------


async def assess_security_config(
    state: dict[str, Any],
    toolkit: BackupSecurityPostureToolkit,
) -> dict[str, Any]:
    """Assess backup security configuration."""
    logger.info("backup_posture.node.config")
    state = _to_dict(state)

    inventory = [BackupInventory(**i) for i in state.get("inventory", [])]
    configs = await toolkit.assess_security_config(inventory)
    data = [c.model_dump() for c in configs]

    avg = (
        round(
            sum(c.compliance_score for c in configs) / len(configs),
            1,
        )
        if configs
        else 0.0
    )
    note = f"Assessed {len(configs)} configs, avg compliance: {avg}%"

    try:
        from .prompts import (
            SYSTEM_CONFIG,
            ConfigInsight,
        )

        ctx = json.dumps(
            {
                "configs": [
                    {
                        "component": (c.component.value),
                        "score": (c.compliance_score),
                        "issues": c.issues,
                    }
                    for c in configs[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ConfigInsight,
            await llm_structured(
                system_prompt=SYSTEM_CONFIG,
                user_prompt=(f"Config data:\n{ctx}"),
                schema=ConfigInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="backup_posture",
            node="config",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="backup_posture",
            node="config",
        )

    return {
        "stage": (BackupPostureStage.DETECT_VULNERABILITIES.value),
        "configs": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="assess_security_config",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Vulnerabilities
# ------------------------------------------------------------------


async def detect_vulnerabilities(
    state: dict[str, Any],
    toolkit: BackupSecurityPostureToolkit,
) -> dict[str, Any]:
    """Detect backup vulnerabilities."""
    logger.info("backup_posture.node.vulns")
    state = _to_dict(state)

    inventory = [BackupInventory(**i) for i in state.get("inventory", [])]
    configs = [SecurityConfig(**c) for c in state.get("configs", [])]
    vulns = await toolkit.detect_vulnerabilities(inventory, configs)
    data = [v.model_dump() for v in vulns]

    critical = sum(1 for v in vulns if v.severity == HardeningPriority.CRITICAL)
    note = f"Found {len(vulns)} vulnerabilities, {critical} critical"

    try:
        from .prompts import (
            SYSTEM_VULN,
            VulnInsight,
        )

        ctx = json.dumps(
            {
                "vulns": [
                    {
                        "vuln": v.vulnerability,
                        "severity": (v.severity.value),
                        "ransomware": (v.ransomware_risk),
                    }
                    for v in vulns[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            VulnInsight,
            await llm_structured(
                system_prompt=SYSTEM_VULN,
                user_prompt=(f"Vulnerabilities:\n{ctx}"),
                schema=VulnInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="backup_posture",
            node="vulns",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="backup_posture",
            node="vulns",
        )

    return {
        "stage": (BackupPostureStage.TEST_RECOVERY.value),
        "vulnerabilities": data,
        "critical_vulns": critical,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="detect_vulnerabilities",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Test Recovery
# ------------------------------------------------------------------


async def test_recovery(
    state: dict[str, Any],
    toolkit: BackupSecurityPostureToolkit,
) -> dict[str, Any]:
    """Test backup recovery capabilities."""
    logger.info("backup_posture.node.recovery")
    state = _to_dict(state)

    inventory = [BackupInventory(**i) for i in state.get("inventory", [])]
    tests = await toolkit.test_recovery(inventory)
    data = [t.model_dump() for t in tests]

    success_rate = (
        round(
            sum(1 for t in tests if t.success) / len(tests) * 100,
            1,
        )
        if tests
        else 0.0
    )
    note = f"Ran {len(tests)} recovery tests, {success_rate}% success"

    try:
        from .prompts import (
            SYSTEM_RECOVERY,
            RecoveryInsight,
        )

        ctx = json.dumps(
            {
                "tests": [
                    {
                        "type": t.test_type,
                        "success": t.success,
                        "time_min": (t.recovery_time_min),
                        "integrity": (t.data_integrity_pct),
                    }
                    for t in tests[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RecoveryInsight,
            await llm_structured(
                system_prompt=SYSTEM_RECOVERY,
                user_prompt=(f"Recovery tests:\n{ctx}"),
                schema=RecoveryInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="backup_posture",
            node="recovery",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="backup_posture",
            node="recovery",
        )

    return {
        "stage": (BackupPostureStage.RECOMMEND_HARDENING.value),
        "recovery_tests": data,
        "recovery_success_rate": success_rate,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="test_recovery",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Recommend Hardening
# ------------------------------------------------------------------


async def recommend_hardening(
    state: dict[str, Any],
    toolkit: BackupSecurityPostureToolkit,
) -> dict[str, Any]:
    """Generate hardening recommendations."""
    logger.info("backup_posture.node.harden")
    state = _to_dict(state)

    inventory = [BackupInventory(**i) for i in state.get("inventory", [])]
    vulns = [BackupVulnerability(**v) for v in state.get("vulnerabilities", [])]
    tests = [RecoveryTest(**t) for t in state.get("recovery_tests", [])]

    recs = await toolkit.recommend_hardening(inventory, vulns, tests)
    data = [r.model_dump() for r in recs]

    return {
        "stage": BackupPostureStage.REPORT.value,
        "recommendations": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="recommend_hardening",
                detail=(f"Generated {len(recs)} hardening recommendations"),
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def report(
    state: dict[str, Any],
    toolkit: BackupSecurityPostureToolkit,
) -> dict[str, Any]:
    """Compile the final backup security report."""
    logger.info("backup_posture.node.report")
    state = _to_dict(state)

    total = state.get("total_backup_assets", 0)
    critical = state.get("critical_vulns", 0)
    recovery = state.get("recovery_success_rate", 0.0)
    recs = [HardeningRecommendation(**r) for r in state.get("recommendations", [])]

    lines = [
        "# Backup Security Posture Report",
        "",
        f"**Backup assets:** {total}",
        f"**Critical vulnerabilities:** {critical}",
        f"**Recovery success rate:** {recovery}%",
        "",
        "## Hardening Recommendations",
    ]
    for i, r in enumerate(recs[:15], 1):
        ransomware = " [RANSOMWARE]" if r.ransomware_protection else ""
        lines.append(f"{i}. [{r.priority.value}]{ransomware} {r.recommendation} — {r.rationale}")

    return {
        "stage": BackupPostureStage.REPORT.value,
        "report": "\n".join(lines),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
