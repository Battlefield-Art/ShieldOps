"""Node implementations for the Air-Gap Vault Agent LangGraph workflow.

Each node is an async function that:
1. Calls toolkit tools to interact with vault infrastructure
2. Uses the LLM to analyze tampering and produce recommendations
3. Updates the air-gap vault state
4. Records its reasoning step in the audit trail
"""

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.air_gap_vault.models import (
    AirGapVaultState,
    IntegrityStatus,
    ReasoningStep,
    VaultStage,
)
from shieldops.agents.air_gap_vault.prompts import (
    SYSTEM_ANALYZE_TAMPERING,
    SYSTEM_GENERATE_REPORT,
    TamperAnalysisResult,
    VaultReportResult,
)
from shieldops.agents.air_gap_vault.tools import AirGapVaultToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by the runner at graph construction.
_toolkit: AirGapVaultToolkit | None = None


def set_toolkit(toolkit: AirGapVaultToolkit) -> None:
    """Configure the toolkit used by all nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> AirGapVaultToolkit:
    if _toolkit is None:
        return AirGapVaultToolkit()
    return _toolkit


async def inventory_vault_assets(
    state: AirGapVaultState,
) -> dict[str, Any]:
    """Discover and inventory all vault assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "vault_inventorying_assets",
        vault_id=state.vault_id,
        scope=state.scan_scope,
    )

    assets = await toolkit.inventory_vault_assets(
        tenant_id=state.tenant_id,
        vault_id=state.vault_id,
        scan_scope=state.scan_scope,
    )

    ai_count = sum(1 for a in assets if a.asset_type in AirGapVaultToolkit.AI_ASSET_TYPES)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="inventory_vault_assets",
        input_summary=f"Vault: {state.vault_id}, scope: {state.scan_scope}",
        output_summary=f"Found {len(assets)} assets ({ai_count} AI-specific)",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="storage_client",
    )

    return {
        "vault_assets": assets,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": VaultStage.INVENTORY_VAULT_ASSETS,
    }


async def verify_isolation(
    state: AirGapVaultState,
) -> dict[str, Any]:
    """Verify network isolation for all vault assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if not state.vault_assets:
        return {
            "error": "No vault assets to verify isolation for.",
            "isolation_passed": False,
            "current_stage": VaultStage.VERIFY_ISOLATION,
        }

    checks = []
    for asset in state.vault_assets:
        check = await toolkit.verify_isolation(asset)
        checks.append(check)

    all_passed = all(c.passed for c in checks)
    failed = [c for c in checks if not c.passed]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="verify_isolation",
        input_summary=f"{len(state.vault_assets)} assets to verify",
        output_summary=f"Isolation {'PASSED' if all_passed else 'FAILED'}: "
        f"{len(checks) - len(failed)}/{len(checks)} passed",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="network_client",
    )

    return {
        "isolation_checks": checks,
        "isolation_passed": all_passed,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": VaultStage.VERIFY_ISOLATION,
    }


async def check_integrity(
    state: AirGapVaultState,
) -> dict[str, Any]:
    """Run cryptographic integrity checks on all vault assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if not state.vault_assets:
        return {
            "error": "No vault assets to check integrity for.",
            "current_stage": VaultStage.CHECK_INTEGRITY,
        }

    verifications = []
    for asset in state.vault_assets:
        check = await toolkit.check_integrity(asset)
        verifications.append(check)

    verified_count = sum(1 for v in verifications if v.status == IntegrityStatus.VERIFIED)
    degraded = [
        v
        for v in verifications
        if v.status
        in (
            IntegrityStatus.DEGRADED,
            IntegrityStatus.TAMPERED,
        )
    ]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="check_integrity",
        input_summary=f"{len(state.vault_assets)} assets to check",
        output_summary=f"{verified_count}/{len(verifications)} verified, "
        f"{len(degraded)} degraded/tampered",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="crypto_verifier",
    )

    return {
        "integrity_verifications": verifications,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": VaultStage.CHECK_INTEGRITY,
    }


async def detect_tampering(
    state: AirGapVaultState,
) -> dict[str, Any]:
    """Detect tampering across all vault assets using LLM analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if not state.vault_assets:
        return {
            "error": "No vault assets to scan for tampering.",
            "current_stage": VaultStage.DETECT_TAMPERING,
        }

    all_alerts = []
    for asset in state.vault_assets:
        alerts = await toolkit.detect_tampering(asset)
        all_alerts.extend(alerts)

    # Build context for LLM analysis
    integrity_lines = [
        f"- {v.asset_id}: status={v.status}, chain_valid={v.chain_valid}"
        for v in state.integrity_verifications
    ]
    alert_lines = [
        f"- {a.asset_id}: type={a.alert_type}, severity={a.severity}, ip={a.source_ip}"
        for a in all_alerts
    ]
    isolation_lines = [
        f"- {c.asset_id}: level={c.isolation_level}, passed={c.passed}"
        for c in state.isolation_checks
    ]

    context = [
        "## Vault Assets",
        *[f"- {a.name} ({a.asset_type})" for a in state.vault_assets],
        "",
        "## Isolation Checks",
        *isolation_lines,
        "",
        "## Integrity Results",
        *integrity_lines,
        "",
        "## Tamper Alerts",
        *(alert_lines if alert_lines else ["- None detected"]),
    ]
    user_prompt = "\n".join(context)

    # Defaults
    vault_health = 1.0
    recommendations = ["Continue regular integrity verification."]

    if all_alerts:
        vault_health = max(0.0, 1.0 - (len(all_alerts) * 0.15))
        recommendations = [
            "Investigate tamper alerts immediately.",
            "Rotate credentials for affected vault segments.",
        ]

    try:
        result = cast(
            TamperAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE_TAMPERING,
                user_prompt=user_prompt,
                schema=TamperAnalysisResult,
            ),
        )
        recommendations = result.recommendations
        if result.risk_level == "critical":
            vault_health = min(vault_health, 0.2)
        elif result.risk_level == "high":
            vault_health = min(vault_health, 0.4)
    except Exception as e:
        logger.error("llm_tamper_analysis_failed", error=str(e))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_tampering",
        input_summary=f"{len(state.vault_assets)} assets scanned",
        output_summary=f"{len(all_alerts)} tamper alerts, health={vault_health:.2f}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "tamper_alerts": all_alerts,
        "vault_health_score": vault_health,
        "recommendations": recommendations,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": VaultStage.DETECT_TAMPERING,
    }


async def enforce_retention(
    state: AirGapVaultState,
) -> dict[str, Any]:
    """Enforce retention policies on all vault assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if not state.vault_assets:
        return {
            "error": "No vault assets for retention enforcement.",
            "current_stage": VaultStage.ENFORCE_RETENTION,
        }

    policies = []
    for asset in state.vault_assets:
        policy = await toolkit.enforce_retention(asset)
        policies.append(policy)

    holds = sum(1 for p in policies if p.legal_hold)
    enforced = sum(1 for p in policies if p.enforced)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="enforce_retention",
        input_summary=f"{len(state.vault_assets)} assets",
        output_summary=f"{enforced} policies enforced, {holds} legal holds active",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="retention_engine",
    )

    return {
        "retention_policies": policies,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": VaultStage.ENFORCE_RETENTION,
    }


async def generate_report(
    state: AirGapVaultState,
) -> dict[str, Any]:
    """Generate final vault health report using the LLM."""
    start = datetime.now(UTC)

    tamper_count = len(state.tamper_alerts)
    integrity_ok = sum(
        1 for v in state.integrity_verifications if v.status == IntegrityStatus.VERIFIED
    )
    total_assets = len(state.vault_assets)

    context_lines = [
        f"Vault: {state.vault_id}",
        f"Total assets: {total_assets}",
        f"Isolation passed: {state.isolation_passed}",
        f"Integrity verified: {integrity_ok}/{total_assets}",
        f"Tamper alerts: {tamper_count}",
        f"Vault health score: {state.vault_health_score:.2f}",
        "",
        "Retention policies:",
        *[
            f"- {p.policy_name}: {p.compliance_framework} "
            f"({p.retention_days}d, hold={p.legal_hold})"
            for p in state.retention_policies
        ],
        "",
        "Recommendations:",
        *[f"- {r}" for r in state.recommendations],
    ]
    user_prompt = "\n".join(context_lines)

    report_summary = (
        f"Vault '{state.vault_id}' health: "
        f"{state.vault_health_score:.2f}. "
        f"{total_assets} assets, {tamper_count} alerts."
    )

    try:
        result = cast(
            VaultReportResult,
            await llm_structured(
                system_prompt=SYSTEM_GENERATE_REPORT,
                user_prompt=user_prompt,
                schema=VaultReportResult,
            ),
        )
        report_summary = (
            f"{result.title}\n\n"
            f"{result.executive_summary}\n\n"
            f"Grade: {result.vault_health_grade}. "
            f"Compliance: {result.compliance_status}. "
            f"Critical: "
            f"{'; '.join(result.critical_findings)}"
        )
    except Exception as e:
        logger.error("llm_generate_report_failed", error=str(e))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=f"Vault {state.vault_id}, score={state.vault_health_score:.2f}",
        output_summary=report_summary[:200],
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    total_duration = sum(s.duration_ms for s in [*state.reasoning_chain, step])

    return {
        "report_summary": report_summary,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": VaultStage.REPORT,
        "duration_ms": total_duration,
    }
