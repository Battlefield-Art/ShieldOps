"""Database Security Scanner Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DatabaseInstance,
    DSSStage,
    FindingSeverity,
    ReasoningStep,
)
from .tools import DatabaseSecurityScannerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Databases
# ------------------------------------------------------------------


async def discover_databases(
    state: dict[str, Any],
    toolkit: DatabaseSecurityScannerToolkit,
) -> dict[str, Any]:
    """Discover database instances across infrastructure."""
    logger.info("dss.node.discover_databases")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    instances = await toolkit.discover_databases(tenant_id)
    data = [inst.model_dump() for inst in instances]

    note = f"Discovered {len(instances)} database instances"

    return {
        "stage": DSSStage.SCAN_CONFIG.value,
        "instances": data,
        "current_step": "discover_databases",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="discover_databases",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Scan Configurations
# ------------------------------------------------------------------


async def scan_configurations(
    state: dict[str, Any],
    toolkit: DatabaseSecurityScannerToolkit,
) -> dict[str, Any]:
    """Scan database configurations for misconfigurations."""
    logger.info("dss.node.scan_config")
    state = _to_dict(state)

    instances = [DatabaseInstance(**r) for r in state.get("instances", [])]
    findings = await toolkit.scan_configurations(instances)
    data = [f.model_dump() for f in findings]

    critical = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    note = f"Found {len(findings)} config issues, {critical} critical"

    try:
        from .prompts import SYSTEM_CONFIG_SCAN, ConfigInsight

        ctx = json.dumps(
            {
                "findings": [
                    {
                        "check": f.check,
                        "severity": f.severity.value,
                        "description": f.description,
                    }
                    for f in findings[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ConfigInsight,
            await llm_structured(
                system_prompt=SYSTEM_CONFIG_SCAN,
                user_prompt=(f"Config scan results:\n{ctx}"),
                schema=ConfigInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="dss",
            node="scan_config",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="dss",
            node="scan_config",
        )

    return {
        "stage": DSSStage.CHECK_AUTH.value,
        "config_findings": data,
        "current_step": "scan_config",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="scan_config",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Check Authentication
# ------------------------------------------------------------------


async def check_authentication(
    state: dict[str, Any],
    toolkit: DatabaseSecurityScannerToolkit,
) -> dict[str, Any]:
    """Check for authentication weaknesses."""
    logger.info("dss.node.check_auth")
    state = _to_dict(state)

    instances = [DatabaseInstance(**r) for r in state.get("instances", [])]
    weaknesses = await toolkit.check_authentication(instances)
    data = [w.model_dump() for w in weaknesses]

    critical = sum(1 for w in weaknesses if w.severity == FindingSeverity.CRITICAL)
    note = f"Found {len(weaknesses)} auth weaknesses, {critical} critical"

    try:
        from .prompts import SYSTEM_AUTH_CHECK, AuthInsight

        ctx = json.dumps(
            {
                "weaknesses": [
                    {
                        "type": w.weakness_type,
                        "severity": w.severity.value,
                        "description": w.description,
                    }
                    for w in weaknesses[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            AuthInsight,
            await llm_structured(
                system_prompt=SYSTEM_AUTH_CHECK,
                user_prompt=(f"Auth weakness results:\n{ctx}"),
                schema=AuthInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="dss",
            node="check_auth",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="dss",
            node="check_auth",
        )

    return {
        "stage": DSSStage.AUDIT_ACCESS.value,
        "auth_weaknesses": data,
        "current_step": "check_auth",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="check_auth",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Audit Access
# ------------------------------------------------------------------


async def audit_access(
    state: dict[str, Any],
    toolkit: DatabaseSecurityScannerToolkit,
) -> dict[str, Any]:
    """Audit access controls and privileges."""
    logger.info("dss.node.audit_access")
    state = _to_dict(state)

    instances = [DatabaseInstance(**r) for r in state.get("instances", [])]
    audits = await toolkit.audit_access(instances)
    data = [a.model_dump() for a in audits]

    excessive = sum(1 for a in audits if a.excessive)
    note = f"Audited {len(audits)} access entries, {excessive} excessive"

    return {
        "stage": DSSStage.DETECT_EXPOSURE.value,
        "access_audits": data,
        "current_step": "audit_access",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="audit_access",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Detect Data Exposure
# ------------------------------------------------------------------


async def detect_data_exposure(
    state: dict[str, Any],
    toolkit: DatabaseSecurityScannerToolkit,
) -> dict[str, Any]:
    """Detect sensitive data exposure in databases."""
    logger.info("dss.node.detect_exposure")
    state = _to_dict(state)

    instances = [DatabaseInstance(**r) for r in state.get("instances", [])]
    exposures = await toolkit.detect_data_exposure(instances)
    data = [e.model_dump() for e in exposures]

    unencrypted = sum(1 for e in exposures if not e.encrypted)
    note = f"Found {len(exposures)} sensitive fields, {unencrypted} unencrypted"

    try:
        from .prompts import (
            SYSTEM_CONFIG_SCAN,
            ExposureInsight,
        )

        ctx = json.dumps(
            {
                "exposures": [
                    {
                        "table": e.table,
                        "column": e.column,
                        "data_type": e.data_type,
                        "encrypted": e.encrypted,
                        "masked": e.masked,
                    }
                    for e in exposures[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ExposureInsight,
            await llm_structured(
                system_prompt=SYSTEM_CONFIG_SCAN,
                user_prompt=(f"Data exposure results:\n{ctx}"),
                schema=ExposureInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="dss",
            node="detect_exposure",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="dss",
            node="detect_exposure",
        )

    return {
        "stage": DSSStage.REPORT.value,
        "data_exposures": data,
        "current_step": "detect_exposure",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_exposure",
                detail=note,
                confidence=0.8,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: DatabaseSecurityScannerToolkit,
) -> dict[str, Any]:
    """Compile the final database security report."""
    logger.info("dss.node.report")
    state = _to_dict(state)

    inst_count = len(state.get("instances", []))
    config_count = len(state.get("config_findings", []))
    auth_count = len(state.get("auth_weaknesses", []))
    exposure_count = len(state.get("data_exposures", []))
    total = config_count + auth_count + exposure_count

    critical = 0
    for f in state.get("config_findings", []):
        if f.get("severity") == FindingSeverity.CRITICAL:
            critical += 1
    for w in state.get("auth_weaknesses", []):
        if w.get("severity") == FindingSeverity.CRITICAL:
            critical += 1
    for e in state.get("data_exposures", []):
        if e.get("severity") == FindingSeverity.CRITICAL:
            critical += 1

    excessive = sum(1 for a in state.get("access_audits", []) if a.get("excessive"))

    lines = [
        "# Database Security Scan Report",
        "",
        f"**Instances scanned:** {inst_count}",
        f"**Total findings:** {total}",
        f"**Critical findings:** {critical}",
        f"**Config issues:** {config_count}",
        f"**Auth weaknesses:** {auth_count}",
        f"**Excessive privileges:** {excessive}",
        f"**Data exposures:** {exposure_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "instances": inst_count,
                "total_findings": total,
                "critical": critical,
                "config_issues": config_count,
                "auth_weaknesses": auth_count,
                "excessive_access": excessive,
                "data_exposures": exposure_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Database security report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="dss",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="dss",
            node="report",
        )

    return {
        "stage": DSSStage.REPORT.value,
        "report": report_text,
        "total_findings": total,
        "critical_count": critical,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
