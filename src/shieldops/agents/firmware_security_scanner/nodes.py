"""Node implementations for the Firmware Security Scanner."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.firmware_security_scanner.models import (
    FirmwareSecurityScannerState,
    FSSStage,
    ReasoningStep,
)
from shieldops.agents.firmware_security_scanner.prompts import (
    SYSTEM_COMPONENTS,
    SYSTEM_CRYPTO,
    SYSTEM_EXTRACT,
    SYSTEM_RISK,
    SYSTEM_VULNS,
    ComponentAnalysisOutput,
    CryptoCheckOutput,
    FirmwareExtractOutput,
    FirmwareRiskOutput,
    VulnScanOutput,
)
from shieldops.agents.firmware_security_scanner.tools import (
    FirmwareSecurityScannerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: FirmwareSecurityScannerToolkit | None = None


def set_toolkit(
    toolkit: FirmwareSecurityScannerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> FirmwareSecurityScannerToolkit:
    if _toolkit is None:
        return FirmwareSecurityScannerToolkit()
    return _toolkit


def _step(
    state: FirmwareSecurityScannerState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def extract_firmware(
    state: FirmwareSecurityScannerState,
) -> dict[str, Any]:
    """Extract firmware images for analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.extract_firmware(state.scan_config)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "targets": state.scan_config.get("targets", [])[:10],
                "image_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EXTRACT,
            user_prompt=(f"Firmware extraction context:\n{ctx}"),
            schema=FirmwareExtractOutput,
        )
        if hasattr(llm_result, "total_extracted"):
            logger.info(
                "llm_enhanced",
                node="extract_firmware",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="extract_firmware",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "extract_firmware",
        f"targets={len(state.scan_config.get('targets', []))}",
        f"extracted {len(raw)} images",
        elapsed,
        "binary_analyzer",
    )
    await toolkit.record_metric("extracted", float(len(raw)))

    return {
        "firmware_images": raw,
        "total_extracted": len(raw),
        "stage": FSSStage.ANALYZE_COMPONENTS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "extract_firmware",
        "session_start": start,
    }


async def analyze_components(
    state: FirmwareSecurityScannerState,
) -> dict[str, Any]:
    """Analyze firmware components and generate SBOM."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    components = await toolkit.analyze_components(
        state.firmware_images,
    )
    outdated = sum(1 for c in components if c.get("is_outdated"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "image_count": len(state.firmware_images),
                "component_count": len(components),
                "outdated": outdated,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COMPONENTS,
            user_prompt=(f"Component analysis:\n{ctx}"),
            schema=ComponentAnalysisOutput,
        )
        if hasattr(llm_result, "outdated_count") and llm_result.outdated_count > outdated:
            outdated = llm_result.outdated_count
        logger.info(
            "llm_enhanced",
            node="analyze_components",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_components",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "analyze_components",
        f"analyzing {len(state.firmware_images)} firmware images",
        f"{len(components)} components, {outdated} outdated",
        elapsed,
        "sbom_generator",
    )

    return {
        "components": components,
        "outdated_component_count": outdated,
        "stage": FSSStage.SCAN_VULNS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_components",
    }


async def scan_vulnerabilities(
    state: FirmwareSecurityScannerState,
) -> dict[str, Any]:
    """Scan components for known vulnerabilities."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    vulns = await toolkit.scan_vulnerabilities(
        state.components,
    )
    critical = sum(1 for v in vulns if v.get("severity") == "critical")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "component_count": len(state.components),
                "vuln_count": len(vulns),
                "critical": critical,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VULNS,
            user_prompt=(f"Vulnerability scan:\n{ctx}"),
            schema=VulnScanOutput,
        )
        if hasattr(llm_result, "critical_count") and llm_result.critical_count > critical:
            critical = llm_result.critical_count
        logger.info(
            "llm_enhanced",
            node="scan_vulnerabilities",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_vulnerabilities",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "scan_vulnerabilities",
        f"scanning {len(state.components)} components",
        f"{len(vulns)} vulns, {critical} critical",
        elapsed,
        "cve_database",
    )
    await toolkit.record_metric("vulnerabilities", float(len(vulns)))

    return {
        "vulnerabilities": vulns,
        "critical_vuln_count": critical,
        "stage": FSSStage.CHECK_CRYPTO,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "scan_vulnerabilities",
    }


async def check_crypto(
    state: FirmwareSecurityScannerState,
) -> dict[str, Any]:
    """Check cryptographic implementations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.check_crypto_strength(
        state.firmware_images,
    )
    weak = sum(1 for f in findings if f.get("strength") in ("weak", "deprecated"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "image_count": len(state.firmware_images),
                "finding_count": len(findings),
                "weak": weak,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CRYPTO,
            user_prompt=(f"Crypto analysis:\n{ctx}"),
            schema=CryptoCheckOutput,
        )
        if hasattr(llm_result, "weak_count") and llm_result.weak_count > weak:
            weak = llm_result.weak_count
        logger.info(
            "llm_enhanced",
            node="check_crypto",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_crypto",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "check_crypto",
        f"checking crypto in {len(state.firmware_images)} images",
        f"{weak} weak algorithms",
        elapsed,
        "crypto_scanner",
    )

    return {
        "crypto_findings": findings,
        "weak_crypto_count": weak,
        "stage": FSSStage.ASSESS_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "check_crypto",
    }


async def assess_risk(
    state: FirmwareSecurityScannerState,
) -> dict[str, Any]:
    """Assess overall firmware risk."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_risk(
        state.firmware_images,
        state.vulnerabilities,
        state.crypto_findings,
    )
    max_score = max(
        (a.get("risk_score", 0.0) for a in assessments),
        default=0.0,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "image_count": len(state.firmware_images),
                "vuln_count": len(state.vulnerabilities),
                "crypto_count": len(state.crypto_findings),
                "max_score": max_score,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=(f"Firmware risk assessment:\n{ctx}"),
            schema=FirmwareRiskOutput,
        )
        if hasattr(llm_result, "max_risk_score") and llm_result.max_risk_score > max_score:
            max_score = round(
                (max_score + llm_result.max_risk_score) / 2,
                1,
            )
        logger.info(
            "llm_enhanced",
            node="assess_risk",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "assess_risk",
        f"assessing {len(state.firmware_images)} firmware images",
        f"max_risk={max_score}",
        elapsed,
        "risk_engine",
    )
    await toolkit.record_metric("max_risk", max_score)

    return {
        "risk_assessments": assessments,
        "max_risk_score": max_score,
        "stage": FSSStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_risk",
    }


async def generate_report(
    state: FirmwareSecurityScannerState,
) -> dict[str, Any]:
    """Generate final firmware security report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_images": state.total_extracted,
        "total_components": len(state.components),
        "outdated_components": state.outdated_component_count,
        "total_vulnerabilities": len(state.vulnerabilities),
        "critical_vulns": state.critical_vuln_count,
        "weak_crypto": state.weak_crypto_count,
        "max_risk_score": state.max_risk_score,
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))
    await toolkit.record_metric(
        "total_images",
        float(state.total_extracted),
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing scan {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
