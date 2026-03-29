"""PCI Scanner Agent — Node function implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import PCIStage
from .tools import PCIScannerToolkit

logger = structlog.get_logger()

_toolkit: PCIScannerToolkit | None = None


def _get_toolkit() -> PCIScannerToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = PCIScannerToolkit()
    return _toolkit


class _LLMPCIAnalysis(BaseModel):
    """LLM-generated PCI DSS compliance analysis."""

    critical_findings: list[str] = Field(
        description="Critical PCI DSS compliance findings",
    )
    scope_gaps: list[str] = Field(
        description="Gaps in CDE scope definition",
    )
    remediation_priority: str = Field(
        description="Overall remediation priority assessment",
    )


async def map_cde(
    state: dict[str, Any],
    toolkit: PCIScannerToolkit,
) -> dict[str, Any]:
    """Map the Cardholder Data Environment."""
    logger.info("pci_scanner.node.map_cde")
    tenant_id = state.get("tenant_id", "")
    assets = await toolkit.map_cde(tenant_id)

    return {
        "stage": PCIStage.REQUIREMENT_CHECK.value,
        "cde_assets": assets,
        "assets_scanned": len(assets),
        "reasoning_chain": state.get("reasoning_chain", []) + [f"Mapped {len(assets)} CDE assets"],
    }


async def check_requirements(
    state: dict[str, Any],
    toolkit: PCIScannerToolkit,
) -> dict[str, Any]:
    """Check PCI DSS requirements."""
    logger.info("pci_scanner.node.check_requirements")
    cde_assets = state.get("cde_assets", [])
    checks = await toolkit.check_requirements(cde_assets)

    passed = sum(1 for c in checks if c.get("status") == "passed")
    failed = sum(1 for c in checks if c.get("status") == "failed")

    return {
        "stage": PCIStage.ASV_SCAN.value,
        "requirement_checks": checks,
        "requirements_passed": passed,
        "requirements_failed": failed,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Checked {len(checks)} requirements: {passed} passed, {failed} failed"],
    }


async def run_asv_scan(
    state: dict[str, Any],
    toolkit: PCIScannerToolkit,
) -> dict[str, Any]:
    """Run ASV vulnerability scans with LLM analysis."""
    logger.info("pci_scanner.node.asv_scan")
    cde_assets = state.get("cde_assets", [])
    asv_results = await toolkit.run_asv_scan(cde_assets)

    llm_text = ""
    try:
        checks = state.get("requirement_checks", [])
        summary = "\n".join(
            f"- {c.get('check_id')}: {c.get('status')}, findings={c.get('findings', [])}"
            for c in checks[:20]
        )
        analysis = await llm_structured(
            system_prompt=(
                "You are a PCI QSA. Analyze requirement check results "
                "and ASV scan data for compliance gaps."
            ),
            user_prompt=(f"Requirements:\n{summary}\n\nASV scans: {len(asv_results)} completed"),
            schema=_LLMPCIAnalysis,
        )
        if isinstance(analysis, _LLMPCIAnalysis):
            llm_text = (
                f"LLM priority: {analysis.remediation_priority}. "
                f"Critical: {len(analysis.critical_findings)}."
            )
    except Exception:
        logger.debug("llm_fallback", agent="pci_scanner", node="asv")

    msg = f"ASV scanned {len(asv_results)} assets"
    if llm_text:
        msg += f" | {llm_text}"

    return {
        "stage": PCIStage.SAQ_COMPLETION.value,
        "asv_results": asv_results,
        "reasoning_chain": state.get("reasoning_chain", []) + [msg],
    }


async def complete_saq(
    state: dict[str, Any],
    toolkit: PCIScannerToolkit,
) -> dict[str, Any]:
    """Complete the Self-Assessment Questionnaire."""
    logger.info("pci_scanner.node.complete_saq")
    checks = state.get("requirement_checks", [])
    saq = await toolkit.complete_saq(checks)

    return {
        "stage": PCIStage.GENERATE_REPORT.value,
        "saq_answers": saq,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Completed SAQ with {len(saq)} answers"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: PCIScannerToolkit,
) -> dict[str, Any]:
    """Generate PCI DSS compliance report."""
    logger.info("pci_scanner.node.generate_report")
    report = toolkit.generate_pci_report(
        cde_assets=state.get("cde_assets", []),
        checks=state.get("requirement_checks", []),
        asv_results=state.get("asv_results", []),
        saq_answers=state.get("saq_answers", []),
    )

    return {
        "stage": PCIStage.GENERATE_REPORT.value,
        "report": report,
        "compliance_score": report.get("compliance_score", 0.0),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report generated: score={report.get('compliance_score', 0)}, "
            f"{report.get('requirements_checked', 0)} requirements"
        ],
    }
