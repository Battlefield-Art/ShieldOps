"""Evidence Automation Engine Agent — Node implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import EAEStage
from .tools import EvidenceAutomationEngineToolkit

logger = structlog.get_logger()

_toolkit: EvidenceAutomationEngineToolkit | None = None


def _get_toolkit() -> EvidenceAutomationEngineToolkit:
    if _toolkit is None:
        return EvidenceAutomationEngineToolkit()
    return _toolkit


class _LLMValidationInsight(BaseModel):
    """LLM-generated validation insight."""

    quality_issues: list[str] = Field(
        description="Evidence quality issues found",
    )
    coverage_gaps: list[str] = Field(
        description="Missing evidence coverage areas",
    )
    recommendation: str = Field(
        description="Overall evidence readiness",
    )


async def identify_requirements(
    state: dict[str, Any],
    toolkit: EvidenceAutomationEngineToolkit,
) -> dict[str, Any]:
    """Identify evidence requirements."""
    logger.info("eae.node.identify_requirements")

    frameworks = state.get(
        "frameworks",
        ["soc2", "hipaa", "pci_dss"],
    )
    reqs = await toolkit.identify_requirements(frameworks)

    return {
        "stage": EAEStage.COLLECT_EVIDENCE.value,
        "requirements": reqs,
        "total_requirements": len(reqs),
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Identified {len(reqs)} requirements across {len(frameworks)} frameworks"],
    }


async def collect_evidence(
    state: dict[str, Any],
    toolkit: EvidenceAutomationEngineToolkit,
) -> dict[str, Any]:
    """Collect evidence for all requirements."""
    logger.info("eae.node.collect_evidence")
    reqs = state.get("requirements", [])

    artifacts: list[dict[str, Any]] = []
    for req in reqs:
        artifact = await toolkit.collect_evidence(req)
        artifacts.append(artifact)

    return {
        "stage": EAEStage.VALIDATE_ARTIFACTS.value,
        "artifacts": artifacts,
        "artifacts_collected": len(artifacts),
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Collected {len(artifacts)} artifacts for {len(reqs)} requirements"],
    }


async def validate_artifacts(
    state: dict[str, Any],
    toolkit: EvidenceAutomationEngineToolkit,
) -> dict[str, Any]:
    """Validate collected evidence artifacts."""
    logger.info("eae.node.validate_artifacts")
    artifacts = state.get("artifacts", [])

    validated: list[dict[str, Any]] = []
    verified = 0
    rejected = 0
    for art in artifacts:
        result = toolkit.validate_artifact(art)
        validated.append(result)
        if result.get("status") == "verified":
            verified += 1
        elif result.get("status") in (
            "rejected",
            "expired",
            "incomplete",
        ):
            rejected += 1

    llm_note = ""
    try:
        summary = "\n".join(f"- {a.get('id')}: {a.get('status')}" for a in validated[:20])
        result_llm = await llm_structured(
            system_prompt=(
                "You are an evidence validation analyst. "
                "Assess the quality and completeness of "
                "compliance evidence artifacts."
            ),
            user_prompt=f"Artifacts:\n{summary}",
            schema=_LLMValidationInsight,
        )
        if isinstance(result_llm, _LLMValidationInsight):
            llm_note = f" LLM: {result_llm.recommendation}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="eae",
            node="validate",
        )

    note = f"Validated {len(validated)}: {verified} verified, {rejected} rejected"
    return {
        "stage": EAEStage.PACKAGE_EVIDENCE.value,
        "artifacts": validated,
        "artifacts_verified": verified,
        "artifacts_rejected": rejected,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [note + llm_note],
    }


async def package_evidence(
    state: dict[str, Any],
    toolkit: EvidenceAutomationEngineToolkit,
) -> dict[str, Any]:
    """Package evidence for attestation submission."""
    logger.info("eae.node.package_evidence")
    artifacts = state.get("artifacts", [])

    # Group by framework from requirements
    reqs = state.get("requirements", [])
    req_map: dict[str, str] = {}
    for req in reqs:
        req_map[req.get("id", "")] = req.get(
            "framework",
            "",
        )

    frameworks: set[str] = set()
    for art in artifacts:
        fw = req_map.get(
            art.get("requirement_id", ""),
            "",
        )
        if fw:
            frameworks.add(fw)

    return {
        "stage": EAEStage.SUBMIT_ATTESTATION.value,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Packaged evidence for {len(frameworks)} frameworks"],
    }


async def submit_attestation(
    state: dict[str, Any],
    toolkit: EvidenceAutomationEngineToolkit,
) -> dict[str, Any]:
    """Submit attestation for each framework."""
    logger.info("eae.node.submit_attestation")
    artifacts = state.get("artifacts", [])
    reqs = state.get("requirements", [])

    req_fw: dict[str, str] = {}
    for req in reqs:
        req_fw[req.get("id", "")] = req.get(
            "framework",
            "",
        )

    by_fw: dict[str, list[dict[str, Any]]] = {}
    for art in artifacts:
        fw = req_fw.get(
            art.get("requirement_id", ""),
            "unknown",
        )
        by_fw.setdefault(fw, []).append(art)

    attestations: list[dict[str, Any]] = []
    for fw, fw_arts in by_fw.items():
        att = await toolkit.submit_attestation(
            fw,
            fw_arts,
        )
        attestations.append(att)

    return {
        "stage": EAEStage.REPORT.value,
        "attestations": attestations,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Submitted {len(attestations)} attestations"],
    }


async def report(
    state: dict[str, Any],
    toolkit: EvidenceAutomationEngineToolkit,
) -> dict[str, Any]:
    """Generate evidence collection report."""
    logger.info("eae.node.report")

    rpt = toolkit.generate_report(
        requirements=state.get("requirements", []),
        artifacts=state.get("artifacts", []),
        attestations=state.get("attestations", []),
    )

    return {
        "stage": EAEStage.REPORT.value,
        "report": rpt,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            f"Report: {rpt.get('artifacts_verified')} verified, {rpt.get('coverage_pct')}% coverage"
        ],
    }
