"""Node implementations for the Trust Relationship Mapper Agent."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.trust_relationship_mapper.models import (
    ReasoningStep,
    TrustStage,
)
from shieldops.agents.trust_relationship_mapper.prompts import (
    SYSTEM_ABUSE,
    SYSTEM_DELEGATION,
    SYSTEM_FEDERATION,
    SYSTEM_REPORT,
    SYSTEM_RISK,
    AbuseDetectionOutput,
    DelegationAnalysisOutput,
    FederationAnalysisOutput,
    RiskAssessmentOutput,
    TrustReportOutput,
)
from shieldops.agents.trust_relationship_mapper.tools import (
    TrustRelationshipMapperToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: TrustRelationshipMapperToolkit | None = None


def set_toolkit(
    toolkit: TrustRelationshipMapperToolkit,
) -> None:
    """Set the global toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> TrustRelationshipMapperToolkit:
    if _toolkit is None:
        return TrustRelationshipMapperToolkit()
    return _toolkit


async def discover_trust_boundaries(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Discover trust boundaries across infra."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    boundaries = await toolkit.discover_trust_boundaries(
        tenant_id=state.get("tenant_id", ""),
        scope=state.get("scope", "all"),
    )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="discover_trust_boundaries",
        input_summary=(f"tenant={state.get('tenant_id', '')}"),
        output_summary=(f"Discovered {len(boundaries)} trust boundaries"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="discover_trust_boundaries",
    )

    return {
        "trust_boundaries": boundaries,
        "total_boundaries": len(boundaries),
        "current_stage": (TrustStage.DISCOVER_TRUST_BOUNDARIES),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def map_federation(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Map federation relationships."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mappings = await toolkit.map_federation(
        state.get("trust_boundaries", []),
    )

    # LLM enrichment
    for fed in mappings:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_FEDERATION,
                user_prompt=(
                    f"Source IdP: {fed.source_idp}\n"
                    f"Target SP: {fed.target_sp}\n"
                    f"Protocol: {fed.protocol}\n"
                    f"Tokens 30d: "
                    f"{fed.token_count_30d}"
                ),
                output_schema=(FederationAnalysisOutput),
            )
            fed.risk_score = result.risk_score
        except Exception:
            logger.warning(
                "trust_mapper.llm_federation_fallback",
                federation_id=fed.id,
            )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="map_federation",
        input_summary=(f"{len(state.get('trust_boundaries', []))} boundaries"),
        output_summary=(f"Mapped {len(mappings)} federations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="map_federation",
    )

    return {
        "federation_mappings": mappings,
        "current_stage": (TrustStage.MAP_FEDERATION),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def analyze_delegation_chains(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Analyze delegation chains."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    chains = await toolkit.analyze_delegation_chains(
        state.get("trust_boundaries", []),
    )

    # LLM enrichment
    for chain in chains:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_DELEGATION,
                user_prompt=(
                    f"Depth: {chain.chain_depth}\n"
                    f"Principals: "
                    f"{', '.join(chain.principals)}\n"
                    f"Transitive: "
                    f"{chain.is_transitive}"
                ),
                output_schema=(DelegationAnalysisOutput),
            )
            chain.effective_permissions = result.effective_permissions
            chain.risk_score = result.risk_score
        except Exception:
            logger.warning(
                "trust_mapper.llm_delegation_fallback",
                chain_id=chain.id,
            )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="analyze_delegation_chains",
        input_summary=(f"{len(state.get('trust_boundaries', []))} boundaries"),
        output_summary=(f"Analyzed {len(chains)} delegation chains"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="analyze_delegation_chains",
    )

    return {
        "delegation_chains": chains,
        "current_stage": (TrustStage.ANALYZE_DELEGATION_CHAINS),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def detect_trust_abuse(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Detect trust abuse indicators."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    abuses = await toolkit.detect_trust_abuse(
        boundaries=state.get("trust_boundaries", []),
        federations=state.get("federation_mappings", []),
        chains=state.get("delegation_chains", []),
    )

    # LLM enrichment
    for abuse in abuses:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_ABUSE,
                user_prompt=(
                    f"Indicator: {abuse.indicator}\n"
                    f"Severity: {abuse.severity}\n"
                    f"Description: "
                    f"{abuse.description}"
                ),
                output_schema=(AbuseDetectionOutput),
            )
            abuse.description = result.description
            abuse.recommended_action = result.recommended_action
        except Exception:
            logger.warning(
                "trust_mapper.llm_abuse_fallback",
                abuse_id=abuse.id,
            )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="detect_trust_abuse",
        input_summary=(f"{len(state.get('trust_boundaries', []))} boundaries"),
        output_summary=(f"Detected {len(abuses)} abuse indicators"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="detect_trust_abuse",
    )

    return {
        "trust_abuses": abuses,
        "total_abuses_detected": len(abuses),
        "current_stage": (TrustStage.DETECT_TRUST_ABUSE),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def assess_risk(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Assess risk for trust relationships."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_trust_risk(
        boundaries=state.get("trust_boundaries", []),
        abuses=state.get("trust_abuses", []),
    )

    # LLM enrichment
    for assessment in assessments:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_RISK,
                user_prompt=(
                    f"Risk: {assessment.overall_risk}"
                    f"\nFactors: "
                    f"{', '.join(assessment.risk_factors)}"
                    f"\nPriority: "
                    f"{assessment.remediation_priority}"
                ),
                output_schema=(RiskAssessmentOutput),
            )
            assessment.overall_risk = result.overall_risk
            assessment.recommendation = result.recommendation
        except Exception:
            logger.warning(
                "trust_mapper.llm_risk_fallback",
                assessment_id=assessment.id,
            )

    avg_risk = 0.0
    if assessments:
        avg_risk = sum(a.overall_risk for a in assessments) / len(assessments)

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="assess_risk",
        input_summary=(f"{len(state.get('trust_boundaries', []))} boundaries"),
        output_summary=(f"Assessed {len(assessments)} risks, avg={avg_risk:.2f}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="assess_trust_risk",
    )

    return {
        "risk_assessments": assessments,
        "avg_risk_score": avg_risk,
        "current_stage": TrustStage.ASSESS_RISK,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def generate_report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate the final trust mapping report."""
    start = datetime.now(UTC)

    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Boundaries: "
                f"{state.get('total_boundaries', 0)}"
                f"\nAbuses: "
                f"{state.get('total_abuses_detected', 0)}"
                f"\nAvg risk: "
                f"{state.get('avg_risk_score', 0):.2f}"
            ),
            output_schema=TrustReportOutput,
        )
        _ = result.executive_summary
    except Exception:
        logger.warning("trust_mapper.llm_report_fallback")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="generate_report",
        input_summary=(f"{state.get('total_boundaries', 0)} boundaries"),
        output_summary="Report generated",
        duration_ms=elapsed,
        tool_used="llm_structured",
    )

    chain = state.get("reasoning_chain", [])
    total_ms = (
        sum(s.duration_ms if hasattr(s, "duration_ms") else s.get("duration_ms", 0) for s in chain)
        + elapsed
    )

    return {
        "current_stage": TrustStage.REPORT,
        "reasoning_chain": [*chain, step],
        "session_duration_ms": total_ms,
    }
