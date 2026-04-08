"""Node implementations for the Identity Protection Agent."""

from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import structlog

from shieldops.agents.identity_protection.models import (
    AttackPattern,
    ContainmentVerification,
    IdentityProtectionState,
    IdentitySignal,
    ReasoningStep,
    ThreatDetection,
    ThreatResponse,
)
from shieldops.agents.identity_protection.prompts import (
    SYSTEM_ATTACK_PATTERN_ANALYSIS,
    SYSTEM_CONTAINMENT_VERIFICATION,
    SYSTEM_RESPONSE_PLANNING,
    SYSTEM_THREAT_DETECTION,
    AttackPatternResult,
    ContainmentResult,
    ResponsePlanResult,
    ThreatAnalysisResult,
)
from shieldops.agents.identity_protection.tools import (
    IdentityProtectionToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IdentityProtectionToolkit | None = None


def _get_toolkit() -> IdentityProtectionToolkit:
    if _toolkit is None:
        return IdentityProtectionToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    delta = datetime.now(UTC) - start
    return int(delta.total_seconds() * 1000)


async def collect_identity_signals(
    state: IdentityProtectionState,
) -> dict[str, Any]:
    """Collect identity signals from all providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "identity_protection.collecting_signals",
        tenant=state.tenant_id,
        providers=state.providers,
    )

    raw_signals = await toolkit.collect_signals(
        tenant_id=state.tenant_id,
        providers=state.providers,
        time_window_minutes=state.time_window_minutes,
    )

    signals: list[IdentitySignal] = []
    for raw in raw_signals:
        signals.append(
            IdentitySignal(
                signal_id=raw.get(
                    "signal_id",
                    f"sig-{uuid4().hex[:8]}",
                ),
                source=raw.get("source", ""),
                identity_id=raw.get("identity_id", ""),
                identity_type=raw.get(
                    "identity_type",
                    "human",
                ),
                event_type=raw.get("event_type", ""),
                ip_address=raw.get("ip_address", ""),
                geo_location=raw.get("geo_location", ""),
                user_agent=raw.get("user_agent", ""),
                metadata=raw.get("metadata", {}),
            )
        )

    step = ReasoningStep(
        step_number=1,
        action="collect_identity_signals",
        input_summary=(f"Collecting from {len(state.providers)} providers for {state.tenant_id}"),
        output_summary=(f"Collected {len(signals)} signals"),
        duration_ms=_elapsed_ms(start),
        tool_used="multi_idp_collector",
    )

    return {
        "signals_collected": signals,
        "reasoning_chain": [step],
        "current_step": "collect_identity_signals",
        "session_start": start,
    }


async def detect_threats(
    state: IdentityProtectionState,
) -> dict[str, Any]:
    """Detect identity threats from collected signals."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "identity_protection.detecting_threats",
        signal_count=len(state.signals_collected),
    )

    # Convert signals to dicts for toolkit
    raw_signals = [s.model_dump() for s in state.signals_collected]

    # Run rule-based detectors
    it_detections = await toolkit.detect_impossible_travel(
        raw_signals,
    )
    bf_detections = await toolkit.detect_brute_force(
        raw_signals,
    )
    mf_detections = await toolkit.detect_mfa_fatigue(
        raw_signals,
    )
    cs_detections = await toolkit.detect_credential_stuffing(
        raw_signals,
    )

    all_rule_detections = it_detections + bf_detections + mf_detections + cs_detections

    # LLM-enhanced threat analysis
    context_lines = ["## Identity Signals"]
    for sig in state.signals_collected[:40]:
        context_lines.append(
            f"- [{sig.source}] {sig.identity_id}: "
            f"{sig.event_type} from {sig.ip_address} "
            f"({sig.geo_location})"
        )

    context_lines.append(f"\n## Rule-Based Detections ({len(all_rule_detections)})")
    for det in all_rule_detections[:20]:
        context_lines.append(
            f"- {det['threat_type']}: {det['identity_id']} (confidence={det['confidence']})"
        )

    user_prompt = "\n".join(context_lines)
    threats: list[ThreatDetection] = []

    try:
        result = cast(
            ThreatAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_THREAT_DETECTION,
                user_prompt=user_prompt,
                schema=ThreatAnalysisResult,
            ),
        )

        for threat_data in result.threats:
            threats.append(
                ThreatDetection(
                    detection_id=threat_data.get(
                        "detection_id",
                        f"det-{uuid4().hex[:8]}",
                    ),
                    threat_type=threat_data.get(
                        "threat_type",
                        "",
                    ),
                    identity_id=threat_data.get(
                        "identity_id",
                        "",
                    ),
                    source=threat_data.get("source", ""),
                    confidence=threat_data.get(
                        "confidence",
                        0.5,
                    ),
                    severity=threat_data.get(
                        "severity",
                        "medium",
                    ),
                    evidence=threat_data.get(
                        "evidence",
                        [],
                    ),
                    detected_at=datetime.now(UTC),
                )
            )

        output_summary = (
            f"LLM: {result.threat_summary[:120]}. Urgency: {result.recommended_urgency}"
        )
    except Exception as e:
        logger.error(
            "identity_protection.llm_detection_failed",
            error=str(e),
        )
        output_summary = f"LLM failed ({e}), using rule-based only"

        # Fallback: use rule-based detections
        for det in all_rule_detections:
            threats.append(
                ThreatDetection(
                    detection_id=det.get(
                        "detection_id",
                        f"det-{uuid4().hex[:8]}",
                    ),
                    threat_type=det.get(
                        "threat_type",
                        "",
                    ),
                    identity_id=det.get(
                        "identity_id",
                        "",
                    ),
                    confidence=det.get(
                        "confidence",
                        0.5,
                    ),
                    severity=det.get(
                        "severity",
                        "medium",
                    ),
                    evidence=(
                        [det["evidence"]]
                        if isinstance(
                            det.get("evidence"),
                            dict,
                        )
                        else det.get("evidence", [])
                    ),
                    detected_at=datetime.now(UTC),
                )
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_threats",
        input_summary=(f"Analyzing {len(state.signals_collected)} signals for threats"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="rule_engine + llm",
    )

    return {
        "threats_detected": threats,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_threats",
    }


async def analyze_attack_patterns(
    state: IdentityProtectionState,
) -> dict[str, Any]:
    """Analyze threats for multi-stage attack patterns."""
    start = datetime.now(UTC)

    logger.info(
        "identity_protection.analyzing_patterns",
        threat_count=len(state.threats_detected),
    )

    context_lines = ["## Detected Threats"]
    for threat in state.threats_detected[:30]:
        context_lines.append(
            f"- {threat.threat_type}: "
            f"{threat.identity_id} "
            f"(severity={threat.severity}, "
            f"confidence={threat.confidence})"
        )

    context_lines.append("\n## Signal Timeline")
    for sig in state.signals_collected[:30]:
        context_lines.append(
            f"- [{sig.source}] {sig.identity_id}: {sig.event_type} @ {sig.ip_address}"
        )

    user_prompt = "\n".join(context_lines)
    patterns: list[AttackPattern] = []

    try:
        result = cast(
            AttackPatternResult,
            await llm_structured(
                system_prompt=(SYSTEM_ATTACK_PATTERN_ANALYSIS),
                user_prompt=user_prompt,
                schema=AttackPatternResult,
            ),
        )

        for pat_data in result.patterns:
            patterns.append(
                AttackPattern(
                    pattern_id=pat_data.get(
                        "pattern_id",
                        f"pat-{uuid4().hex[:8]}",
                    ),
                    pattern_type=pat_data.get(
                        "pattern_type",
                        "",
                    ),
                    kill_chain_stage=pat_data.get(
                        "kill_chain_stage",
                        "",
                    ),
                    identities_involved=pat_data.get(
                        "identities_involved",
                        [],
                    ),
                    providers_affected=pat_data.get(
                        "providers_affected",
                        [],
                    ),
                    risk_score=pat_data.get(
                        "risk_score",
                        50.0,
                    ),
                    description=pat_data.get(
                        "description",
                        "",
                    ),
                )
            )

        output_summary = (
            f"LLM: {result.kill_chain_summary[:120]}. Next predicted: {result.predicted_next_stage}"
        )
    except Exception as e:
        logger.error(
            "identity_protection.pattern_analysis_failed",
            error=str(e),
        )
        output_summary = f"Pattern analysis failed: {e}"

        # Fallback: group threats by identity
        identity_threats: dict[str, list[str]] = {}
        for t in state.threats_detected:
            identity_threats.setdefault(
                t.identity_id,
                [],
            ).append(t.threat_type)

        for iid, ttypes in identity_threats.items():
            if len(ttypes) >= 2:
                patterns.append(
                    AttackPattern(
                        pattern_id=(f"pat-{uuid4().hex[:8]}"),
                        pattern_type="multi_vector",
                        kill_chain_stage="lateral_movement",
                        identities_involved=[iid],
                        risk_score=75.0,
                        description=(f"Multi-vector attack: {', '.join(ttypes)}"),
                    )
                )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_attack_patterns",
        input_summary=(f"Analyzing {len(state.threats_detected)} threats for attack chains"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm",
    )

    return {
        "attack_patterns": patterns,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_attack_patterns",
    }


async def respond_to_threats(
    state: IdentityProtectionState,
) -> dict[str, Any]:
    """Execute automated response actions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "identity_protection.responding",
        threat_count=len(state.threats_detected),
        pattern_count=len(state.attack_patterns),
    )

    # Build context for LLM response planning
    context_lines = ["## Active Threats"]
    for threat in state.threats_detected[:20]:
        context_lines.append(
            f"- {threat.threat_type}: {threat.identity_id} (severity={threat.severity})"
        )

    context_lines.append(f"\n## Attack Patterns ({len(state.attack_patterns)})")
    for pat in state.attack_patterns[:10]:
        context_lines.append(f"- {pat.pattern_type}: {pat.description[:80]}")

    user_prompt = "\n".join(context_lines)
    responses: list[ThreatResponse] = []
    protected: list[str] = []

    try:
        result = cast(
            ResponsePlanResult,
            await llm_structured(
                system_prompt=SYSTEM_RESPONSE_PLANNING,
                user_prompt=user_prompt,
                schema=ResponsePlanResult,
            ),
        )

        for action_data in result.actions:
            action_type = action_data.get(
                "action_type",
                "revoke_sessions",
            )
            target_id = action_data.get(
                "target_identity",
                "",
            )
            provider = action_data.get(
                "target_provider",
                "",
            )

            # Execute the response
            if action_type == "disable_account":
                resp = await toolkit.disable_account(
                    target_id,
                    provider,
                )
            elif action_type == "force_mfa":
                resp = await toolkit.force_mfa_reenrollment(
                    target_id,
                    provider,
                )
            elif action_type == "block_ip":
                resp = await toolkit.block_ip(target_id)
            else:
                resp = await toolkit.revoke_sessions(
                    target_id,
                    provider,
                )

            responses.append(
                ThreatResponse(
                    response_id=resp.get(
                        "response_id",
                        f"resp-{uuid4().hex[:8]}",
                    ),
                    action_type=action_type,
                    target_identity=target_id,
                    target_provider=provider,
                    status=resp.get("status", "executed"),
                    executed_at=datetime.now(UTC),
                )
            )
            protected.append(target_id)

        output_summary = (
            f"Executed {len(responses)} responses. "
            f"Est. containment: "
            f"{result.estimated_containment_time_min}min"
        )
    except Exception as e:
        logger.error(
            "identity_protection.response_failed",
            error=str(e),
        )
        output_summary = f"Response planning failed: {e}"

        # Fallback: revoke sessions for critical threats
        for threat in state.threats_detected:
            if threat.severity in ("critical", "high"):
                resp = await toolkit.revoke_sessions(
                    threat.identity_id,
                    threat.source or "unknown",
                )
                responses.append(
                    ThreatResponse(
                        response_id=resp.get(
                            "response_id",
                            f"resp-{uuid4().hex[:8]}",
                        ),
                        action_type="revoke_sessions",
                        target_identity=threat.identity_id,
                        target_provider=(threat.source or "unknown"),
                        status="executed",
                        executed_at=datetime.now(UTC),
                    )
                )
                protected.append(threat.identity_id)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="respond_to_threats",
        input_summary=(f"Responding to {len(state.threats_detected)} threats"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="response_orchestrator + llm",
    )

    return {
        "responses_executed": responses,
        "identities_protected": list(set(protected)),
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "respond_to_threats",
    }


async def verify_containment(
    state: IdentityProtectionState,
) -> dict[str, Any]:
    """Verify that response actions contained threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "identity_protection.verifying_containment",
        response_count=len(state.responses_executed),
    )

    verifications: list[ContainmentVerification] = []

    for response in state.responses_executed:
        raw = await toolkit.verify_containment(
            identity_id=response.target_identity,
            provider=response.target_provider,
            action_type=response.action_type,
        )

        verifications.append(
            ContainmentVerification(
                verification_id=raw.get(
                    "verification_id",
                    f"ver-{uuid4().hex[:8]}",
                ),
                response_id=response.response_id,
                identity_id=response.target_identity,
                is_contained=raw.get(
                    "is_contained",
                    False,
                ),
                residual_risk=raw.get(
                    "residual_risk",
                    50.0,
                ),
                verification_checks=raw.get(
                    "verification_checks",
                    [],
                ),
                verified_at=datetime.now(UTC),
            )
        )

    contained = sum(1 for v in verifications if v.is_contained)
    not_contained = len(verifications) - contained

    # LLM containment assessment if uncontained
    if not_contained > 0:
        context_lines = [
            "## Containment Verification Results",
        ]
        for v in verifications:
            context_lines.append(
                f"- {v.identity_id}: contained={v.is_contained}, residual_risk={v.residual_risk}"
            )

        user_prompt = "\n".join(context_lines)
        try:
            llm_result = cast(
                ContainmentResult,
                await llm_structured(
                    system_prompt=(SYSTEM_CONTAINMENT_VERIFICATION),
                    user_prompt=user_prompt,
                    schema=ContainmentResult,
                ),
            )
            if llm_result.requires_escalation:
                logger.warning(
                    "identity_protection.escalation_needed",
                    summary=(llm_result.verification_summary),
                )
        except Exception as e:
            logger.error(
                "identity_protection.verify_llm_failed",
                error=str(e),
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="verify_containment",
        input_summary=(f"Verifying {len(state.responses_executed)} response actions"),
        output_summary=(
            f"{contained}/{len(verifications)} contained, {not_contained} require follow-up"
        ),
        duration_ms=_elapsed_ms(start),
        tool_used="containment_verifier",
    )

    return {
        "containment_verified": verifications,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "verify_containment",
    }


async def report(
    state: IdentityProtectionState,
) -> dict[str, Any]:
    """Generate final protection report."""
    start = datetime.now(UTC)

    contained = sum(1 for v in state.containment_verified if v.is_contained)

    output_summary = (
        f"Protection complete: "
        f"{len(state.signals_collected)} signals, "
        f"{len(state.threats_detected)} threats, "
        f"{len(state.attack_patterns)} patterns, "
        f"{len(state.responses_executed)} responses, "
        f"{contained}/{len(state.containment_verified)}"
        f" contained"
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary=("Compiling identity protection report"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
    )

    session_duration = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        session_duration = int(
            delta.total_seconds() * 1000,
        )

    return {
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
        "session_duration_ms": session_duration,
    }
