"""Node implementations for the Breakout Defender Agent LangGraph workflow."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.breakout_defender.models import (
    BreakoutDefenderState,
    BreakoutReport,
    BreakoutSignal,
    ContainmentOrder,
    DefenseReasoningStep,
    LateralMovementPath,
)
from shieldops.agents.breakout_defender.prompts import (
    SYSTEM_ASSESS_RISK,
    SYSTEM_DETECT,
    SYSTEM_VERIFY,
    BreakoutRiskOutput,
    ContainmentVerifyOutput,
    InitialAccessOutput,
)
from shieldops.agents.breakout_defender.tools import (
    BreakoutDefenderToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: BreakoutDefenderToolkit | None = None


def _get_toolkit() -> BreakoutDefenderToolkit:
    if _toolkit is None:
        return BreakoutDefenderToolkit()
    return _toolkit


def _elapsed_seconds(
    start: datetime | None,
) -> float:
    """Calculate elapsed seconds from start."""
    if not start:
        return 0.0
    delta = datetime.now(UTC) - start
    return round(delta.total_seconds(), 2)


async def detect_initial_access(
    state: BreakoutDefenderState,
) -> dict[str, Any]:
    """Detect initial access indicators from signals."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_initial_access_signals(
        state.incoming_signals,
    )
    signals = [BreakoutSignal(**s) for s in raw if isinstance(s, dict)]

    detected_phase = "initial_access"
    mitre_techniques: list[str] = []

    # LLM: classify kill chain phase
    try:
        import json as _json

        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "signal_count": len(signals),
                "signals": [s.model_dump() for s in signals[:20]],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT,
            user_prompt=(f"Analyze these signals for breakout indicators:\n{context}"),
            schema=InitialAccessOutput,
        )
        if hasattr(llm_result, "phase_detected"):
            detected_phase = llm_result.phase_detected
        if hasattr(llm_result, "mitre_techniques"):
            mitre_techniques = llm_result.mitre_techniques
        logger.info(
            "llm_enhanced",
            node="detect_initial_access",
            phase=detected_phase,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_initial_access",
        )

    step = DefenseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_initial_access",
        input_summary=(f"Analyzing {len(state.incoming_signals)} raw signals"),
        output_summary=(f"Detected {len(signals)} signals, phase={detected_phase}"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="signal_collector",
    )

    # Update signals with MITRE techniques
    for sig in signals:
        if not sig.mitre_tactic and mitre_techniques:
            sig.mitre_technique = mitre_techniques[0]

    await toolkit.record_defense_metric(
        "signals_detected",
        float(len(signals)),
    )

    return {
        "signals": signals,
        "initial_access_detected": len(signals) > 0,
        "detected_phase": detected_phase,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_initial_access",
        "session_start": start,
    }


async def analyze_lateral_movement(
    state: BreakoutDefenderState,
) -> dict[str, Any]:
    """Analyze signals for lateral movement paths."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    signal_dicts = [s.model_dump() for s in state.signals]
    raw_paths = await toolkit.analyze_lateral_paths(
        signal_dicts,
    )
    paths = [LateralMovementPath(**p) for p in raw_paths if isinstance(p, dict)]

    cross_cloud = any(p.is_cross_cloud for p in paths)

    step = DefenseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_lateral_movement",
        input_summary=(f"Analyzing {len(state.signals)} signals for lateral movement"),
        output_summary=(f"Found {len(paths)} paths, cross_cloud={cross_cloud}"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="lateral_analyzer",
    )

    await toolkit.record_defense_metric(
        "lateral_paths",
        float(len(paths)),
    )

    return {
        "paths": paths,
        "cross_cloud_detected": cross_cloud,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_lateral_movement",
    }


async def assess_breakout_risk(
    state: BreakoutDefenderState,
) -> dict[str, Any]:
    """Assess the overall breakout risk and decide containment."""
    start = datetime.now(UTC)

    # Heuristic risk scoring
    base_risk = 0.0
    phase_weights = {
        "initial_access": 20.0,
        "privilege_escalation": 40.0,
        "lateral_movement": 60.0,
        "data_staging": 80.0,
        "exfiltration": 95.0,
    }
    base_risk = phase_weights.get(
        state.detected_phase,
        30.0,
    )

    # Boost for lateral movement
    if state.paths:
        base_risk += min(len(state.paths) * 5.0, 20.0)

    # Boost for cross-cloud
    if state.cross_cloud_detected:
        base_risk += 15.0

    risk_score = min(base_risk, 100.0)
    est_breakout = max(
        30.0 - (risk_score / 100.0) * 25.0,
        2.0,
    )
    # Auto-contain if risk > 85
    auto_contain = risk_score >= 85.0

    # LLM: refine risk assessment
    try:
        import json as _json

        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "detected_phase": state.detected_phase,
                "signal_count": len(state.signals),
                "lateral_paths": len(state.paths),
                "cross_cloud": state.cross_cloud_detected,
                "heuristic_risk": risk_score,
                "paths": [p.model_dump() for p in state.paths[:10]],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS_RISK,
            user_prompt=(f"Assess breakout risk:\n{context}"),
            schema=BreakoutRiskOutput,
        )
        if hasattr(llm_result, "risk_score"):
            risk_score = round(
                (risk_score + llm_result.risk_score) / 2,
                2,
            )
        if hasattr(llm_result, "auto_contain"):
            auto_contain = llm_result.auto_contain
        if hasattr(
            llm_result,
            "estimated_breakout_minutes",
        ):
            est_breakout = round(
                (est_breakout + llm_result.estimated_breakout_minutes) / 2,
                2,
            )
        logger.info(
            "llm_enhanced",
            node="assess_breakout_risk",
            risk=risk_score,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_breakout_risk",
        )

    step = DefenseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_breakout_risk",
        input_summary=(f"Phase={state.detected_phase}, paths={len(state.paths)}"),
        output_summary=(
            f"Risk={risk_score}, auto_contain={auto_contain}, est_breakout={est_breakout}min"
        ),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used=None,
    )

    return {
        "breakout_risk_score": risk_score,
        "estimated_breakout_time_minutes": est_breakout,
        "auto_contain": auto_contain,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_breakout_risk",
    }


async def execute_containment(
    state: BreakoutDefenderState,
) -> dict[str, Any]:
    """Execute containment actions to stop breakout."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    orders: list[ContainmentOrder] = []

    # Build containment orders from signals + paths
    compromised_hosts: set[str] = set()
    compromised_identities: set[str] = set()

    for sig in state.signals:
        if sig.hostname:
            compromised_hosts.add(sig.hostname)
        if sig.user_identity:
            compromised_identities.add(
                sig.user_identity,
            )

    for host in compromised_hosts:
        cloud = ""
        for sig in state.signals:
            if sig.hostname == host:
                cloud = sig.cloud_provider
                break
        orders.append(
            ContainmentOrder(
                order_id=f"co-{uuid4().hex[:8]}",
                action="isolate_host",
                target=host,
                target_type="host",
                cloud_provider=cloud,
                reason=(f"Breakout signal on {host} phase={state.detected_phase}"),
                confidence=state.breakout_risk_score / 100,
                requires_approval=not state.auto_contain,
            )
        )

    for identity in compromised_identities:
        orders.append(
            ContainmentOrder(
                order_id=f"co-{uuid4().hex[:8]}",
                action="revoke_credentials",
                target=identity,
                target_type="identity",
                reason=(f"Compromised identity: {identity}"),
                confidence=state.breakout_risk_score / 100,
                requires_approval=not state.auto_contain,
            )
        )

    # Block cross-cloud paths
    for path in state.paths:
        if path.is_cross_cloud:
            orders.append(
                ContainmentOrder(
                    order_id=f"co-{uuid4().hex[:8]}",
                    action="block_network",
                    target=(f"{path.source_host}->{path.target_host}"),
                    target_type="network_path",
                    cloud_provider=path.source_cloud,
                    reason=(f"Cross-cloud pivot: {path.source_cloud}->{path.target_cloud}"),
                    confidence=path.risk_score / 100,
                    requires_approval=not state.auto_contain,
                )
            )

    # Execute orders that don't require approval
    executable = [o.model_dump() for o in orders if not o.requires_approval]
    results = await toolkit.execute_containment(
        executable,
    )

    # Update orders with execution results
    result_map = {r.get("order_id", ""): r for r in results}
    for order in orders:
        if order.order_id in result_map:
            r = result_map[order.order_id]
            order.executed = r.get("executed", False)
            order.result = r.get("result", "")
            order.execution_time_ms = r.get(
                "execution_time_ms",
                0,
            )

    ttc = _elapsed_seconds(state.session_start)

    step = DefenseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_containment",
        input_summary=(
            f"Containing {len(compromised_hosts)} hosts, {len(compromised_identities)} identities"
        ),
        output_summary=(f"Executed {len(executable)} orders, ttc={ttc}s"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="containment_engine",
    )

    await toolkit.record_defense_metric(
        "containment_orders",
        float(len(orders)),
    )
    await toolkit.record_defense_metric(
        "time_to_contain_seconds",
        ttc,
    )

    return {
        "containment_orders": orders,
        "containment_executed": len(executable) > 0,
        "time_to_contain_seconds": ttc,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "execute_containment",
    }


async def verify_containment(
    state: BreakoutDefenderState,
) -> dict[str, Any]:
    """Verify containment actions are effective."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    order_dicts = [o.model_dump() for o in state.containment_orders]
    verification = await toolkit.verify_containment_status(
        order_dicts,
    )

    verified = verification.get("verified", False)
    residual = 0.0

    # LLM: deeper verification analysis
    try:
        import json as _json

        context = _json.dumps(
            {
                "orders": order_dicts[:15],
                "verification": verification,
                "detected_phase": state.detected_phase,
                "cross_cloud": state.cross_cloud_detected,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VERIFY,
            user_prompt=(f"Verify containment:\n{context}"),
            schema=ContainmentVerifyOutput,
        )
        if hasattr(llm_result, "verified"):
            verified = llm_result.verified
        if hasattr(llm_result, "residual_risk"):
            residual = llm_result.residual_risk
        logger.info(
            "llm_enhanced",
            node="verify_containment",
            verified=verified,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="verify_containment",
        )

    step = DefenseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="verify_containment",
        input_summary=(f"Verifying {len(state.containment_orders)} orders"),
        output_summary=(f"Verified={verified}, residual_risk={residual}"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="containment_verifier",
    )

    return {
        "containment_verified": verified,
        "residual_risk": residual,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "verify_containment",
    }


async def report(
    state: BreakoutDefenderState,
) -> dict[str, Any]:
    """Generate final breakout defense report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    ttc = state.time_to_contain_seconds
    prevented = (
        state.containment_verified and ttc < 300.0  # Under 5 minutes
    )

    # Collect MITRE techniques
    mitre: list[str] = list({s.mitre_technique for s in state.signals if s.mitre_technique})

    executed_count = sum(1 for o in state.containment_orders if o.executed)

    ttd = 0.0
    if state.reasoning_chain:
        detect_step = next(
            (s for s in state.reasoning_chain if s.action == "detect_initial_access"),
            None,
        )
        if detect_step:
            ttd = detect_step.duration_ms / 1000.0

    summary = (
        f"Breakout defense engagement for "
        f"{state.tenant_id}: "
        f"{'PREVENTED' if prevented else 'ACTIVE'}. "
        f"Detected phase={state.detected_phase}, "
        f"{len(state.signals)} signals, "
        f"{len(state.paths)} lateral paths, "
        f"{executed_count} containment actions. "
        f"Time to contain: {ttc:.1f}s "
        f"(target: <300s)."
    )

    defense_report = BreakoutReport(
        report_id=f"br-{uuid4().hex[:12]}",
        tenant_id=state.tenant_id,
        breakout_prevented=prevented,
        initial_phase_detected=state.detected_phase,
        furthest_phase_reached=state.detected_phase,
        time_to_detect_seconds=ttd,
        time_to_contain_seconds=ttc,
        signals_analyzed=len(state.signals),
        lateral_paths_found=len(state.paths),
        containment_actions_taken=executed_count,
        mitre_techniques=mitre,
        summary=summary,
    )

    step = DefenseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary=(f"Generating report for {state.defense_id}"),
        output_summary=(f"Prevented={prevented}, ttc={ttc:.1f}s"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used=None,
    )

    await toolkit.record_defense_metric(
        "defense_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_defense_metric(
        "breakout_prevented",
        1.0 if prevented else 0.0,
    )

    return {
        "breakout_prevented": prevented,
        "report": defense_report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
