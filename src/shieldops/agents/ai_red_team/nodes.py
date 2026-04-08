"""Node implementations for the AI Red Team Agent LangGraph workflow."""

from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import structlog

from shieldops.agents.ai_red_team.models import (
    AIRedTeamState,
    AttackScenario,
    ExploitChain,
    ProbeResult,
    ReasoningStep,
)
from shieldops.agents.ai_red_team.prompts import (
    SYSTEM_ATTACK_SCENARIO_GENERATION,
    SYSTEM_EXPLOIT_CHAIN_ANALYSIS,
    SYSTEM_VULNERABILITY_ANALYSIS,
    AttackScenarioOutput,
    ExploitChainOutput,
    VulnerabilityAnalysisOutput,
)
from shieldops.agents.ai_red_team.tools import AIRedTeamToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AIRedTeamToolkit | None = None


def _get_toolkit() -> AIRedTeamToolkit:
    if _toolkit is None:
        return AIRedTeamToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


async def generate_scenarios(state: AIRedTeamState) -> dict[str, Any]:
    """Generate attack scenarios based on target environment and objectives."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "ai_red_team.generating_scenarios",
        target=state.target_environment,
        objectives=state.attack_objectives,
    )

    env_info = await toolkit.get_environment_info(state.target_environment)

    context_lines = [
        "## Target Environment",
        f"Target: {state.target_environment}",
        f"Cloud providers: {env_info.get('cloud_providers', [])}",
        f"K8s clusters: {env_info.get('kubernetes_clusters', 0)}",
        f"Services: {env_info.get('total_services', 0)}",
        f"Network zones: {env_info.get('network_zones', [])}",
        f"Security tools: {env_info.get('security_tools', [])}",
        "",
        "## Attack Objectives",
        *[f"- {obj}" for obj in state.attack_objectives],
        "",
        "## Available MITRE Techniques",
        *[f"- {t}" for t in state.mitre_techniques[:20]],
        "",
        "## Rules of Engagement",
        *[f"- {k}: {v}" for k, v in state.rules_of_engagement.items()],
    ]
    user_prompt = "\n".join(context_lines)

    scenarios: list[AttackScenario] = []
    try:
        result = cast(
            AttackScenarioOutput,
            await llm_structured(
                system_prompt=SYSTEM_ATTACK_SCENARIO_GENERATION,
                user_prompt=user_prompt,
                schema=AttackScenarioOutput,
            ),
        )
        for s in result.scenarios:
            scenarios.append(
                AttackScenario(
                    scenario_id=f"scenario-{uuid4().hex[:8]}",
                    name=s.get("name", ""),
                    description=s.get("description", ""),
                    mitre_technique_ids=s.get("techniques", []),
                    target_assets=s.get("targets", []),
                    complexity=s.get("complexity", "moderate"),
                    estimated_impact=s.get("impact", "medium"),
                )
            )
        output_summary = f"Generated {len(scenarios)} scenarios. {result.rationale[:100]}"
    except Exception as e:
        logger.error("ai_red_team.scenario_generation_failed", error=str(e))
        output_summary = f"Scenario generation failed: {e}"
        # Fallback scenarios
        scenarios.append(
            AttackScenario(
                scenario_id=f"scenario-{uuid4().hex[:8]}",
                name="Network Segmentation Test",
                description="Test network segmentation between zones",
                mitre_technique_ids=["T1046"],
                complexity="simple",
            )
        )

    step = ReasoningStep(
        step_number=1,
        action="generate_scenarios",
        input_summary=f"Target: {state.target_environment}, {len(state.attack_objectives)} obj",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm + env_info",
    )

    return {
        "attack_scenarios_generated": scenarios,
        "reasoning_chain": [step],
        "current_step": "generate_scenarios",
        "session_start": start,
    }


async def select_techniques(state: AIRedTeamState) -> dict[str, Any]:
    """Select and prioritize MITRE techniques from generated scenarios."""
    start = datetime.now(UTC)

    all_techniques: list[str] = []
    for scenario in state.attack_scenarios_generated:
        all_techniques.extend(scenario.mitre_technique_ids)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_techniques: list[str] = []
    for t in all_techniques:
        if t not in seen:
            seen.add(t)
            unique_techniques.append(t)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="select_techniques",
        input_summary=f"Selecting from {len(state.attack_scenarios_generated)} scenarios",
        output_summary=f"Selected {len(unique_techniques)} unique techniques",
        duration_ms=_elapsed_ms(start),
    )

    return {
        "mitre_techniques": unique_techniques,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "select_techniques",
    }


async def execute_probes(state: AIRedTeamState) -> dict[str, Any]:
    """Execute authorized security probes against the target."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "ai_red_team.executing_probes",
        technique_count=len(state.mitre_techniques),
        target=state.target_environment,
    )

    probes: list[ProbeResult] = []

    # Execute probes for each scenario
    for _scenario in state.attack_scenarios_generated[:5]:
        # Network probe
        net_result = await toolkit.probe_network_segmentation(state.target_environment)
        probes.append(
            ProbeResult(
                probe_id=net_result["probe_id"],
                technique_id=net_result.get("technique_id", ""),
                target=state.target_environment,
                success=not net_result.get("segmentation_bypass", True),
                detection_triggered=net_result.get("detection_triggered", False),
                detection_time_ms=net_result.get("detection_time_ms", 0),
                findings=net_result.get("findings", []),
            )
        )

        # Credential probe
        cred_result = await toolkit.test_credential_spray(state.target_environment)
        probes.append(
            ProbeResult(
                probe_id=cred_result["probe_id"],
                technique_id=cred_result.get("technique_id", ""),
                target=state.target_environment,
                success=cred_result.get("success", False),
                detection_triggered=cred_result.get("detection_triggered", False),
                detection_time_ms=cred_result.get("detection_time_ms", 0),
            )
        )

        # Privilege escalation probe
        privesc_result = await toolkit.test_privilege_escalation(state.target_environment)
        probes.append(
            ProbeResult(
                probe_id=privesc_result["probe_id"],
                technique_id=privesc_result.get("technique_id", ""),
                target=state.target_environment,
                success=privesc_result.get("escalation_possible", False),
                detection_triggered=privesc_result.get("detection_triggered", False),
                detection_time_ms=privesc_result.get("detection_time_ms", 0),
                findings=privesc_result.get("findings", []),
            )
        )

        # Lateral movement probe
        lateral_result = await toolkit.test_lateral_movement(
            state.target_environment, f"{state.target_environment}-internal"
        )
        probes.append(
            ProbeResult(
                probe_id=lateral_result["probe_id"],
                technique_id=lateral_result.get("technique_id", ""),
                target=state.target_environment,
                success=lateral_result.get("movement_possible", False),
                detection_triggered=lateral_result.get("detection_triggered", False),
                detection_time_ms=lateral_result.get("detection_time_ms", 0),
            )
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_probes",
        input_summary=f"Executing probes for {len(state.attack_scenarios_generated)} scenarios",
        output_summary=(
            f"Executed {len(probes)} probes: "
            f"{sum(1 for p in probes if p.success)} successful, "
            f"{sum(1 for p in probes if p.detection_triggered)} detected"
        ),
        duration_ms=_elapsed_ms(start),
        tool_used="red_team_toolkit",
    )

    return {
        "probes_executed": probes,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_probes",
    }


async def analyze_results(state: AIRedTeamState) -> dict[str, Any]:
    """Analyze probe results to identify vulnerabilities using LLM."""
    start = datetime.now(UTC)

    logger.info("ai_red_team.analyzing_results", probe_count=len(state.probes_executed))

    context_lines = ["## Probe Results"]
    for probe in state.probes_executed:
        context_lines.append(
            f"- {probe.probe_id} (T:{probe.technique_id}): "
            f"success={probe.success}, detected={probe.detection_triggered}, "
            f"detection_time={probe.detection_time_ms}ms"
        )
        if probe.findings:
            for f in probe.findings:
                context_lines.append(f"  Finding: {f}")

    context_lines.append(f"\n## Target: {state.target_environment}")
    context_lines.append(f"## Scenarios tested: {len(state.attack_scenarios_generated)}")

    user_prompt = "\n".join(context_lines)

    vulns: list[dict[str, Any]] = []
    try:
        result = cast(
            VulnerabilityAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_VULNERABILITY_ANALYSIS,
                user_prompt=user_prompt,
                schema=VulnerabilityAnalysisOutput,
            ),
        )
        vulns = result.vulnerabilities
        output_summary = (
            f"{result.summary[:150]}. "
            f"Risk: {result.risk_rating}. "
            f"{len(result.detection_gaps)} detection gaps"
        )
    except Exception as e:
        logger.error("ai_red_team.analysis_failed", error=str(e))
        output_summary = f"Analysis failed: {e}"
        # Fallback: flag undetected probes
        for probe in state.probes_executed:
            if probe.success and not probe.detection_triggered:
                vulns.append(
                    {
                        "probe_id": probe.probe_id,
                        "technique_id": probe.technique_id,
                        "severity": "high",
                        "description": "Successful probe not detected by defenses",
                    }
                )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_results",
        input_summary=f"Analyzing {len(state.probes_executed)} probe results",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm",
    )

    return {
        "vulnerabilities_found": vulns,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_results",
    }


async def chain_exploits(state: AIRedTeamState) -> dict[str, Any]:
    """Chain individual vulnerabilities into exploit chains using LLM."""
    start = datetime.now(UTC)

    logger.info(
        "ai_red_team.chaining_exploits",
        vuln_count=len(state.vulnerabilities_found),
    )

    context_lines = [
        "## Vulnerabilities Found",
        *[f"- {v}" for v in state.vulnerabilities_found[:20]],
        "",
        "## Probe Results",
    ]
    for probe in state.probes_executed[:15]:
        context_lines.append(
            f"- {probe.technique_id}: success={probe.success}, detected={probe.detection_triggered}"
        )
    context_lines.append(f"\n## Target: {state.target_environment}")

    user_prompt = "\n".join(context_lines)

    chains: list[ExploitChain] = []
    try:
        result = cast(
            ExploitChainOutput,
            await llm_structured(
                system_prompt=SYSTEM_EXPLOIT_CHAIN_ANALYSIS,
                user_prompt=user_prompt,
                schema=ExploitChainOutput,
            ),
        )
        for c in result.chains:
            chains.append(
                ExploitChain(
                    chain_id=f"chain-{uuid4().hex[:8]}",
                    steps=c.get("steps", []),
                    techniques_used=c.get("techniques", []),
                    initial_access=c.get("initial_access", ""),
                    final_objective=c.get("objective", ""),
                    success_probability=c.get("probability", 0.0),
                    risk_level=c.get("risk", "medium"),
                )
            )
        output_summary = (
            f"Identified {len(chains)} exploit chains. "
            f"Breach probability: {result.breach_probability_pct}%"
        )
    except Exception as e:
        logger.error("ai_red_team.chain_exploits_failed", error=str(e))
        output_summary = f"Exploit chaining failed: {e}"

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="chain_exploits",
        input_summary=f"Chaining {len(state.vulnerabilities_found)} vulnerabilities",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm",
    )

    return {
        "exploit_chains": chains,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "chain_exploits",
    }


async def generate_findings(state: AIRedTeamState) -> dict[str, Any]:
    """Generate final findings report."""
    start = datetime.now(UTC)

    output_summary = (
        f"Red team engagement complete: "
        f"{len(state.attack_scenarios_generated)} scenarios, "
        f"{len(state.probes_executed)} probes, "
        f"{len(state.vulnerabilities_found)} vulns, "
        f"{len(state.exploit_chains)} chains"
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_findings",
        input_summary="Compiling final red team report",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
    )

    session_duration = 0
    if state.session_start:
        session_duration = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
        "session_duration_ms": session_duration,
    }
