"""Node implementations for the Evolution Engine Agent."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.agents.evolution.models import (
    EvolutionCandidate,
    EvolutionStage,
    LearningPropagation,
    PromptMutation,
    ValidationResult,
)
from shieldops.agents.evolution.prompts import (
    SYSTEM_ANALYZE_PATTERNS,
    SYSTEM_EVOLUTION_REPORT,
    SYSTEM_EVOLVE_PROMPTS,
    SYSTEM_VALIDATE_EVOLUTION,
)
from shieldops.agents.evolution.tools import EvolutionToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()


class PatternAnalysis(BaseModel):
    """LLM output for pattern analysis."""

    candidates: list[dict[str, Any]] = Field(default_factory=list)
    fleet_patterns: list[str] = Field(default_factory=list)
    cross_agent_opportunities: list[str] = Field(default_factory=list)


class PromptEvolution(BaseModel):
    """LLM output for prompt evolution."""

    evolved_prompt: str = ""
    changes_made: list[str] = Field(default_factory=list)
    expected_impact: str = ""
    risk_assessment: str = ""


class PropagationPlan(BaseModel):
    """LLM output for learning propagation."""

    propagations: list[dict[str, Any]] = Field(default_factory=list)
    skip_reasons: list[str] = Field(default_factory=list)


class EvolutionValidation(BaseModel):
    """LLM output for evolution validation."""

    verdict: str = ""
    reasoning: str = ""
    recommendations: list[str] = Field(default_factory=list)


class EvolutionReport(BaseModel):
    """LLM output for final evolution report."""

    summary: str = ""
    key_improvements: list[str] = Field(default_factory=list)
    regressions: list[str] = Field(default_factory=list)
    next_cycle_recommendations: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


async def measure_fitness(
    state: dict[str, Any],
    toolkit: EvolutionToolkit,
) -> dict[str, Any]:
    """Measure fitness across the fleet and identify evolution candidates."""
    logger.info("evolution.measure_fitness")

    target_ids = state.get("target_agent_ids", [])
    max_candidates = state.get("max_candidates", 10)

    # Measure fleet fitness
    fleet = await toolkit.measure_fleet_fitness(target_ids or None)
    fleet_avg = fleet.get("fleet_avg_fitness", 0.0)

    # Identify candidates
    candidates = await toolkit.identify_candidates(
        max_candidates=max_candidates,
        target_agent_ids=target_ids or None,
    )

    # Capture genomes for candidates
    genomes = []
    for candidate in candidates:
        genome = await toolkit.capture_genome(candidate.agent_id)
        genomes.append(genome)

    return {
        "stage": EvolutionStage.ANALYZE_PATTERNS,
        "candidates": candidates,
        "genomes": genomes,
        "total_agents_evaluated": len(fleet.get("leaderboard", [])),
        "total_candidates": len(candidates),
        "fleet_fitness_before": fleet_avg,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Measured {len(fleet.get('leaderboard', []))} agents, "
            f"found {len(candidates)} candidates"
        ],
    }


async def analyze_patterns(
    state: dict[str, Any],
    toolkit: EvolutionToolkit,
) -> dict[str, Any]:
    """Analyze performance patterns across candidates using LLM."""
    logger.info("evolution.analyze_patterns")

    candidates: list[EvolutionCandidate] = state.get("candidates", [])
    if not candidates:
        return {
            "stage": EvolutionStage.REPORT,
            "reasoning_chain": state.get("reasoning_chain", [])
            + ["No candidates for evolution — fleet is healthy"],
        }

    # Prepare context for LLM
    candidate_data = [
        {
            "agent_id": c.agent_id,
            "agent_type": c.agent_type,
            "fitness": c.fitness_score,
            "weakest": c.weakest_dimension,
            "strongest": c.strongest_dimension,
            "trend": c.trend,
            "strategy": c.suggested_strategy,
            "opportunity": c.improvement_opportunity,
        }
        for c in candidates
    ]

    # Get fleet-wide learnings
    fleet_learnings = await toolkit.get_fleet_learnings(min_applications=2)

    # LLM analysis
    try:
        analysis = await llm_structured(
            system_prompt=SYSTEM_ANALYZE_PATTERNS,
            user_prompt=(
                f"Candidates for evolution:\n{candidate_data}\n\n"
                f"Fleet learnings (widely applied):\n{fleet_learnings}"
            ),
            schema=PatternAnalysis,
        )
        patterns = analysis.fleet_patterns if isinstance(analysis, PatternAnalysis) else []
        cross_opportunities = (
            analysis.cross_agent_opportunities if isinstance(analysis, PatternAnalysis) else []
        )
    except Exception:
        logger.debug("evolution.analyze_patterns.llm_fallback")
        patterns = [f"{c.weakest_dimension} weakness in {c.agent_type}" for c in candidates]
        cross_opportunities = []

    return {
        "stage": EvolutionStage.EVOLVE_PROMPTS,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Analyzed {len(candidates)} candidates, found {len(patterns)} patterns, "
            f"{len(cross_opportunities)} cross-agent opportunities"
        ],
    }


async def evolve_prompts(
    state: dict[str, Any],
    toolkit: EvolutionToolkit,
) -> dict[str, Any]:
    """Generate prompt mutations for evolution candidates."""
    logger.info("evolution.evolve_prompts")

    candidates: list[EvolutionCandidate] = state.get("candidates", [])
    mutations: list[PromptMutation] = []

    for candidate in candidates:
        if candidate.suggested_strategy != "prompt_refine":
            continue

        # Generate mutation for the weakest dimension
        mutation = await toolkit.generate_mutation(
            agent_id=candidate.agent_id,
            node_name="primary",  # Default node
            weakness=candidate.weakest_dimension,
        )

        # Use LLM to generate the evolved prompt
        if mutation.current_prompt:
            try:
                result = await llm_structured(
                    system_prompt=SYSTEM_EVOLVE_PROMPTS,
                    user_prompt=(
                        f"Agent: {candidate.agent_type}\n"
                        f"Weakness: {candidate.weakest_dimension}\n"
                        f"Fitness: {candidate.fitness_score}\n"
                        f"Current prompt:\n{mutation.current_prompt}\n\n"
                        f"Improvement opportunity: {candidate.improvement_opportunity}"
                    ),
                    schema=PromptEvolution,
                )
                if isinstance(result, PromptEvolution) and result.evolved_prompt:
                    mutation.proposed_prompt = result.evolved_prompt
                    mutation.expected_improvement = 0.05
            except Exception:
                logger.debug(
                    "evolution.evolve_prompts.llm_fallback",
                    agent_id=candidate.agent_id,
                )
                # Use current prompt with minor annotation
                mutation.proposed_prompt = (
                    mutation.current_prompt
                    + f"\n\nIMPORTANT: Pay special attention to {candidate.weakest_dimension}. "
                    f"Recent analysis shows this is an area for improvement."
                )

        if mutation.proposed_prompt:
            mutations.append(mutation)

    return {
        "stage": EvolutionStage.PROPAGATE_LEARNINGS,
        "mutations": mutations,
        "total_mutations": len(mutations),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Generated {len(mutations)} prompt mutations"],
    }


async def propagate_learnings(
    state: dict[str, Any],
    toolkit: EvolutionToolkit,
) -> dict[str, Any]:
    """Propagate successful patterns across the agent fleet."""
    logger.info("evolution.propagate_learnings")

    candidates: list[EvolutionCandidate] = state.get("candidates", [])
    propagations: list[LearningPropagation] = []

    # Find high-performing agents that can teach others
    teachers = [c for c in candidates if c.fitness_score > 0.7]

    for teacher in teachers:
        # Propagate their strongest dimension as a learning
        prop = await toolkit.propagate_learning(
            source_agent_id=teacher.agent_id,
            source_agent_type=teacher.agent_type,
            learning_type="pattern_detected",
            title=f"High-performance pattern in {teacher.strongest_dimension}",
            description=(
                f"Agent {teacher.agent_id} ({teacher.agent_type}) achieves "
                f"strong {teacher.strongest_dimension} performance. "
                f"Pattern available for cross-pollination."
            ),
        )
        propagations.append(prop)

    # Also propagate false positive discoveries fleet-wide
    fleet_learnings = await toolkit.get_fleet_learnings(min_applications=3)
    for learning in fleet_learnings[:5]:
        prop = await toolkit.propagate_learning(
            source_agent_id=learning.get("source", ""),
            source_agent_type="",
            learning_type=learning.get("type", "pattern_detected"),
            title=learning.get("title", "Fleet learning"),
            description=f"Widely applied learning ({learning.get('applied_by_count', 0)} agents)",
        )
        propagations.append(prop)

    return {
        "stage": EvolutionStage.DEPLOY_CHANGES,
        "propagations": propagations,
        "total_learnings_propagated": len(propagations),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Propagated {len(propagations)} learnings across the fleet"],
    }


async def deploy_changes(
    state: dict[str, Any],
    toolkit: EvolutionToolkit,
) -> dict[str, Any]:
    """Deploy evolution changes (mutations + threshold adjustments)."""
    logger.info("evolution.deploy_changes")

    mutations: list[PromptMutation] = state.get("mutations", [])
    dry_run = state.get("dry_run", False)
    deployments = []

    for mutation in mutations:
        if not mutation.proposed_prompt:
            continue

        deployment = await toolkit.deploy_mutation(mutation, dry_run=dry_run)
        # Store pre-evolution fitness for validation
        fitness = toolkit._fitness.get_fitness(mutation.agent_id)
        deployment.changes["pre_fitness"] = fitness.composite_score
        deployments.append(deployment)

    return {
        "stage": EvolutionStage.VALIDATE_EVOLUTION,
        "deployments": deployments,
        "total_deployments": len(deployments),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Deployed {len(deployments)} evolution changes (dry_run={dry_run})"],
    }


async def validate_evolution(
    state: dict[str, Any],
    toolkit: EvolutionToolkit,
) -> dict[str, Any]:
    """Validate evolution deployments and rollback failures."""
    logger.info("evolution.validate_evolution")

    deployments = state.get("deployments", [])
    validations: list[ValidationResult] = []

    for deployment in deployments:
        validation = await toolkit.validate_deployment(deployment)

        # LLM validation for borderline cases
        if validation.verdict == "MONITOR":
            try:
                llm_result = await llm_structured(
                    system_prompt=SYSTEM_VALIDATE_EVOLUTION,
                    user_prompt=(
                        f"Agent: {deployment.agent_id}\n"
                        f"Pre-fitness: {validation.pre_evolution_fitness}\n"
                        f"Post-fitness: {validation.post_evolution_fitness}\n"
                        f"Improvement: {validation.improvement_pct}%\n"
                        f"Improved: {validation.dimensions_improved}\n"
                        f"Degraded: {validation.dimensions_degraded}"
                    ),
                    schema=EvolutionValidation,
                )
                if isinstance(llm_result, EvolutionValidation):
                    validation.verdict = llm_result.verdict or "MONITOR"
            except Exception:
                logger.debug("evolution.validate.llm_fallback")

        # Execute rollback if needed
        if validation.verdict == "ROLLBACK":
            await toolkit.rollback_deployment(deployment)

        validations.append(validation)

    # Compute fleet fitness after evolution
    fleet = await toolkit.measure_fleet_fitness()
    fleet_after = fleet.get("fleet_avg_fitness", 0.0)

    return {
        "stage": EvolutionStage.REPORT,
        "validations": validations,
        "fleet_fitness_after": fleet_after,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Validated {len(validations)} deployments: "
            f"{sum(1 for v in validations if v.verdict == 'KEEP')} kept, "
            f"{sum(1 for v in validations if v.verdict == 'ROLLBACK')} rolled back"
        ],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: EvolutionToolkit,
) -> dict[str, Any]:
    """Generate the final evolution cycle report."""
    logger.info("evolution.generate_report")

    fleet_before = state.get("fleet_fitness_before", 0.0)
    fleet_after = state.get("fleet_fitness_after", 0.0)
    improvement = (
        (fleet_after - fleet_before) / max(fleet_before, 0.01) * 100 if fleet_before > 0 else 0.0
    )

    # LLM report generation
    try:
        report = await llm_structured(
            system_prompt=SYSTEM_EVOLUTION_REPORT,
            user_prompt=(
                f"Evolution cycle results:\n"
                f"Agents evaluated: {state.get('total_agents_evaluated', 0)}\n"
                f"Candidates evolved: {state.get('total_candidates', 0)}\n"
                f"Mutations deployed: {state.get('total_deployments', 0)}\n"
                f"Learnings propagated: {state.get('total_learnings_propagated', 0)}\n"
                f"Fleet fitness: {fleet_before:.4f} → {fleet_after:.4f} ({improvement:+.1f}%)\n"
                f"Validations: {state.get('validations', [])}\n"
                f"Reasoning chain: {state.get('reasoning_chain', [])}"
            ),
            schema=EvolutionReport,
        )
    except Exception:
        logger.debug("evolution.report.llm_fallback")
        report = None

    summary = ""
    if isinstance(report, EvolutionReport):
        summary = report.summary

    return {
        "stage": EvolutionStage.REPORT,
        "improvement_pct": round(improvement, 2),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            summary
            or (
                f"Evolution cycle complete: {state.get('total_candidates', 0)} agents evolved, "
                f"fleet fitness {fleet_before:.4f} → {fleet_after:.4f} ({improvement:+.1f}%)"
            )
        ],
    }
