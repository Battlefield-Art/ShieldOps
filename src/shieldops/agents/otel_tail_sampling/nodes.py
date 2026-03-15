"""OTel Tail Sampling Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import SamplingPolicy, SamplingStage, TraceProfile
from .tools import OTelTailSamplingToolkit

logger = structlog.get_logger()


async def analyze_traces(
    state: dict[str, Any],
    toolkit: OTelTailSamplingToolkit,
) -> dict[str, Any]:
    """Analyze trace patterns across services in the namespace."""
    logger.info("otel_tail_sampling.node.analyze_traces")
    namespace = state.get("target_namespace", "default")

    profiles = await toolkit.analyze_trace_patterns(namespace)

    reasoning = [
        f"Analyzed trace patterns in namespace '{namespace}'",
        f"Found {len(profiles)} services with trace data",
    ]
    for p in profiles:
        reasoning.append(
            f"  {p.service}: {p.volume_per_min} traces/min, "
            f"avg={p.avg_latency_ms:.1f}ms, p99={p.p99_latency_ms:.1f}ms, "
            f"err={p.error_rate:.2%}"
        )

    return {
        "stage": SamplingStage.DESIGN_POLICY.value,
        "trace_profiles": [p.model_dump() for p in profiles],
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def design_policies(
    state: dict[str, Any],
    toolkit: OTelTailSamplingToolkit,
) -> dict[str, Any]:
    """Design sampling policies based on trace profiles."""
    logger.info("otel_tail_sampling.node.design_policies")
    budget_pct = state.get("budget_pct", 50.0)

    raw_profiles = state.get("trace_profiles", [])
    profiles = [TraceProfile(**p) if isinstance(p, dict) else p for p in raw_profiles]

    policies: list[SamplingPolicy] = []
    reasoning: list[str] = []

    for profile in profiles:
        policy = toolkit.design_sampling_policy(profile, budget_pct=budget_pct)
        policies.append(policy)
        reasoning.append(
            f"Designed {policy.policy_type.value} policy '{policy.name}' "
            f"for {profile.service} (rate={policy.sample_rate:.2f})"
        )

    # LLM enhancement: intelligent policy design reasoning
    try:
        from .prompts import SYSTEM_DESIGN, PolicyDesignResult

        policy_context = json.dumps(
            {
                "budget_pct": budget_pct,
                "num_profiles": len(profiles),
                "profiles_summary": [
                    {
                        "service": p.service,
                        "volume_per_min": p.volume_per_min,
                        "error_rate": p.error_rate,
                        "p99_latency_ms": p.p99_latency_ms,
                    }
                    for p in profiles[:20]
                ],
                "policies_summary": [
                    {"name": p.name, "type": p.policy_type.value, "rate": p.sample_rate}
                    for p in policies[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PolicyDesignResult,
            await llm_structured(
                system_prompt=SYSTEM_DESIGN,
                user_prompt=f"Sampling policy design context:\n{policy_context}",
                schema=PolicyDesignResult,
            ),
        )
        logger.info("llm_enhanced", agent="otel_tail_sampling", node="design_policies")
        reasoning.append(f"LLM analysis: {llm_result.summary}")
        reasoning.extend(llm_result.coverage_risks)
    except Exception:
        logger.debug("llm_fallback", agent="otel_tail_sampling", node="design_policies")

    return {
        "stage": SamplingStage.SIMULATE.value,
        "policies": [p.model_dump() for p in policies],
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def simulate_impact(
    state: dict[str, Any],
    toolkit: OTelTailSamplingToolkit,
) -> dict[str, Any]:
    """Simulate the impact of each policy on trace volume and cost."""
    logger.info("otel_tail_sampling.node.simulate_impact")

    raw_policies = state.get("policies", [])
    policies = [SamplingPolicy(**p) if isinstance(p, dict) else p for p in raw_policies]

    raw_profiles = state.get("trace_profiles", [])
    profiles = [TraceProfile(**p) if isinstance(p, dict) else p for p in raw_profiles]

    simulations = []
    reasoning: list[str] = []
    total_sampled = 0
    total_dropped = 0

    for policy in policies:
        # Match policy to its service profile
        matching_profile = None
        for profile in profiles:
            if profile.service in policy.name:
                matching_profile = profile
                break

        if matching_profile is None and profiles:
            matching_profile = profiles[0]

        if matching_profile:
            sim = toolkit.simulate_policy(policy, matching_profile)
            simulations.append(sim)
            total_sampled += sim.traces_sampled
            total_dropped += sim.traces_dropped
            reasoning.append(
                f"Policy '{sim.policy_name}': keep {sim.traces_sampled}, "
                f"drop {sim.traces_dropped} ({sim.estimated_cost_reduction:.1f}% savings) "
                f"— {sim.coverage_impact}"
            )

    total = total_sampled + total_dropped
    cost_savings = (total_dropped / total * 100.0) if total > 0 else 0.0
    reasoning.append(f"Overall estimated cost savings: {cost_savings:.1f}%")

    return {
        "stage": SamplingStage.APPLY.value,
        "simulations": [s.model_dump() for s in simulations],
        "cost_savings_pct": round(cost_savings, 2),
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def apply_policies(
    state: dict[str, Any],
    toolkit: OTelTailSamplingToolkit,
) -> dict[str, Any]:
    """Apply the approved sampling policies to the collector."""
    logger.info("otel_tail_sampling.node.apply_policies")
    namespace = state.get("target_namespace", "default")

    raw_policies = state.get("policies", [])
    policies = [SamplingPolicy(**p) if isinstance(p, dict) else p for p in raw_policies]

    applied: list[str] = []
    reasoning: list[str] = []

    for policy in policies:
        result = await toolkit.apply_policy(policy, namespace)
        status = result.get("status", "unknown")
        applied.append(policy.name)
        reasoning.append(f"Applied policy '{policy.name}': {status}")

    # Generate combined YAML
    if policies:
        _combined_yaml = toolkit.generate_tail_sampling_yaml(policies)
        reasoning.append(f"Generated combined tail_sampling YAML with {len(policies)} policies")

    return {
        "applied_policies": applied,
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }
