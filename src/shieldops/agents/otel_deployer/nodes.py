"""OTel Deployment Orchestrator Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    DeploymentPlan,
    DeploymentResult,
    DeployStage,
    K8sTarget,
    RolloutStrategy,
)
from .tools import OTelDeployerToolkit

logger = structlog.get_logger()


async def plan_deployments(
    state: dict[str, Any],
    toolkit: OTelDeployerToolkit,
) -> dict[str, Any]:
    """Discover clusters and create deployment plans for each target."""
    logger.info("otel_deployer.node.plan_deployments")

    namespace_filter = ""
    existing_targets = state.get("targets", [])

    # Use existing targets or discover new ones
    if existing_targets:
        targets = [K8sTarget(**t) if isinstance(t, dict) else t for t in existing_targets]
    else:
        targets = await toolkit.discover_clusters(namespace_filter)

    # Default config YAML if none provided
    default_config = (
        "receivers:\n"
        "  otlp:\n"
        "    protocols:\n"
        "      grpc:\n"
        "        endpoint: 0.0.0.0:4317\n"
        "      http:\n"
        "        endpoint: 0.0.0.0:4318\n"
        "processors:\n"
        "  memory_limiter:\n"
        "    check_interval: 1s\n"
        "    limit_mib: 512\n"
        "  batch:\n"
        "    timeout: 5s\n"
        "    send_batch_size: 1024\n"
        "exporters:\n"
        "  otlp/shieldops:\n"
        "    endpoint: ${SHIELDOPS_OTEL_ENDPOINT}\n"
        "service:\n"
        "  pipelines:\n"
        "    traces:\n"
        "      receivers: [otlp]\n"
        "      processors: [memory_limiter, batch]\n"
        "      exporters: [otlp/shieldops]\n"
    )

    # Build plans from existing state or create new ones
    existing_plans = state.get("plans", [])
    if existing_plans:
        plans = [DeploymentPlan(**p) if isinstance(p, dict) else p for p in existing_plans]
    else:
        strategy_str = state.get("strategy", RolloutStrategy.ROLLING.value)
        try:
            strategy = RolloutStrategy(strategy_str)
        except ValueError:
            strategy = RolloutStrategy.ROLLING

        plans = [
            toolkit.create_deployment_plan(
                target=t,
                config_yaml=default_config,
                strategy=strategy,
            )
            for t in targets
        ]

    reasoning = [
        f"Discovered {len(targets)} target cluster(s)",
        f"Created {len(plans)} deployment plan(s)",
    ]
    for plan in plans:
        reasoning.append(
            f"  - {plan.target.cluster_name}/{plan.target.namespace}: "
            f"{plan.replicas} replica(s), strategy={plan.strategy.value}"
        )

    return {
        "stage": DeployStage.PLAN.value,
        "targets": [t.model_dump() for t in targets],
        "plans": [p.model_dump() for p in plans],
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
        "confidence_score": 0.7,
    }


async def validate_configs(
    state: dict[str, Any],
    toolkit: OTelDeployerToolkit,
) -> dict[str, Any]:
    """Validate deployment plans and collector configs before applying."""
    logger.info("otel_deployer.node.validate_configs")

    plans_data = state.get("plans", [])
    plans = [DeploymentPlan(**p) if isinstance(p, dict) else p for p in plans_data]

    reasoning: list[str] = []
    valid_count = 0

    for plan in plans:
        issues: list[str] = []

        # Check config YAML is non-empty
        if not plan.config_yaml.strip():
            issues.append("empty config_yaml")

        # Check resource limits
        mem = plan.resource_limits.get("memory", "0Mi")
        mem_val = int("".join(c for c in mem if c.isdigit()) or "0")
        if mem_val < 256 and "Gi" not in mem:
            issues.append(f"memory limit {mem} is below recommended 256Mi")

        # Check image tag
        if plan.target.labels.get("env") == "production" and ":latest" in plan.collector_image:
            issues.append("':latest' tag in production is not recommended")

        if issues:
            reasoning.append(
                f"  WARN {plan.target.cluster_name}/{plan.target.namespace}: " + "; ".join(issues)
            )
        else:
            valid_count += 1
            reasoning.append(
                f"  OK {plan.target.cluster_name}/{plan.target.namespace}: config valid"
            )

    reasoning.insert(0, f"Validated {len(plans)} plan(s): {valid_count} valid")
    confidence = 0.9 if valid_count == len(plans) else 0.6

    # LLM enhancement: deeper config validation reasoning
    try:
        from .prompts import SYSTEM_VALIDATE, ValidationResult

        validation_context = json.dumps(
            {
                "total_plans": len(plans),
                "valid_count": valid_count,
                "plans_summary": [
                    {
                        "cluster": p.target.cluster_name,
                        "namespace": p.target.namespace,
                        "strategy": p.strategy.value,
                        "replicas": p.replicas,
                    }
                    for p in plans[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ValidationResult,
            await llm_structured(
                system_prompt=SYSTEM_VALIDATE,
                user_prompt=f"Deployment validation context:\n{validation_context}",
                schema=ValidationResult,
            ),
        )
        logger.info("llm_enhanced", agent="otel_deployer", node="validate_configs")
        reasoning.append(f"LLM analysis: {llm_result.summary}")
        reasoning.extend(llm_result.recommendations)
    except Exception:
        logger.debug("llm_fallback", agent="otel_deployer", node="validate_configs")

    return {
        "stage": DeployStage.VALIDATE.value,
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
        "confidence_score": confidence,
    }


async def deploy_collectors(
    state: dict[str, Any],
    toolkit: OTelDeployerToolkit,
) -> dict[str, Any]:
    """Apply deployment plans to target clusters."""
    logger.info("otel_deployer.node.deploy_collectors")

    plans_data = state.get("plans", [])
    plans = [DeploymentPlan(**p) if isinstance(p, dict) else p for p in plans_data]

    results: list[DeploymentResult] = []
    reasoning: list[str] = []

    for plan in plans:
        result = await toolkit.apply_deployment(plan, dry_run=False)
        results.append(result)
        reasoning.append(
            f"  {result.cluster_name}: status={result.status}, "
            f"pods={result.healthy_pods}/{result.total_pods}, "
            f"hash={result.config_hash}"
        )

    success_count = sum(1 for r in results if "fail" not in r.status)
    reasoning.insert(0, f"Deployed to {success_count}/{len(plans)} cluster(s)")

    return {
        "stage": DeployStage.DEPLOY.value,
        "results": [r.model_dump() for r in results],
        "rollback_available": success_count > 0,
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
        "confidence_score": 0.95 if success_count == len(plans) else 0.5,
    }


async def verify_and_report(
    state: dict[str, Any],
    toolkit: OTelDeployerToolkit,
) -> dict[str, Any]:
    """Verify all deployments and generate a summary report."""
    logger.info("otel_deployer.node.verify_and_report")

    results_data = state.get("results", [])
    results = [DeploymentResult(**r) if isinstance(r, dict) else r for r in results_data]

    reasoning: list[str] = []
    all_healthy = True

    for result in results:
        namespace = "default"
        # Find the namespace from plans
        for plan_data in state.get("plans", []):
            plan = DeploymentPlan(**plan_data) if isinstance(plan_data, dict) else plan_data
            if plan.target.cluster_name == result.cluster_name:
                namespace = plan.target.namespace
                break

        verification = await toolkit.verify_deployment(
            cluster_name=result.cluster_name,
            namespace=namespace,
        )

        is_healthy = verification.get("healthy", False)
        if not is_healthy:
            all_healthy = False

        reasoning.append(
            f"  {result.cluster_name}/{namespace}: "
            f"healthy={is_healthy}, "
            f"pods={verification.get('healthy_pods', 0)}/{verification.get('total_pods', 0)}, "
            f"zpages={verification.get('zpages_reachable', False)}, "
            f"telemetry_flowing={verification.get('receiving_telemetry', False)}"
        )

    status_summary = "all healthy" if all_healthy else "issues detected"
    reasoning.insert(0, f"Verification complete: {status_summary}")

    return {
        "stage": DeployStage.VERIFY.value,
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
        "confidence_score": 1.0 if all_healthy else 0.6,
    }
