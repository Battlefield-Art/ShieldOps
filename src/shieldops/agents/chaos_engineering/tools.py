"""Tool functions for the Chaos Engineering Agent.

Provides experiment planning, safety validation, fault injection,
and impact observation capabilities.
"""

import time
from typing import Any

import structlog

from shieldops.agents.chaos_engineering.models import (
    ChaosExperiment,
    ExperimentStatus,
    FaultInjection,
    FaultType,
    ImpactObservation,
    SafetyCheck,
)

logger = structlog.get_logger()


class ChaosEngineeringToolkit:
    """Collection of tools available to the chaos engineering agent."""

    EXPERIMENT_LIBRARY: dict[str, dict[str, Any]] = {
        "pod_kill_single": {
            "fault_type": FaultType.POD_KILL,
            "duration_sec": 30,
            "blast_radius": "single_pod",
            "hypothesis": "Service recovers within 30s when a single pod is terminated.",
        },
        "network_latency_injection": {
            "fault_type": FaultType.NETWORK_LATENCY,
            "duration_sec": 60,
            "blast_radius": "single_pod",
            "hypothesis": "Service degrades gracefully under 200ms added latency.",
        },
        "cpu_stress_test": {
            "fault_type": FaultType.CPU_STRESS,
            "duration_sec": 120,
            "blast_radius": "single_pod",
            "hypothesis": "Service maintains <2s p99 latency under CPU pressure.",
        },
        "memory_pressure_test": {
            "fault_type": FaultType.MEMORY_PRESSURE,
            "duration_sec": 90,
            "blast_radius": "single_pod",
            "hypothesis": "OOM killer targets the stress process, not the app.",
        },
        "dns_failure_resilience": {
            "fault_type": FaultType.DNS_FAILURE,
            "duration_sec": 45,
            "blast_radius": "single_pod",
            "hypothesis": "Service retries DNS lookups and recovers within 15s.",
        },
    }

    def __init__(self, opa_client: Any = None, k8s_client: Any = None) -> None:
        self._opa_client = opa_client
        self._k8s_client = k8s_client

    async def plan_experiment(
        self,
        experiment_name: str,
        target_service: str,
        target_namespace: str,
    ) -> ChaosExperiment:
        """Plan a chaos experiment from the library or create a custom one.

        Args:
            experiment_name: Name or library key for the experiment.
            target_service: Kubernetes service to target.
            target_namespace: Kubernetes namespace of the target.

        Returns:
            A fully defined ChaosExperiment ready for safety validation.
        """
        template = self.EXPERIMENT_LIBRARY.get(experiment_name, {})

        fault_type = template.get("fault_type", FaultType.POD_KILL)
        duration_sec = template.get("duration_sec", 60)
        blast_radius = template.get("blast_radius", "single_pod")
        hypothesis = template.get(
            "hypothesis",
            f"Service {target_service} recovers after {fault_type.value} fault.",
        )

        experiment = ChaosExperiment(
            name=experiment_name,
            fault_type=fault_type,
            target_service=target_service,
            target_namespace=target_namespace,
            duration_sec=duration_sec,
            blast_radius=blast_radius,
            hypothesis=hypothesis,
            status=ExperimentStatus.PLANNED,
        )

        logger.info(
            "chaos_experiment_planned",
            experiment_id=experiment.id,
            fault_type=experiment.fault_type,
            target=f"{target_namespace}/{target_service}",
            blast_radius=blast_radius,
        )

        return experiment

    async def validate_safety(self, experiment: ChaosExperiment) -> list[SafetyCheck]:
        """Run safety checks before fault injection.

        Validates blast radius, OPA policy, SLO headroom, and replica count.

        Args:
            experiment: The experiment to validate.

        Returns:
            List of safety check results.
        """
        checks: list[SafetyCheck] = []

        # Check 1: Blast radius must be contained
        blast_ok = experiment.blast_radius in ("single_pod", "single_node")
        checks.append(
            SafetyCheck(
                experiment_id=experiment.id,
                check_name="blast_radius_limit",
                passed=blast_ok,
                details=f"Blast radius '{experiment.blast_radius}' is "
                + ("within safe bounds." if blast_ok else "too wide — aborting."),
                blocking=True,
            )
        )

        # Check 2: OPA policy evaluation
        opa_passed = True
        opa_details = "OPA policy allows experiment."
        if self._opa_client is not None:
            try:
                result = await self._opa_client.evaluate(
                    "chaos/allow",
                    {
                        "fault_type": experiment.fault_type.value,
                        "namespace": experiment.target_namespace,
                        "blast_radius": experiment.blast_radius,
                    },
                )
                opa_passed = bool(result.get("allow", False))
                opa_details = result.get("reason", opa_details)
            except Exception as e:
                opa_passed = False
                opa_details = f"OPA evaluation failed: {e}"
        checks.append(
            SafetyCheck(
                experiment_id=experiment.id,
                check_name="opa_policy",
                passed=opa_passed,
                details=opa_details,
                blocking=True,
            )
        )

        # Check 3: Target has sufficient replicas
        replica_ok = True
        replica_details = "Replica count sufficient (simulated: 3 replicas)."
        if self._k8s_client is not None:
            try:
                replicas = await self._k8s_client.get_replica_count(
                    experiment.target_service,
                    experiment.target_namespace,
                )
                replica_ok = replicas >= 2
                replica_details = f"Replica count: {replicas}. " + (
                    "Sufficient." if replica_ok else "Insufficient — need >=2."
                )
            except Exception as e:
                replica_ok = False
                replica_details = f"Failed to check replicas: {e}"
        checks.append(
            SafetyCheck(
                experiment_id=experiment.id,
                check_name="replica_count",
                passed=replica_ok,
                details=replica_details,
                blocking=True,
            )
        )

        # Check 4: SLO error budget headroom
        checks.append(
            SafetyCheck(
                experiment_id=experiment.id,
                check_name="slo_headroom",
                passed=True,
                details="SLO error budget has >20% remaining (simulated).",
                blocking=False,
            )
        )

        logger.info(
            "chaos_safety_validated",
            experiment_id=experiment.id,
            total_checks=len(checks),
            all_passed=all(c.passed for c in checks if c.blocking),
        )

        return checks

    async def inject_fault(self, experiment: ChaosExperiment) -> FaultInjection:
        """Inject a fault into the target service.

        In production this would call the Kubernetes API or a chaos mesh
        controller. Currently simulates the injection.

        Args:
            experiment: The validated experiment to execute.

        Returns:
            A FaultInjection record with timing information.
        """
        started = time.time()

        logger.info(
            "chaos_fault_injecting",
            experiment_id=experiment.id,
            fault_type=experiment.fault_type,
            target=f"{experiment.target_namespace}/{experiment.target_service}",
        )

        # Simulated injection — in production, call chaos-mesh / litmus / k8s API
        injection = FaultInjection(
            experiment_id=experiment.id,
            fault_type=experiment.fault_type,
            target=f"{experiment.target_namespace}/{experiment.target_service}",
            started_at=started,
            ended_at=started + experiment.duration_sec,
            rollback_triggered=False,
        )

        logger.info(
            "chaos_fault_injected",
            injection_id=injection.id,
            duration_sec=experiment.duration_sec,
        )

        return injection

    async def observe_impact(
        self,
        experiment: ChaosExperiment,
        injection: FaultInjection,
    ) -> list[ImpactObservation]:
        """Observe service metrics during and after fault injection.

        Collects baseline vs. during-fault metric values for key SLIs.

        Args:
            experiment: The running experiment.
            injection: The active fault injection record.

        Returns:
            List of impact observations with deviation percentages.
        """
        observations: list[ImpactObservation] = []

        # Simulated metric observations — in production, query Prometheus/Datadog
        metrics = [
            ("p99_latency_ms", 150.0, 320.0),
            ("error_rate_pct", 0.1, 0.8),
            ("request_throughput_rps", 1000.0, 850.0),
            ("cpu_utilization_pct", 45.0, 78.0),
        ]

        slo_breached = False
        for metric_name, baseline, during in metrics:
            deviation = ((during - baseline) / baseline) * 100 if baseline else 0.0
            recovered = abs(deviation) < 50  # Simplified recovery check

            obs = ImpactObservation(
                experiment_id=experiment.id,
                metric_name=metric_name,
                baseline_value=baseline,
                during_fault_value=during,
                deviation_pct=round(deviation, 2),
                recovered=recovered,
                recovery_time_sec=5.0 if recovered else 0.0,
            )
            observations.append(obs)

            # Check for SLO breach: error rate >5% or latency >500ms
            if metric_name == "error_rate_pct" and during > 5.0:
                slo_breached = True
            if metric_name == "p99_latency_ms" and during > 500.0:
                slo_breached = True

        if slo_breached:
            injection.rollback_triggered = True
            logger.warning(
                "chaos_slo_breached_auto_rollback",
                experiment_id=experiment.id,
            )

        logger.info(
            "chaos_impact_observed",
            experiment_id=experiment.id,
            observations=len(observations),
            slo_breached=slo_breached,
        )

        return observations
