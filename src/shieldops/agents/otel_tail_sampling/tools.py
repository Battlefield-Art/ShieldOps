"""OTel Tail Sampling Agent — Tool functions for sampling policy management."""

from __future__ import annotations

from typing import Any

import structlog
import yaml

from .models import PolicyType, SamplingPolicy, SimulationResult, TraceProfile

logger = structlog.get_logger()


class OTelTailSamplingToolkit:
    """Tools for OpenTelemetry tail-based sampling policy management."""

    def __init__(
        self,
        k8s_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._k8s_client = k8s_client
        self._repository = repository

    async def analyze_trace_patterns(self, namespace: str) -> list[TraceProfile]:
        """Profile trace latency, error rate, and volume per service.

        In production this queries Prometheus/Tempo/Jaeger for trace metrics.
        Returns simulated profiles when no backend is connected.
        """
        logger.info(
            "otel_tail_sampling.analyze_trace_patterns",
            namespace=namespace,
        )

        if self._k8s_client is not None:
            try:
                metrics = await self._k8s_client.query_trace_metrics(namespace=namespace)
                return [
                    TraceProfile(
                        service=m["service"],
                        avg_latency_ms=m.get("avg_latency_ms", 0.0),
                        error_rate=m.get("error_rate", 0.0),
                        volume_per_min=m.get("volume_per_min", 0),
                        p99_latency_ms=m.get("p99_latency_ms", 0.0),
                    )
                    for m in metrics
                ]
            except Exception:
                logger.exception("otel_tail_sampling.analyze_trace_patterns.error")
                return [
                    TraceProfile(
                        service="unknown",
                        error_rate=0.0,
                        volume_per_min=0,
                    )
                ]

        # Simulated profiles for demo / testing
        return [
            TraceProfile(
                service="api-gateway",
                avg_latency_ms=45.0,
                error_rate=0.02,
                volume_per_min=12000,
                p99_latency_ms=320.0,
            ),
            TraceProfile(
                service="payment-service",
                avg_latency_ms=120.0,
                error_rate=0.05,
                volume_per_min=3000,
                p99_latency_ms=850.0,
            ),
            TraceProfile(
                service="health-check",
                avg_latency_ms=2.0,
                error_rate=0.0,
                volume_per_min=50000,
                p99_latency_ms=5.0,
            ),
        ]

    def design_sampling_policy(
        self,
        profile: TraceProfile,
        budget_pct: float = 50.0,
    ) -> SamplingPolicy:
        """Create an optimal sampling policy for a service based on its trace profile.

        Uses heuristics:
        - High error rate (>1%) -> always sample errors
        - High volume + low error -> rate-limit
        - High latency -> latency-based sampling at p99 threshold
        """
        logger.info(
            "otel_tail_sampling.design_policy",
            service=profile.service,
            budget_pct=budget_pct,
        )

        # Services with high error rates: sample all errors
        if profile.error_rate > 0.01:
            return SamplingPolicy(
                name=f"{profile.service}-error-capture",
                policy_type=PolicyType.ERROR,
                threshold=profile.error_rate,
                sample_rate=1.0,
            )

        # High volume, low value: rate-limit aggressively
        if profile.volume_per_min > 10000 and profile.error_rate <= 0.001:
            target_rate = budget_pct / 100.0
            return SamplingPolicy(
                name=f"{profile.service}-rate-limit",
                policy_type=PolicyType.RATE_LIMITING,
                threshold=float(int(profile.volume_per_min * target_rate)),
                sample_rate=target_rate,
            )

        # Default: latency-based sampling at p99
        return SamplingPolicy(
            name=f"{profile.service}-latency",
            policy_type=PolicyType.LATENCY,
            threshold=profile.p99_latency_ms,
            sample_rate=budget_pct / 100.0,
        )

    def simulate_policy(
        self,
        policy: SamplingPolicy,
        profile: TraceProfile,
    ) -> SimulationResult:
        """Dry-run a sampling policy against a trace profile to estimate impact."""
        logger.info(
            "otel_tail_sampling.simulate_policy",
            policy=policy.name,
            service=profile.service,
        )

        total_traces = profile.volume_per_min

        if policy.policy_type == PolicyType.RATE_LIMITING:
            sampled = min(int(policy.threshold), total_traces)
        elif policy.policy_type == PolicyType.ERROR:
            # Sample all error traces + a fraction of healthy ones
            error_traces = int(total_traces * profile.error_rate)
            healthy_sampled = int((total_traces - error_traces) * policy.sample_rate * 0.1)
            sampled = error_traces + healthy_sampled
        elif policy.policy_type == PolicyType.LATENCY:
            # Sample traces above the latency threshold (roughly top 1%) + sample_rate of rest
            above_threshold = int(total_traces * 0.01)
            below_sampled = int((total_traces - above_threshold) * policy.sample_rate)
            sampled = above_threshold + below_sampled
        elif policy.policy_type == PolicyType.ALWAYS_SAMPLE:
            sampled = total_traces
        else:
            sampled = int(total_traces * policy.sample_rate)

        sampled = min(sampled, total_traces)
        dropped = total_traces - sampled
        cost_reduction = (dropped / total_traces * 100.0) if total_traces > 0 else 0.0

        if cost_reduction > 80:
            coverage = "minimal — high risk of missing signals"
        elif cost_reduction > 50:
            coverage = "reduced — errors and outliers retained"
        elif cost_reduction > 20:
            coverage = "good — most important traces retained"
        else:
            coverage = "full — near-complete observability"

        return SimulationResult(
            policy_name=policy.name,
            traces_sampled=sampled,
            traces_dropped=dropped,
            estimated_cost_reduction=round(cost_reduction, 2),
            coverage_impact=coverage,
        )

    async def apply_policy(
        self,
        policy: SamplingPolicy,
        namespace: str,
    ) -> dict[str, Any]:
        """Apply a sampling policy to the collector configuration in the namespace."""
        logger.info(
            "otel_tail_sampling.apply_policy",
            policy=policy.name,
            namespace=namespace,
        )

        if self._k8s_client is not None:
            try:
                yaml_snippet = self.generate_tail_sampling_yaml([policy])
                result = await self._k8s_client.patch_configmap(
                    name="otel-collector-config",
                    namespace=namespace,
                    data={"tail_sampling": yaml_snippet},
                )
                return {
                    "status": "applied",
                    "policy": policy.name,
                    "namespace": namespace,
                    "detail": result,
                }
            except Exception as exc:
                logger.exception("otel_tail_sampling.apply_policy.error")
                return {
                    "status": "failed",
                    "policy": policy.name,
                    "namespace": namespace,
                    "error": str(exc),
                }

        return {
            "status": "simulated",
            "policy": policy.name,
            "namespace": namespace,
        }

    def generate_tail_sampling_yaml(self, policies: list[SamplingPolicy]) -> str:
        """Generate the tail_sampling processor YAML for the OTel Collector.

        Produces config matching the OTel Collector's tail_sampling processor spec:
        https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/tailsamplingprocessor
        """
        logger.info(
            "otel_tail_sampling.generate_yaml",
            policy_count=len(policies),
        )

        policy_configs: list[dict[str, Any]] = []

        for policy in policies:
            entry: dict[str, Any] = {
                "name": policy.name,
                "type": policy.policy_type.value,
            }

            if policy.policy_type == PolicyType.LATENCY:
                entry["latency"] = {
                    "threshold_ms": int(policy.threshold),
                }
            elif policy.policy_type == PolicyType.ERROR:
                entry["status_code"] = {
                    "status_codes": ["ERROR"],
                }
            elif policy.policy_type == PolicyType.STATUS_CODE:
                entry["status_code"] = {
                    "status_codes": ["ERROR", "UNSET"],
                }
            elif policy.policy_type == PolicyType.STRING_ATTRIBUTE:
                entry["string_attribute"] = {
                    "key": policy.attribute_key,
                    "values": list(policy.attribute_values),
                }
            elif policy.policy_type == PolicyType.RATE_LIMITING:
                entry["rate_limiting"] = {
                    "spans_per_second": int(policy.threshold),
                }
            elif policy.policy_type == PolicyType.COMPOSITE:
                entry["composite"] = {
                    "max_total_spans_per_second": int(policy.threshold),
                    "policy_order": ["always_sample", "string_attribute", "rate_limiting"],
                }
            elif policy.policy_type == PolicyType.ALWAYS_SAMPLE:
                pass  # No extra config needed

            policy_configs.append(entry)

        total_volume = sum(p.threshold for p in policies if p.threshold > 0) or 5000
        tail_sampling_config: dict[str, Any] = {
            "processors": {
                "tail_sampling": {
                    "decision_wait": "10s",
                    "num_traces": 100000,
                    "expected_new_traces_per_sec": int(total_volume / 60)
                    if total_volume > 60
                    else 100,
                    "policies": policy_configs,
                },
            },
        }

        return yaml.dump(
            tail_sampling_config,
            default_flow_style=False,
            sort_keys=False,
        )
