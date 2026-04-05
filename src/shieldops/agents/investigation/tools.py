"""Tool functions for the Investigation Agent.

These bridge observability connectors and infrastructure connectors to the
agent's LangGraph nodes. Each tool is a self-contained async function that
queries external systems and returns structured data.

All infrastructure-reading actions are gated by OPA policy evaluation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.connectors.base import ConnectorRouter
from shieldops.models.base import TimeRange
from shieldops.observability.base import LogSource, MetricSource, TraceSource
from shieldops.policy.engine import PolicyContext
from shieldops.policy.engine import evaluate as policy_evaluate
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()


class _RootCauseAnalysis(BaseModel):
    """Structured LLM output for root cause analysis."""

    summary: str = Field(description="Brief summary of the root cause analysis")
    probable_root_cause: str = Field(description="Most likely root cause")
    contributing_factors: list[str] = Field(description="Contributing factors")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the analysis")
    recommended_next_steps: list[str] = Field(description="Recommended next steps")


class InvestigationToolkit:
    """Collection of tools available to the investigation agent.

    Injected into nodes at graph construction time to decouple agent logic
    from specific connector implementations.

    All infrastructure-reading actions are gated by an OPA policy check.
    If denied, the action is skipped and partial/empty results returned.
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        log_sources: list[LogSource] | None = None,
        metric_sources: list[MetricSource] | None = None,
        trace_sources: list[TraceSource] | None = None,
        repository: Any = None,
    ) -> None:
        self._router = connector_router
        self._log_sources = log_sources or []
        self._metric_sources = metric_sources or []
        self._trace_sources = trace_sources or []
        self._repository = repository

    async def _check_policy(
        self,
        action: str,
        target: str,
        environment: str = "production",
    ) -> bool:
        """Evaluate OPA policy before an infrastructure action.

        Returns True if the action is allowed, False if denied.
        On evaluation errors, defaults to allow (fail-open for read-only).
        """
        try:
            ctx = PolicyContext(
                agent_name="investigation",
                action_type=action,
                target_resources=[target] if target else [],
                environment=environment,
                risk_score=0.1,  # Read-only investigation actions are low risk
            )
            decision = await policy_evaluate(action=action, context=ctx)
            logger.info(
                "investigation.policy_check",
                action=action,
                target=target,
                allowed=decision.allowed,
                decision=decision.decision.value,
                reason=decision.reason,
            )
            return decision.allowed
        except Exception as e:
            # Fail-open for read-only investigation queries
            logger.warning(
                "investigation.policy_check_error",
                action=action,
                target=target,
                error=str(e),
            )
            return True

    async def query_logs(
        self,
        resource_id: str,
        time_range: TimeRange | None = None,
        patterns: list[str] | None = None,
    ) -> dict[str, Any]:
        """Query logs across all registered log sources.

        Returns aggregated log entries and pattern matches.
        Attempts Splunk via connector_router first, then falls back to
        registered log sources.
        """
        # OPA policy gate
        if not await self._check_policy("query_logs", resource_id):
            logger.warning(
                "investigation.query_logs.policy_denied",
                resource_id=resource_id,
            )
            return {
                "total_entries": 0,
                "error_count": 0,
                "warning_count": 0,
                "entries": [],
                "error_entries": [],
                "warning_entries": [],
                "pattern_matches": {},
                "sources_queried": [],
                "policy_denied": True,
            }

        logger.info(
            "investigation.query_logs",
            resource_id=resource_id,
            patterns=patterns,
            source_count=len(self._log_sources),
        )

        if time_range is None:
            now = datetime.now(UTC)
            time_range = TimeRange(start=now - timedelta(hours=1), end=now)

        all_entries: list[dict[str, Any]] = []
        pattern_matches: dict[str, list[dict[str, Any]]] = {}

        # Try Splunk via connector router for enriched log data
        if self._router:
            try:
                splunk = self._router.get("splunk")
                splunk_results = await splunk.search(
                    f'index=* host="{resource_id}" earliest=-1h',
                )
                if isinstance(splunk_results, list):
                    all_entries.extend(splunk_results)
                    logger.info(
                        "investigation.query_logs.splunk_success",
                        resource_id=resource_id,
                        entries=len(splunk_results),
                    )
            except (ValueError, Exception) as e:
                logger.debug(
                    "investigation.query_logs.splunk_unavailable",
                    resource_id=resource_id,
                    error=str(e),
                )

        for source in self._log_sources:
            try:
                entries = await source.query_logs(resource_id, time_range)
                all_entries.extend(entries)

                if patterns:
                    matches = await source.search_patterns(resource_id, patterns, time_range)
                    for pattern, hits in matches.items():
                        pattern_matches.setdefault(pattern, []).extend(hits)
            except Exception as e:
                logger.error(
                    "log_query_failed",
                    source=source.source_name,
                    resource_id=resource_id,
                    error=str(e),
                )

        # Classify entries by severity
        error_entries = [e for e in all_entries if e.get("level") in ("error", "fatal")]
        warning_entries = [e for e in all_entries if e.get("level") == "warning"]

        result = {
            "total_entries": len(all_entries),
            "error_count": len(error_entries),
            "warning_count": len(warning_entries),
            "entries": all_entries[:100],  # Cap at 100 for LLM context
            "error_entries": error_entries[:30],
            "warning_entries": warning_entries[:20],
            "pattern_matches": {k: v[:10] for k, v in pattern_matches.items()},
            "sources_queried": [s.source_name for s in self._log_sources],
        }

        logger.info(
            "investigation.audit",
            action="query_logs",
            target=resource_id,
            result="completed",
            total_entries=result["total_entries"],
            error_count=result["error_count"],
        )

        return result

    async def query_metrics(
        self,
        resource_id: str,
        metric_names: list[str] | None = None,
        time_range: TimeRange | None = None,
    ) -> dict[str, Any]:
        """Query metrics across all registered metric sources.

        If metric_names not provided, queries standard SRE metrics:
        CPU, memory, error rate, latency, restarts.
        """
        # OPA policy gate
        if not await self._check_policy("query_metrics", resource_id):
            logger.warning(
                "investigation.query_metrics.policy_denied",
                resource_id=resource_id,
            )
            return {
                "current_values": {},
                "anomalies": [],
                "anomaly_count": 0,
                "metrics_checked": [],
                "sources_queried": [],
                "policy_denied": True,
            }

        logger.info(
            "investigation.query_metrics",
            resource_id=resource_id,
            metric_names=metric_names,
            source_count=len(self._metric_sources),
        )

        if time_range is None:
            now = datetime.now(UTC)
            time_range = TimeRange(start=now - timedelta(hours=1), end=now)

        baseline_range = TimeRange(
            start=time_range.start - timedelta(hours=24),
            end=time_range.start - timedelta(hours=23),
        )

        # Default SRE metrics to check if none specified
        if metric_names is None:
            metric_names = self._default_metrics_for_resource(resource_id)

        labels = self._labels_from_resource_id(resource_id)
        all_anomalies: list[dict[str, Any]] = []
        current_values: dict[str, Any] = {}

        for source in self._metric_sources:
            for metric in metric_names:
                try:
                    # Get current value
                    instant = await source.query_instant(
                        f"{metric}{{{self._format_labels(labels)}}}"
                    )
                    if instant:
                        current_values[metric] = instant[0].get("value")

                    # Detect anomalies against baseline
                    anomalies = await source.detect_anomalies(
                        metric_name=metric,
                        labels=labels,
                        time_range=time_range,
                        baseline_range=baseline_range,
                        threshold_percent=50.0,
                    )
                    all_anomalies.extend(anomalies)
                except Exception as e:
                    logger.error(
                        "metric_query_failed",
                        source=source.source_name,
                        metric=metric,
                        error=str(e),
                    )

        result = {
            "current_values": current_values,
            "anomalies": all_anomalies,
            "anomaly_count": len(all_anomalies),
            "metrics_checked": metric_names,
            "sources_queried": [s.source_name for s in self._metric_sources],
        }

        logger.info(
            "investigation.audit",
            action="query_metrics",
            target=resource_id,
            result="completed",
            anomaly_count=result["anomaly_count"],
            metrics_checked=len(metric_names) if metric_names else 0,
        )

        return result

    async def query_traces(
        self,
        service_name: str,
        time_range: TimeRange | None = None,
    ) -> dict[str, Any]:
        """Query distributed traces for a service to find bottlenecks."""
        # OPA policy gate
        if not await self._check_policy("query_traces", service_name):
            logger.warning(
                "investigation.query_traces.policy_denied",
                service_name=service_name,
            )
            return {
                "traces": [],
                "bottleneck": None,
                "error_traces": [],
                "sources_queried": [],
                "policy_denied": True,
            }

        logger.info(
            "investigation.query_traces",
            service_name=service_name,
            source_count=len(self._trace_sources),
        )

        if time_range is None:
            now = datetime.now(UTC)
            time_range = TimeRange(start=now - timedelta(hours=1), end=now)

        results: dict[str, Any] = {
            "traces": [],
            "bottleneck": None,
            "error_traces": [],
            "sources_queried": [],
        }

        for source in self._trace_sources:
            try:
                results["sources_queried"].append(source.source_name)

                # Find slow traces
                slow = await source.search_traces(
                    service=service_name,
                    time_range=time_range,
                    min_duration_ms=1000,
                    limit=10,
                )
                results["traces"].extend(slow)

                # Find error traces
                errors = await source.search_traces(
                    service=service_name,
                    time_range=time_range,
                    status="error",
                    limit=10,
                )
                results["error_traces"].extend(errors)

                # Identify bottleneck
                bottleneck = await source.find_bottleneck(service_name, time_range)
                if bottleneck:
                    results["bottleneck"] = bottleneck
            except Exception as e:
                logger.error(
                    "trace_query_failed",
                    source=source.source_name,
                    service=service_name,
                    error=str(e),
                )

        logger.info(
            "investigation.audit",
            action="query_traces",
            target=service_name,
            result="completed",
            trace_count=len(results["traces"]),
            error_trace_count=len(results["error_traces"]),
            has_bottleneck=results["bottleneck"] is not None,
        )

        return results

    async def get_k8s_events(
        self,
        resource_id: str,
        time_range: TimeRange | None = None,
    ) -> list[dict[str, Any]]:
        """Get Kubernetes events for a resource."""
        # OPA policy gate
        if not await self._check_policy("get_k8s_events", resource_id):
            logger.warning(
                "investigation.get_k8s_events.policy_denied",
                resource_id=resource_id,
            )
            return []

        logger.info("investigation.get_k8s_events", resource_id=resource_id)

        if self._router is None:
            logger.debug(
                "investigation.get_k8s_events.no_router",
                resource_id=resource_id,
            )
            return []

        if time_range is None:
            now = datetime.now(UTC)
            time_range = TimeRange(start=now - timedelta(hours=1), end=now)

        try:
            connector = self._router.get("kubernetes")
            events = await connector.get_events(resource_id, time_range)
            logger.info(
                "investigation.audit",
                action="get_k8s_events",
                target=resource_id,
                result="completed",
                event_count=len(events),
            )
            return events
        except (ValueError, Exception) as e:
            logger.error("k8s_events_failed", resource_id=resource_id, error=str(e))
            return []

    async def get_resource_health(
        self,
        resource_id: str,
        provider: str = "kubernetes",
    ) -> dict[str, Any]:
        """Get health status of a specific resource."""
        logger.info(
            "investigation.get_resource_health",
            resource_id=resource_id,
            provider=provider,
        )

        if self._router is None:
            logger.debug(
                "investigation.get_resource_health.no_router",
                resource_id=resource_id,
            )
            return {"healthy": None, "status": "unknown", "message": "No connector available"}

        try:
            connector = self._router.get(provider)
            health = await connector.get_health(resource_id)
            result = health.model_dump()
            logger.info(
                "investigation.audit",
                action="get_resource_health",
                target=resource_id,
                result="completed",
                status=result.get("status", "unknown"),
            )
            return result
        except (ValueError, Exception) as e:
            logger.error("health_check_failed", resource_id=resource_id, error=str(e))
            return {"healthy": None, "status": "error", "message": str(e)}

    async def query_historical_patterns(
        self,
        alert_type: str,
        resource_id: str = "",
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Query historical incident outcomes that match the current alert.

        Returns past incidents with similar alert_type for pattern matching,
        ordered by recency.  Falls back to an empty list when no repository
        is configured.
        """
        logger.info(
            "investigation.query_historical_patterns",
            alert_type=alert_type,
            resource_id=resource_id,
        )

        if self._repository is None:
            logger.debug("investigation.query_historical_patterns.no_repository")
            return []

        try:
            results: list[dict[str, Any]] = await self._repository.get_similar_incidents(
                alert_type=alert_type,
                resource_id=resource_id,
                limit=limit,
            )
            logger.info(
                "investigation.audit",
                action="query_historical_patterns",
                target=alert_type,
                result="completed",
                pattern_count=len(results),
            )
            return results
        except Exception as e:
            logger.warning("historical_pattern_query_failed", error=str(e))
            return []

    async def get_detection_context(
        self,
        alert_id: str,
        resource_id: str = "",
    ) -> dict[str, Any]:
        """Get CrowdStrike detection context for enriched threat intelligence.

        Falls back gracefully when the CrowdStrike connector is unavailable.
        """
        # OPA policy gate
        if not await self._check_policy("get_detection_context", resource_id or alert_id):
            logger.warning(
                "investigation.get_detection_context.policy_denied",
                alert_id=alert_id,
                resource_id=resource_id,
            )
            return {"available": False, "reason": "Policy denied"}

        logger.info(
            "investigation.get_detection_context",
            alert_id=alert_id,
            resource_id=resource_id,
        )

        if self._router is None:
            return {"available": False, "reason": "No connector router configured"}

        try:
            cs_connector = self._router.get("crowdstrike")
            detections = await cs_connector.get_detections(
                filter_query=f"resource_id:'{resource_id}'",
                limit=10,
            )
            logger.info(
                "investigation.audit",
                action="get_detection_context",
                target=resource_id,
                result="completed",
                detection_count=len(detections) if isinstance(detections, list) else 0,
            )
            return {
                "available": True,
                "detections": detections if isinstance(detections, list) else [],
                "source": "crowdstrike",
            }
        except (ValueError, Exception) as e:
            logger.debug(
                "investigation.get_detection_context.unavailable",
                error=str(e),
            )
            return {"available": False, "reason": str(e)}

    async def analyze_root_cause(
        self,
        alert_context: dict[str, Any],
        findings: dict[str, Any],
    ) -> dict[str, Any]:
        """LLM-powered root cause analysis with structured fallback.

        Uses llm_structured() to analyze collected findings and produce a
        structured root cause assessment. Falls back to a heuristic summary
        when the LLM is unavailable.
        """
        logger.info(
            "investigation.analyze_root_cause",
            alert_name=alert_context.get("alert_name", ""),
            findings_keys=list(findings.keys()),
        )

        prompt = (
            "Analyze the following investigation findings and determine the root cause.\n\n"
            f"## Alert\n"
            f"Name: {alert_context.get('alert_name', 'unknown')}\n"
            f"Severity: {alert_context.get('severity', 'unknown')}\n"
            f"Resource: {alert_context.get('resource_id', 'unknown')}\n\n"
            f"## Findings\n"
        )
        for key, value in findings.items():
            prompt += f"### {key}\n{value}\n\n"

        try:
            analysis = await llm_structured(
                system_prompt=(
                    "You are an expert SRE investigating a production incident. "
                    "Analyze the findings and identify the root cause with high precision."
                ),
                user_prompt=prompt,
                schema=_RootCauseAnalysis,
            )
            result = {
                "summary": analysis.summary,
                "probable_root_cause": analysis.probable_root_cause,
                "contributing_factors": analysis.contributing_factors,
                "confidence": analysis.confidence,
                "recommended_next_steps": analysis.recommended_next_steps,
                "source": "llm",
            }
        except Exception as e:
            logger.error("investigation.analyze_root_cause.llm_failed", error=str(e))
            # Heuristic fallback: summarize from raw findings
            error_count = findings.get("error_count", 0)
            anomaly_count = findings.get("anomaly_count", 0)
            result = {
                "summary": (
                    f"LLM unavailable. Raw findings: {error_count} errors, "
                    f"{anomaly_count} anomalies detected."
                ),
                "probable_root_cause": "Unable to determine (LLM unavailable)",
                "contributing_factors": [],
                "confidence": 0.0,
                "recommended_next_steps": ["Manual review required"],
                "source": "fallback",
            }

        logger.info(
            "investigation.audit",
            action="analyze_root_cause",
            target=alert_context.get("alert_name", ""),
            result="completed",
            confidence=result.get("confidence", 0.0),
            source=result.get("source", "unknown"),
        )

        return result

    # --- Private helpers ---

    @staticmethod
    def _default_metrics_for_resource(resource_id: str) -> list[str]:
        """Standard SRE metrics to check for any resource."""
        return [
            "container_cpu_usage_seconds_total",
            "container_memory_usage_bytes",
            "kube_pod_container_status_restarts_total",
            "container_network_receive_bytes_total",
        ]

    @staticmethod
    def _labels_from_resource_id(resource_id: str) -> dict[str, str]:
        """Extract Prometheus labels from a resource ID like 'namespace/pod'."""
        parts = resource_id.split("/", 1)
        if len(parts) == 2:
            return {"namespace": parts[0], "pod": parts[1]}
        return {"pod": parts[0]}

    @staticmethod
    def _format_labels(labels: dict[str, str]) -> str:
        """Format labels dict as PromQL selector string."""
        return ",".join(f'{k}="{v}"' for k, v in labels.items())
