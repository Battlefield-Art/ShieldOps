"""Investigation Agent runner — entry point for executing investigations.

Takes an AlertContext, constructs the LangGraph, runs it end-to-end,
and returns the completed investigation state.

Production features:
- OPA policy gate before execution
- Connector health checks at startup
- Result persistence via persist_agent_run() and write_audit_log()
- Structured logging with investigation.* pattern
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.investigation.graph import create_investigation_graph
from shieldops.agents.investigation.models import InvestigationState
from shieldops.agents.investigation.nodes import set_toolkit
from shieldops.agents.investigation.tools import InvestigationToolkit
from shieldops.connectors.base import ConnectorRouter
from shieldops.connectors.health import (
    AllConnectorsUnavailableError,
    ConnectorStatus,
    check_agent_connectors,
)
from shieldops.models.base import AlertContext
from shieldops.observability.base import LogSource, MetricSource, TraceSource
from shieldops.observability.tracing import get_tracer
from shieldops.utils.persistence import persist_agent_run, write_audit_log

if __import__("typing").TYPE_CHECKING:
    from shieldops.policy.opa.client import PolicyEngine

logger = structlog.get_logger()

# Connectors the investigation agent relies on for full functionality.
# Degraded operation is possible when some are unavailable.
_REQUIRED_CONNECTORS = ["kubernetes", "splunk", "crowdstrike"]


class InvestigationRunner:
    """Runs investigation agent workflows.

    Usage:
        runner = InvestigationRunner(
            connector_router=router,
            log_sources=[k8s_logs],
            metric_sources=[prometheus],
            policy_engine=policy_engine,
        )
        result = await runner.investigate(alert_context)
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        log_sources: list[LogSource] | None = None,
        metric_sources: list[MetricSource] | None = None,
        trace_sources: list[TraceSource] | None = None,
        repository: Any | None = None,
        ws_manager: "object | None" = None,
        policy_engine: "PolicyEngine | None" = None,
    ) -> None:
        self._toolkit = InvestigationToolkit(
            connector_router=connector_router,
            log_sources=log_sources or [],
            metric_sources=metric_sources or [],
            trace_sources=trace_sources or [],
            repository=repository,
        )
        # Configure the module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build the compiled graph
        graph = create_investigation_graph()
        self._app = graph.compile()

        # In-memory store of completed investigations (fallback when no DB)
        self._investigations: dict[str, InvestigationState] = {}
        self._repository = repository
        self._ws_manager = ws_manager
        self._policy_engine = policy_engine

    async def _check_policy(
        self,
        action: str,
        target: str,
        environment: str = "production",
    ) -> dict[str, Any] | None:
        """Evaluate OPA policy before an investigation action.

        Returns None if allowed (or no policy engine configured).
        Returns an error dict if denied.
        """
        if self._policy_engine is None:
            return None

        try:
            from shieldops.models.base import Environment, RemediationAction, RiskLevel

            # Build a lightweight RemediationAction for policy evaluation
            env = (
                Environment(environment)
                if environment in Environment.__members__.values()
                else Environment.PRODUCTION
            )
            policy_action = RemediationAction(
                id=f"inv-policy-{uuid4().hex[:8]}",
                action_type=action,
                target_resource=target,
                environment=env,
                risk_level=RiskLevel.LOW,
                parameters={"agent_type": "investigation"},
                description=f"Investigation action: {action}",
            )

            evaluation = await self._policy_engine.evaluate(
                action=policy_action,
                agent_id="investigation",
                context={
                    "agent_type": "investigation",
                    "action": action,
                    "target_resource": target,
                    "environment": environment,
                },
            )

            if not evaluation.allowed:
                logger.warning(
                    "investigation.policy_denied",
                    action=action,
                    target=target,
                    reasons=evaluation.reasons,
                )
                return {"error": f"Policy denied: {evaluation.reasons}"}

            logger.info(
                "investigation.policy_allowed",
                action=action,
                target=target,
            )
        except Exception as e:
            # Fail open for read-only investigation queries — log the failure
            # but allow the investigation to proceed. Remediation actions are
            # separately gated in the graph's recommend_action node.
            logger.error(
                "investigation.policy_evaluation_error",
                action=action,
                target=target,
                error=str(e),
            )

        return None

    async def _check_connector_health(self, investigation_id: str) -> dict[str, Any]:
        """Check health of required connectors before investigation.

        Returns a dict of connector statuses. Logs warnings for degraded
        connectors and raises on total unavailability.
        """
        try:
            statuses = await check_agent_connectors(
                agent_name="investigation",
                required_connectors=_REQUIRED_CONNECTORS,
            )
            healthy = [name for name, s in statuses.items() if s.status == ConnectorStatus.HEALTHY]
            degraded = [name for name, s in statuses.items() if s.status != ConnectorStatus.HEALTHY]
            logger.info(
                "investigation.connector_health",
                investigation_id=investigation_id,
                healthy=healthy,
                degraded=degraded,
            )
            return {
                "healthy": healthy,
                "degraded": degraded,
                "statuses": {name: s.status.value for name, s in statuses.items()},
            }
        except AllConnectorsUnavailableError:
            logger.error(
                "investigation.all_connectors_unavailable",
                investigation_id=investigation_id,
                connectors=_REQUIRED_CONNECTORS,
            )
            raise
        except Exception as e:
            # Non-fatal: continue with degraded mode if health check itself fails
            logger.warning(
                "investigation.connector_health_check_failed",
                investigation_id=investigation_id,
                error=str(e),
            )
            return {"healthy": [], "degraded": _REQUIRED_CONNECTORS, "error": str(e)}

    async def investigate(self, alert: AlertContext) -> InvestigationState:
        """Run a full investigation for an alert.

        Args:
            alert: The alert context that triggered this investigation.

        Returns:
            The completed InvestigationState with hypotheses and reasoning chain.
        """
        investigation_id = f"inv-{uuid4().hex[:12]}"

        logger.info(
            "investigation.started",
            investigation_id=investigation_id,
            alert_id=alert.alert_id,
            alert_name=alert.alert_name,
            severity=alert.severity,
        )

        # OPA policy check: verify the investigation itself is allowed
        environment = alert.labels.get("environment", "production")
        policy_result = await self._check_policy(
            action="investigate",
            target=alert.resource_id or alert.alert_id,
            environment=environment,
        )
        if policy_result and "error" in policy_result:
            error_state = InvestigationState(
                alert_id=alert.alert_id,
                alert_context=alert,
                error=policy_result["error"],
                current_step="policy_denied",
            )
            self._investigations[investigation_id] = error_state
            return error_state

        # Connector health check: verify required connectors are available
        connector_health = await self._check_connector_health(investigation_id)

        initial_state = InvestigationState(
            alert_id=alert.alert_id,
            alert_context=alert,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("investigation.run") as span:
                span.set_attribute("investigation.id", investigation_id)
                span.set_attribute("investigation.alert_id", alert.alert_id)
                span.set_attribute("investigation.alert_name", alert.alert_name)
                span.set_attribute("investigation.severity", alert.severity)

                # Run the LangGraph workflow
                final_state_dict = await self._app.ainvoke(
                    initial_state.model_dump(),  # type: ignore[arg-type]
                    config={
                        "metadata": {
                            "investigation_id": investigation_id,
                            "alert_id": alert.alert_id,
                        },
                    },
                )

                final_state = InvestigationState.model_validate(final_state_dict)

                # Calculate total duration
                if final_state.investigation_start:
                    final_state.investigation_duration_ms = int(
                        (datetime.now(UTC) - final_state.investigation_start).total_seconds() * 1000
                    )

                span.set_attribute(
                    "investigation.duration_ms", final_state.investigation_duration_ms
                )
                span.set_attribute("investigation.hypotheses_count", len(final_state.hypotheses))
                span.set_attribute("investigation.confidence", final_state.confidence_score)

            logger.info(
                "investigation.completed",
                investigation_id=investigation_id,
                alert_id=alert.alert_id,
                duration_ms=final_state.investigation_duration_ms,
                hypotheses_count=len(final_state.hypotheses),
                confidence=final_state.confidence_score,
                steps=len(final_state.reasoning_chain),
            )

            # Audit trail: immutable record of investigation outcome
            logger.info(
                "investigation.audit",
                action="investigate",
                investigation_id=investigation_id,
                target=alert.alert_id,
                result="completed",
                findings_count=(
                    len(final_state.log_findings)
                    + len(final_state.metric_anomalies)
                    + len(final_state.correlated_events)
                ),
                hypotheses_count=len(final_state.hypotheses),
                confidence=final_state.confidence_score,
                duration_ms=final_state.investigation_duration_ms,
                environment=environment,
                connector_health=connector_health,
            )

            # Store result in memory + repository
            self._investigations[investigation_id] = final_state
            await self._persist(investigation_id, final_state)
            await self._broadcast(investigation_id, final_state)

            # Persist agent run and audit log via utils/persistence.py
            org_id = alert.labels.get("org_id", "default")
            await persist_agent_run(
                agent_name="investigation",
                org_id=org_id,
                input_data={
                    "alert_id": alert.alert_id,
                    "alert_name": alert.alert_name,
                    "severity": alert.severity,
                    "resource_id": alert.resource_id,
                },
                output_data={
                    "investigation_id": investigation_id,
                    "hypotheses_count": len(final_state.hypotheses),
                    "confidence": final_state.confidence_score,
                    "top_hypothesis": (
                        final_state.hypotheses[0].description[:200]
                        if final_state.hypotheses
                        else None
                    ),
                },
                duration_ms=final_state.investigation_duration_ms,
            )
            await write_audit_log(
                action="investigation.completed",
                actor="investigation-agent",
                target=alert.alert_id,
                result="completed",
                org_id=org_id,
                metadata={
                    "investigation_id": investigation_id,
                    "confidence": final_state.confidence_score,
                    "hypotheses_count": len(final_state.hypotheses),
                    "duration_ms": final_state.investigation_duration_ms,
                    "environment": environment,
                },
            )

            return final_state

        except Exception as e:
            logger.error(
                "investigation.failed",
                investigation_id=investigation_id,
                alert_id=alert.alert_id,
                error=str(e),
            )
            # Audit trail for failed investigations
            logger.info(
                "investigation.audit",
                action="investigate",
                investigation_id=investigation_id,
                target=alert.alert_id,
                result="failed",
                error=str(e),
                environment=environment,
            )
            # Return partial state with error
            error_state = InvestigationState(
                alert_id=alert.alert_id,
                alert_context=alert,
                error=str(e),
                current_step="failed",
            )
            self._investigations[investigation_id] = error_state
            await self._persist(investigation_id, error_state)

            # Persist failed run
            org_id = alert.labels.get("org_id", "default")
            await persist_agent_run(
                agent_name="investigation",
                org_id=org_id,
                input_data={
                    "alert_id": alert.alert_id,
                    "alert_name": alert.alert_name,
                },
                error_message=str(e),
            )
            await write_audit_log(
                action="investigation.failed",
                actor="investigation-agent",
                target=alert.alert_id,
                result="failed",
                org_id=org_id,
                metadata={
                    "investigation_id": investigation_id,
                    "error": str(e),
                    "environment": environment,
                },
            )

            return error_state

    async def _broadcast(self, investigation_id: str, state: InvestigationState) -> None:
        """Broadcast progress via WebSocket if manager is available."""
        if self._ws_manager is None:
            return
        try:
            event = {
                "type": "investigation_update",
                "investigation_id": investigation_id,
                "status": state.current_step,
                "confidence": state.confidence_score,
                "hypotheses_count": len(state.hypotheses),
            }
            await self._ws_manager.broadcast("global", event)  # type: ignore[attr-defined]
            await self._ws_manager.broadcast(f"investigation:{investigation_id}", event)  # type: ignore[attr-defined]
        except Exception as e:
            logger.warning("ws_broadcast_failed", id=investigation_id, error=str(e))

    async def _persist(self, investigation_id: str, state: InvestigationState) -> None:
        """Persist to DB if repository is available."""
        if self._repository is None:
            return
        try:
            await self._repository.save_investigation(investigation_id, state)
        except Exception as e:
            logger.error("investigation_persist_failed", id=investigation_id, error=str(e))

    def get_investigation(self, investigation_id: str) -> InvestigationState | None:
        """Retrieve a completed investigation by ID."""
        return self._investigations.get(investigation_id)

    def list_investigations(self) -> list[dict[str, Any]]:
        """List all investigations with summary info."""
        return [
            {
                "investigation_id": inv_id,
                "alert_id": state.alert_id,
                "alert_name": state.alert_context.alert_name,
                "status": state.current_step,
                "confidence": state.confidence_score,
                "hypotheses_count": len(state.hypotheses),
                "duration_ms": state.investigation_duration_ms,
                "error": state.error,
            }
            for inv_id, state in self._investigations.items()
        ]
