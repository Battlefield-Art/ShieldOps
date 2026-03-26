"""Log Intelligence Agent runner -- entry point for multi-source log analysis."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.log_intelligence.graph import (
    create_log_intelligence_graph,
)
from shieldops.agents.log_intelligence.models import (
    LogIntelligenceState,
    LogSource,
)
from shieldops.agents.log_intelligence.nodes import (
    set_toolkit,
)
from shieldops.agents.log_intelligence.tools import (
    LogIntelligenceToolkit,
)

logger = structlog.get_logger()


class LogIntelligenceRunner:
    """Runner for the Log Intelligence Agent."""

    def __init__(
        self,
        splunk_client: Any | None = None,
        elastic_client: Any | None = None,
        cloudwatch_client: Any | None = None,
        gcp_logging_client: Any | None = None,
        datadog_client: Any | None = None,
        syslog_receiver: Any | None = None,
        threat_intel_feed: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = LogIntelligenceToolkit(
            splunk_client=splunk_client,
            elastic_client=elastic_client,
            cloudwatch_client=cloudwatch_client,
            gcp_logging_client=gcp_logging_client,
            datadog_client=datadog_client,
            syslog_receiver=syslog_receiver,
            threat_intel_feed=threat_intel_feed,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_log_intelligence_graph()
        self._app = graph.compile()
        self._results: dict[str, LogIntelligenceState] = {}
        logger.info("log_intelligence_runner.initialized")

    async def analyze(
        self,
        tenant_id: str,
        sources: list[LogSource] | None = None,
        time_range_hours: int = 24,
        query: str = "",
    ) -> LogIntelligenceState:
        """Run multi-source log intelligence analysis."""
        session_id = f"login-{uuid4().hex[:12]}"
        initial_state = LogIntelligenceState(
            tenant_id=tenant_id,
            sources=sources or [LogSource.CUSTOM],
            time_range_hours=time_range_hours,
            query=query,
        )

        logger.info(
            "log_intelligence_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            sources=[s.value for s in initial_state.sources],
            time_range_hours=time_range_hours,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "log_intelligence",
                    }
                },
            )
            final_state = LogIntelligenceState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "log_intelligence_runner.completed",
                session_id=session_id,
                logs_ingested=(final_state.logs_ingested),
                patterns=len(final_state.patterns_detected),
                threats=len(final_state.threats_correlated),
                insights=len(final_state.insights_generated),
                duration_ms=(final_state.session_duration_ms),
            )
            return final_state

        except Exception as e:
            logger.error(
                "log_intelligence_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = LogIntelligenceState(
                tenant_id=tenant_id,
                sources=sources or [LogSource.CUSTOM],
                time_range_hours=time_range_hours,
                query=query,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> LogIntelligenceState | None:
        """Retrieve a previous analysis result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results with summary."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "logs_ingested": state.logs_ingested,
                "patterns": len(state.patterns_detected),
                "threats": len(state.threats_correlated),
                "insights": len(state.insights_generated),
                "max_severity": state.max_severity,
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]
