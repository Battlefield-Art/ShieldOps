"""Log Analyzer Agent runner — entry point for executing log analysis workflows."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.log_analyzer.graph import create_log_analyzer_graph
from shieldops.agents.log_analyzer.models import LogAnalyzerState, LogSource
from shieldops.agents.log_analyzer.nodes import set_toolkit
from shieldops.agents.log_analyzer.tools import LogAnalyzerToolkit

logger = structlog.get_logger()


class LogAnalyzerRunner:
    """Runner for the Log Analyzer Agent."""

    def __init__(
        self,
        log_backend: Any | None = None,
        pattern_engine: Any | None = None,
        anomaly_detector: Any | None = None,
        correlation_engine: Any | None = None,
        alert_manager: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = LogAnalyzerToolkit(
            log_backend=log_backend,
            pattern_engine=pattern_engine,
            anomaly_detector=anomaly_detector,
            correlation_engine=correlation_engine,
            alert_manager=alert_manager,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_log_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, LogAnalyzerState] = {}
        logger.info("log_analyzer_runner.initialized")

    async def analyze(
        self,
        tenant_id: str,
        sources: list[LogSource] | None = None,
        time_range_hours: int = 24,
    ) -> LogAnalyzerState:
        """Run log analysis for a tenant."""
        session_id = f"logaz-{uuid4().hex[:12]}"
        initial_state = LogAnalyzerState(
            tenant_id=tenant_id,
            sources=sources or [LogSource.APPLICATION],
            time_range_hours=time_range_hours,
        )

        logger.info(
            "log_analyzer_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            sources=[s.value for s in initial_state.sources],
            time_range_hours=time_range_hours,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={"metadata": {"session_id": session_id, "agent": "log_analyzer"}},
            )
            final_state = LogAnalyzerState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "log_analyzer_runner.completed",
                session_id=session_id,
                anomaly_count=len(final_state.anomalies),
                max_severity=final_state.max_severity,
                alerts_sent=final_state.alerts_sent,
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error("log_analyzer_runner.failed", session_id=session_id, error=str(e))
            error_state = LogAnalyzerState(
                tenant_id=tenant_id,
                sources=sources or [LogSource.APPLICATION],
                time_range_hours=time_range_hours,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> LogAnalyzerState | None:
        """Retrieve a previous analysis result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results with summary metadata."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "anomaly_count": len(state.anomalies),
                "max_severity": state.max_severity,
                "alerts_sent": state.alerts_sent,
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]
