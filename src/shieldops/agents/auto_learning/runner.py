"""Auto Learning Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import AutoLearningToolkit

logger = structlog.get_logger()


class AutoLearningRunner:
    """Runs the Auto Learning agent workflow."""

    def __init__(
        self,
        metrics_store: Any | None = None,
        config_store: Any | None = None,
        experiment_runner: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AutoLearningToolkit(
            metrics_store=metrics_store,
            config_store=config_store,
            experiment_runner=experiment_runner,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("auto_learning_runner.init")

    async def run(
        self,
        max_iterations: int = 10,
        budget_seconds: int = 300,
        budget_api_calls: int = 50,
    ) -> dict[str, Any]:
        """Execute the auto-learning loop."""
        initial_state = {
            "request_id": "",
            "iteration": 0,
            "max_iterations": max_iterations,
            "budget": {
                "max_duration_seconds": budget_seconds,
                "max_api_calls": budget_api_calls,
                "max_memory_mb": 256,
                "max_concurrent": 1,
            },
            "reasoning_chain": [],
        }
        logger.info(
            "auto_learning_runner.run",
            max_iterations=max_iterations,
            budget_seconds=budget_seconds,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("auto_learning_runner.run.error")
            raise

    async def run_continuous(
        self,
        max_iterations: int = 100,
        stop_on_plateau: bool = True,
    ) -> list[dict[str, Any]]:
        """Run multiple learning iterations (overnight autonomous mode)."""
        all_results: list[dict[str, Any]] = []
        consecutive_rejections = 0

        for i in range(max_iterations):
            logger.info("auto_learning_runner.iteration", iteration=i)
            result = await self.run(max_iterations=1)
            all_results.append(result)

            accepted = len(result.get("accepted_changes", []))
            if accepted == 0:
                consecutive_rejections += 1
            else:
                consecutive_rejections = 0

            if stop_on_plateau and consecutive_rejections >= 3:
                logger.info(
                    "auto_learning_runner.plateau_detected",
                    iteration=i,
                    consecutive_rejections=consecutive_rejections,
                )
                break

        return all_results

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist learning run results."""
        if self._repository:
            await self._repository.save_learning_run(result)
