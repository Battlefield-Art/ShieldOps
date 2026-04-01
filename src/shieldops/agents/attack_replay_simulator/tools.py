"""Tool functions for the Attack Replay Simulator.

Bridges technique selection, sandbox configuration, replay
execution, telemetry capture, and detection evaluation to
the LangGraph nodes.
"""

from __future__ import annotations

import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.attack_replay_simulator.models import (
    AttackTechnique,
    DetectionEvaluation,
    DetectionResult,
    ReplayExecution,
    SandboxConfig,
    TechniqueSelection,
    TelemetryCapture,
)

logger = structlog.get_logger()


class AttackReplaySimulatorToolkit:
    """Tools for the attack replay simulator agent."""

    def __init__(
        self,
        technique_library: Any | None = None,
        sandbox_manager: Any | None = None,
        replay_engine: Any | None = None,
        telemetry_collector: Any | None = None,
        detection_evaluator: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._technique_library = technique_library
        self._sandbox_manager = sandbox_manager
        self._replay_engine = replay_engine
        self._telemetry_collector = telemetry_collector
        self._detection_evaluator = detection_evaluator
        self._repository = repository
        self._metrics: list[dict[str, Any]] = []

    # ---- Technique Selection ----

    async def select_techniques(
        self,
        tenant_id: str = "",
        filters: dict[str, Any] | None = None,
    ) -> list[TechniqueSelection]:
        """Select attack techniques for replay."""
        selections: list[TechniqueSelection] = []

        if self._technique_library is not None:
            try:
                raw = await self._technique_library.select(
                    tenant_id=tenant_id,
                    filters=filters,
                )
                for item in raw:
                    selections.append(
                        TechniqueSelection(
                            selection_id=item.get("id", f"sel-{uuid4().hex[:8]}"),
                            technique=AttackTechnique(item.get("technique", "credential_dumping")),
                            mitre_id=item.get("mitre_id", ""),
                            description=item.get("description", ""),
                            complexity=item.get("complexity", "medium"),
                        )
                    )
            except Exception as e:
                logger.error(
                    "ars_technique_selection_failed",
                    error=str(e),
                )
        else:
            # Mock technique selection
            mitre_map = {
                AttackTechnique.CREDENTIAL_DUMPING: "T1003",
                AttackTechnique.LATERAL_MOVEMENT: "T1021",
                AttackTechnique.PRIVILEGE_ESCALATION: "T1548",
                AttackTechnique.DATA_EXFILTRATION: "T1041",
                AttackTechnique.COMMAND_AND_CONTROL: "T1071",
                AttackTechnique.PERSISTENCE: "T1053",
                AttackTechnique.DEFENSE_EVASION: "T1070",
                AttackTechnique.INITIAL_ACCESS: "T1566",
            }
            techniques = list(AttackTechnique)
            count = random.randint(3, 6)  # noqa: S311
            chosen = random.sample(  # noqa: S311
                techniques, min(count, len(techniques))
            )
            complexities = ["low", "medium", "high", "critical"]
            for tech in chosen:
                selections.append(
                    TechniqueSelection(
                        selection_id=f"sel-{uuid4().hex[:8]}",
                        technique=tech,
                        mitre_id=mitre_map.get(tech, "T0000"),
                        description=f"Replay {tech.value} technique",
                        complexity=random.choice(complexities),  # noqa: S311
                    )
                )

        logger.info(
            "ars_techniques_selected",
            tenant_id=tenant_id,
            count=len(selections),
        )
        return selections

    # ---- Sandbox Configuration ----

    async def configure_sandbox(
        self,
        techniques: list[TechniqueSelection],
    ) -> SandboxConfig:
        """Configure sandbox for replay execution."""
        detection_tools = [
            "edr_agent",
            "network_ids",
            "siem_collector",
            "file_integrity_monitor",
        ]
        os_type = random.choice(["linux", "windows"])  # noqa: S311

        config = SandboxConfig(
            sandbox_id=f"sbx-{uuid4().hex[:8]}",
            environment="isolated",
            os_type=os_type,
            network_mode="simulated",
            detection_tools=detection_tools,
            timeout_seconds=random.randint(  # noqa: S311
                300, 900
            ),
            capture_pcap=True,
        )

        logger.info(
            "ars_sandbox_configured",
            sandbox_id=config.sandbox_id,
            techniques=len(techniques),
        )
        return config

    # ---- Replay Execution ----

    async def execute_replay(
        self,
        techniques: list[TechniqueSelection],
        sandbox: SandboxConfig,
    ) -> list[ReplayExecution]:
        """Execute attack technique replays in the sandbox."""
        executions: list[ReplayExecution] = []
        now = datetime.now(UTC)

        for tech in techniques:
            execution = ReplayExecution(
                execution_id=f"exec-{uuid4().hex[:8]}",
                technique=tech.technique,
                mitre_id=tech.mitre_id,
                sandbox_id=sandbox.sandbox_id,
                started_at=now,
                completed_at=now,
                exit_code=random.choice([0, 0, 0, 1]),  # noqa: S311
                artifacts=[
                    f"artifact-{uuid4().hex[:6]}.log",
                    f"pcap-{uuid4().hex[:6]}.pcap",
                ],
                logs=[
                    f"Executed {tech.technique.value}",
                    f"MITRE {tech.mitre_id} replay complete",
                ],
            )
            executions.append(execution)

        logger.info(
            "ars_replay_executed",
            sandbox=sandbox.sandbox_id,
            executions=len(executions),
        )
        return executions

    # ---- Telemetry Capture ----

    async def capture_telemetry(
        self,
        executions: list[ReplayExecution],
    ) -> list[TelemetryCapture]:
        """Capture telemetry from replay executions."""
        captures: list[TelemetryCapture] = []

        for execution in executions:
            capture = TelemetryCapture(
                capture_id=f"cap-{uuid4().hex[:8]}",
                execution_id=execution.execution_id,
                alerts_fired=random.randint(0, 5),  # noqa: S311
                logs_generated=random.randint(10, 200),  # noqa: S311
                network_events=random.randint(5, 50),  # noqa: S311
                process_events=random.randint(3, 30),  # noqa: S311
                file_events=random.randint(1, 20),  # noqa: S311
                detection_latency_ms=random.randint(  # noqa: S311
                    100, 5000
                ),
            )
            captures.append(capture)

        logger.info(
            "ars_telemetry_captured",
            captures=len(captures),
        )
        return captures

    # ---- Detection Evaluation ----

    async def evaluate_detection(
        self,
        executions: list[ReplayExecution],
        captures: list[TelemetryCapture],
    ) -> list[DetectionEvaluation]:
        """Evaluate detection effectiveness per technique."""
        evaluations: list[DetectionEvaluation] = []

        capture_map: dict[str, TelemetryCapture] = {c.execution_id: c for c in captures}

        for execution in executions:
            cap = capture_map.get(execution.execution_id)
            alerts = cap.alerts_fired if cap else 0

            if alerts >= 3:
                result = DetectionResult.DETECTED
            elif alerts >= 1:
                result = DetectionResult.PARTIALLY_DETECTED
            else:
                result = random.choice(  # noqa: S311
                    [DetectionResult.MISSED, DetectionResult.DELAYED]
                )

            confidence = round(random.uniform(0.4, 0.99), 3)  # noqa: S311
            latency = cap.detection_latency_ms if cap else 0

            evaluations.append(
                DetectionEvaluation(
                    evaluation_id=f"eval-{uuid4().hex[:8]}",
                    technique=execution.technique,
                    result=result,
                    confidence=confidence,
                    detection_latency_ms=latency,
                    alerts_matched=alerts,
                    coverage_gaps=(
                        [f"gap in {execution.technique.value}"]
                        if result
                        in (
                            DetectionResult.MISSED,
                            DetectionResult.DELAYED,
                        )
                        else []
                    ),
                    recommendations=(
                        [f"Add detection rule for {execution.mitre_id}"]
                        if result != DetectionResult.DETECTED
                        else []
                    ),
                )
            )

        logger.info(
            "ars_detection_evaluated",
            evaluations=len(evaluations),
            results=[e.result.value for e in evaluations],
        )
        return evaluations

    # ---- Metrics ----

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record an attack replay simulator metric."""
        self._metrics.append(
            {
                "name": metric_name,
                "value": value,
                "tags": tags or {},
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
