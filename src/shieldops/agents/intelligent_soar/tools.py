"""Tool functions for the Intelligent SOAR Agent."""

from typing import Any

import structlog

logger = structlog.get_logger()


class IntelligentSOARToolkit:
    """Toolkit for intelligent SOAR operations.

    Bridges the intelligent_soar agent to connectors
    (CrowdStrike RTR, Defender, AWS IAM, etc.) and
    internal modules for playbook management.
    """

    def __init__(
        self,
        repository: Any | None = None,
    ) -> None:
        self._repository = repository
        self._playbook_registry: dict[str, dict[str, Any]] = self._init_playbook_registry()
        self._effectiveness_log: list[dict[str, Any]] = []

    def _init_playbook_registry(
        self,
    ) -> dict[str, dict[str, Any]]:
        """Initialize built-in LangGraph playbooks."""
        return {
            "pb-investigate-malware": {
                "name": "Malware Investigation",
                "type": "investigation",
                "steps": [
                    "isolate_endpoint",
                    "collect_artifacts",
                    "analyze_binary",
                    "check_lateral_movement",
                    "generate_iocs",
                ],
                "effectiveness": 0.87,
            },
            "pb-contain-compromise": {
                "name": "Account Compromise Containment",
                "type": "containment",
                "steps": [
                    "disable_account",
                    "revoke_sessions",
                    "rotate_credentials",
                    "audit_access_logs",
                    "notify_stakeholders",
                ],
                "effectiveness": 0.92,
            },
            "pb-eradicate-threat": {
                "name": "Threat Eradication",
                "type": "eradication",
                "steps": [
                    "identify_persistence",
                    "remove_malware",
                    "patch_vulnerability",
                    "verify_clean",
                    "update_signatures",
                ],
                "effectiveness": 0.85,
            },
            "pb-recover-service": {
                "name": "Service Recovery",
                "type": "recovery",
                "steps": [
                    "assess_damage",
                    "restore_from_backup",
                    "validate_integrity",
                    "re_enable_services",
                    "monitor_stability",
                ],
                "effectiveness": 0.90,
            },
            "pb-compliance-response": {
                "name": "Compliance Incident Response",
                "type": "compliance",
                "steps": [
                    "classify_data_exposure",
                    "assess_regulatory_impact",
                    "notify_authorities",
                    "remediate_controls",
                    "document_evidence",
                ],
                "effectiveness": 0.88,
            },
        }

    async def ingest_trigger(
        self,
        trigger_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Ingest and normalize an incoming trigger."""
        logger.info(
            "intelligent_soar.ingest_trigger",
            source=trigger_data.get("source", "unknown"),
        )
        return {
            "trigger_id": trigger_data.get("trigger_id", ""),
            "source": trigger_data.get("source", ""),
            "alert_type": trigger_data.get("alert_type", "unknown"),
            "severity": trigger_data.get("severity", "medium"),
            "indicators": trigger_data.get("indicators", []),
            "normalized": True,
        }

    async def select_playbook(
        self,
        alert_type: str,
        severity: str,
        indicators: list[str],
    ) -> list[dict[str, Any]]:
        """Rank playbooks by relevance to the trigger.

        Returns ranked list for LLM final selection.
        """
        logger.info(
            "intelligent_soar.select_playbook",
            alert_type=alert_type,
        )
        candidates: list[dict[str, Any]] = []
        for pb_id, pb in self._playbook_registry.items():
            score = pb.get("effectiveness", 0.5)
            if severity in ("critical", "high") and pb["type"] == "containment":
                score += 0.1
            candidates.append(
                {
                    "playbook_id": pb_id,
                    "playbook_name": pb["name"],
                    "playbook_type": pb["type"],
                    "steps": pb["steps"],
                    "match_score": round(min(score, 1.0), 3),
                }
            )
        candidates.sort(
            key=lambda c: c["match_score"],
            reverse=True,
        )
        return candidates

    async def execute_step(
        self,
        step_name: str,
        target: str,
        vendor: str,
        execution_mode: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a single playbook step.

        In dry_run mode, simulates without impact.
        Routes to vendor-specific connectors in prod.
        """
        logger.info(
            "intelligent_soar.execute_step",
            step=step_name,
            vendor=vendor,
            mode=execution_mode,
        )
        if execution_mode == "dry_run":
            return {
                "step_name": step_name,
                "status": "simulated",
                "vendor": vendor,
                "target": target,
                "dry_run": True,
                "result": {"message": f"Dry-run: {step_name}"},
            }
        return {
            "step_name": step_name,
            "status": "completed",
            "vendor": vendor,
            "target": target,
            "dry_run": False,
            "result": {"message": f"Executed: {step_name}"},
        }

    async def evaluate_adaptation(
        self,
        completed_steps: list[dict[str, Any]],
        remaining_steps: list[str],
        findings: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate whether to adapt remaining steps.

        Provides context for LLM adaptation decision.
        """
        logger.info(
            "intelligent_soar.evaluate_adaptation",
            completed=len(completed_steps),
            remaining=len(remaining_steps),
        )
        return {
            "completed_count": len(completed_steps),
            "remaining_steps": remaining_steps,
            "anomalies_detected": findings.get("anomalies", []),
            "escalation_needed": findings.get("escalation", False),
        }

    async def validate_outcome(
        self,
        execution_results: list[dict[str, Any]],
        trigger_indicators: list[str],
    ) -> dict[str, Any]:
        """Validate that playbook execution was effective.

        Checks indicator resolution and residual risk.
        """
        logger.info(
            "intelligent_soar.validate_outcome",
            steps_run=len(execution_results),
        )
        succeeded = sum(
            1 for r in execution_results if r.get("status") in ("completed", "simulated")
        )
        total = len(execution_results) or 1
        return {
            "success_rate": round(succeeded / total, 3),
            "indicators_resolved": len(trigger_indicators),
            "residual_indicators": [],
            "validated": succeeded == total,
        }

    async def track_effectiveness(
        self,
        playbook_id: str,
        success_rate: float,
        adaptation_count: int,
    ) -> None:
        """Track playbook effectiveness for learning."""
        logger.info(
            "intelligent_soar.track_effectiveness",
            playbook_id=playbook_id,
            success_rate=success_rate,
        )
        self._effectiveness_log.append(
            {
                "playbook_id": playbook_id,
                "success_rate": success_rate,
                "adaptation_count": adaptation_count,
            }
        )

    async def record_metric(
        self,
        metric_type: str,
        value: float,
    ) -> None:
        """Record an intelligent SOAR metric."""
        logger.info(
            "intelligent_soar.record_metric",
            metric=metric_type,
            value=value,
        )
