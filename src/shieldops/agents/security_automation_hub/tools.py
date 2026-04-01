"""Tool functions for the Security Automation Hub.

Bridges trigger ingestion, playbook matching, automation
execution, validation, and learning to the LangGraph nodes.
"""

from __future__ import annotations

import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_automation_hub.models import (
    AutomationExecution,
    AutomationStatus,
    LearningOutcome,
    PlaybookMatch,
    SecurityTrigger,
    TriggerType,
    ValidationResult,
)

logger = structlog.get_logger()


class SecurityAutomationHubToolkit:
    """Tools for the security automation hub agent."""

    def __init__(
        self,
        trigger_source: Any | None = None,
        playbook_engine: Any | None = None,
        execution_engine: Any | None = None,
        validator: Any | None = None,
        learning_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._trigger_source = trigger_source
        self._playbook_engine = playbook_engine
        self._execution_engine = execution_engine
        self._validator = validator
        self._learning_store = learning_store
        self._repository = repository
        self._metrics: list[dict[str, Any]] = []

    # ---- Trigger Ingestion ----

    async def ingest_triggers(
        self,
        tenant_id: str = "",
        sources: list[str] | None = None,
    ) -> list[SecurityTrigger]:
        """Ingest security triggers from configured sources."""
        triggers: list[SecurityTrigger] = []
        now = datetime.now(UTC)

        if self._trigger_source is not None:
            try:
                raw = await self._trigger_source.collect(tenant_id=tenant_id, sources=sources)
                for item in raw:
                    triggers.append(
                        SecurityTrigger(
                            trigger_id=item.get("id", f"trg-{uuid4().hex[:8]}"),
                            trigger_type=TriggerType(item.get("type", "alert")),
                            source=item.get("source", ""),
                            severity=item.get("severity", "medium"),
                            title=item.get("title", ""),
                            description=item.get("description", ""),
                            payload=item.get("payload", {}),
                            timestamp=item.get("timestamp", now),
                            tenant_id=tenant_id,
                        )
                    )
            except Exception as e:
                logger.error("sah_trigger_ingestion_failed", error=str(e))
        else:
            # Mock trigger data
            trigger_types = list(TriggerType)
            severities = ["critical", "high", "medium", "low"]
            sources_list = [
                "siem",
                "edr",
                "ids",
                "waf",
                "cloudtrail",
                "threat_intel",
                "anomaly_engine",
            ]
            count = random.randint(3, 10)  # noqa: S311
            for _unused_i in range(count):
                ttype = random.choice(trigger_types)  # noqa: S311
                sev = random.choice(severities)  # noqa: S311
                src = random.choice(sources_list)  # noqa: S311
                triggers.append(
                    SecurityTrigger(
                        trigger_id=f"trg-{uuid4().hex[:8]}",
                        trigger_type=ttype,
                        source=src,
                        severity=sev,
                        title=f"{ttype.value} from {src}",
                        description=(
                            f"Security {ttype.value} detected by {src} with {sev} severity"
                        ),
                        payload={"mock": True},
                        timestamp=now,
                        tenant_id=tenant_id,
                    )
                )

        logger.info(
            "sah_triggers_ingested",
            tenant_id=tenant_id,
            count=len(triggers),
        )
        return triggers

    # ---- Playbook Matching ----

    async def match_playbooks(
        self,
        triggers: list[SecurityTrigger],
    ) -> list[PlaybookMatch]:
        """Match triggers to appropriate playbooks."""
        matches: list[PlaybookMatch] = []

        playbook_map = {
            TriggerType.ALERT: "alert_response",
            TriggerType.INCIDENT: "incident_response",
            TriggerType.POLICY_VIOLATION: "policy_remediation",
            TriggerType.THREAT_INTEL: "threat_hunting",
            TriggerType.ANOMALY: "anomaly_investigation",
            TriggerType.SCHEDULED: "scheduled_scan",
            TriggerType.MANUAL: "manual_response",
            TriggerType.WEBHOOK: "webhook_handler",
        }

        for trigger in triggers:
            playbook = playbook_map.get(trigger.trigger_type, "generic_response")
            confidence = round(
                random.uniform(0.6, 0.99),  # noqa: S311
                3,
            )
            actions = [
                "collect_evidence",
                "analyze_context",
                "execute_response",
                "verify_outcome",
            ]
            needs_approval = trigger.severity == "critical" or confidence < 0.7

            matches.append(
                PlaybookMatch(
                    match_id=f"match-{uuid4().hex[:8]}",
                    trigger_id=trigger.trigger_id,
                    playbook_name=playbook,
                    confidence=confidence,
                    actions=actions,
                    estimated_duration_ms=random.randint(  # noqa: S311
                        1000, 30000
                    ),
                    requires_approval=needs_approval,
                )
            )

        logger.info(
            "sah_playbooks_matched",
            triggers=len(triggers),
            matches=len(matches),
        )
        return matches

    # ---- Automation Execution ----

    async def execute_automations(
        self,
        matches: list[PlaybookMatch],
    ) -> list[AutomationExecution]:
        """Execute matched playbook automations."""
        executions: list[AutomationExecution] = []

        for match in matches:
            if match.requires_approval:
                status = AutomationStatus.REQUIRES_APPROVAL
                completed = 0
            else:
                roll = random.random()  # noqa: S311
                if roll > 0.15:
                    status = AutomationStatus.COMPLETED
                    completed = len(match.actions)
                else:
                    status = AutomationStatus.FAILED
                    completed = random.randint(  # noqa: S311
                        0, len(match.actions) - 1
                    )

            executions.append(
                AutomationExecution(
                    execution_id=f"exec-{uuid4().hex[:8]}",
                    playbook_name=match.playbook_name,
                    trigger_id=match.trigger_id,
                    status=status,
                    actions_completed=completed,
                    actions_total=len(match.actions),
                    duration_ms=random.randint(500, 15000),  # noqa: S311
                    output={"mock": True, "match_id": match.match_id},
                )
            )

        logger.info(
            "sah_automations_executed",
            matches=len(matches),
            executions=len(executions),
            completed=sum(1 for e in executions if e.status == AutomationStatus.COMPLETED),
        )
        return executions

    # ---- Validation ----

    async def validate_results(
        self,
        executions: list[AutomationExecution],
    ) -> list[ValidationResult]:
        """Validate automation execution results."""
        validations: list[ValidationResult] = []

        for execution in executions:
            if execution.status != AutomationStatus.COMPLETED:
                continue

            checks_total = random.randint(3, 8)  # noqa: S311
            checks_passed = random.randint(  # noqa: S311
                checks_total - 1, checks_total
            )
            issues: list[str] = []
            if checks_passed < checks_total:
                issues.append(f"{checks_total - checks_passed} checks failed")

            validations.append(
                ValidationResult(
                    validation_id=f"val-{uuid4().hex[:8]}",
                    execution_id=execution.execution_id,
                    passed=checks_passed == checks_total,
                    checks_passed=checks_passed,
                    checks_total=checks_total,
                    issues=issues,
                )
            )

        logger.info(
            "sah_results_validated",
            executions=len(executions),
            validations=len(validations),
            passed=sum(1 for v in validations if v.passed),
        )
        return validations

    # ---- Learning ----

    async def learn_outcomes(
        self,
        executions: list[AutomationExecution],
        validations: list[ValidationResult],
    ) -> list[LearningOutcome]:
        """Extract learning outcomes from automation cycle."""
        learnings: list[LearningOutcome] = []

        validation_map = {v.execution_id: v for v in validations}

        for execution in executions:
            val = validation_map.get(execution.execution_id)
            if val and val.passed:
                score = round(  # noqa: S311
                    random.uniform(0.7, 1.0),  # noqa: S311
                    3,  # noqa: S311
                )
                lessons = [f"Playbook {execution.playbook_name} effective"]
            elif val:
                score = round(  # noqa: S311
                    random.uniform(0.3, 0.7),  # noqa: S311
                    3,  # noqa: S311
                )
                lessons = [
                    f"Playbook {execution.playbook_name} partially effective",
                    *val.issues,
                ]
            else:
                score = round(  # noqa: S311
                    random.uniform(0.0, 0.3),  # noqa: S311
                    3,  # noqa: S311
                )
                lessons = [f"Playbook {execution.playbook_name} did not complete"]

            learnings.append(
                LearningOutcome(
                    outcome_id=f"learn-{uuid4().hex[:8]}",
                    execution_id=execution.execution_id,
                    effectiveness_score=score,
                    lessons=lessons,
                    recommended_changes=[],
                )
            )

        logger.info(
            "sah_outcomes_learned",
            executions=len(executions),
            learnings=len(learnings),
        )
        return learnings

    # ---- Metrics ----

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a security automation hub metric."""
        self._metrics.append(
            {
                "name": metric_name,
                "value": value,
                "tags": tags or {},
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
