"""Tool functions for the Security Automation Agent.

Provides alert triage, playbook matching, containment execution,
validation, and learning record capabilities.
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_automation.models import (
    ContainmentAction,
    ContainmentResult,
    LearningOutcome,
    PlaybookCandidate,
    PlaybookMatch,
    RiskAlert,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Playbook registry (in production this would be loaded from a DB/YAML)
# ---------------------------------------------------------------------------

_PLAYBOOK_REGISTRY: list[dict[str, Any]] = [
    {
        "playbook_id": "pb-host-isolate-001",
        "name": "Host Isolation — Lateral Movement",
        "tactics": ["lateral_movement", "execution", "command_and_control"],
        "entity_types": ["host"],
        "actions": [
            ContainmentAction.ISOLATE_HOST,
            ContainmentAction.REVOKE_TOKEN,
        ],
        "estimated_duration_seconds": 30,
    },
    {
        "playbook_id": "pb-account-disable-001",
        "name": "Account Disable — Compromised Credentials",
        "tactics": [
            "credential_access",
            "initial_access",
            "privilege_escalation",
        ],
        "entity_types": ["user"],
        "actions": [
            ContainmentAction.DISABLE_ACCOUNT,
            ContainmentAction.REVOKE_TOKEN,
        ],
        "estimated_duration_seconds": 15,
    },
    {
        "playbook_id": "pb-ip-block-001",
        "name": "IP Block — External Threat",
        "tactics": [
            "initial_access",
            "command_and_control",
            "exfiltration",
        ],
        "entity_types": ["ip"],
        "actions": [ContainmentAction.BLOCK_IP],
        "estimated_duration_seconds": 10,
    },
    {
        "playbook_id": "pb-file-quarantine-001",
        "name": "File Quarantine — Malware Detected",
        "tactics": ["execution", "persistence", "defense_evasion"],
        "entity_types": ["host", "service"],
        "actions": [
            ContainmentAction.QUARANTINE_FILE,
            ContainmentAction.ISOLATE_HOST,
        ],
        "estimated_duration_seconds": 45,
    },
]


class SecurityAutomationToolkit:
    """Collection of tools for the security automation agent.

    Injected into nodes at graph construction time to decouple
    agent logic from specific infrastructure implementations.
    """

    def __init__(
        self,
        risk_threshold: float = 50.0,
        playbook_registry: list[dict[str, Any]] | None = None,
        repository: Any = None,
    ) -> None:
        self._risk_threshold = risk_threshold
        self._playbooks = playbook_registry or _PLAYBOOK_REGISTRY
        self._repository = repository
        self._learning_store: list[LearningOutcome] = []

    def triage_alerts(
        self,
        alerts: list[RiskAlert],
        threshold: float | None = None,
    ) -> list[RiskAlert]:
        """Prioritize alerts by composite risk score.

        Filters out alerts below the risk threshold and sorts
        remaining by score descending.
        """
        cutoff = threshold if threshold is not None else self._risk_threshold

        # Filter and sort
        above_threshold = [a for a in alerts if a.composite_score >= cutoff]
        above_threshold.sort(key=lambda a: a.composite_score, reverse=True)

        logger.info(
            "alerts_triaged",
            total=len(alerts),
            above_threshold=len(above_threshold),
            cutoff=cutoff,
        )
        return above_threshold

    def match_playbook(self, alert: RiskAlert) -> PlaybookCandidate:
        """Match an alert to the best playbook based on MITRE tactics.

        Scoring:
        - EXACT: entity_type matches AND >= 2 tactics overlap
        - PARTIAL: entity_type matches AND >= 1 tactic overlap
        - FALLBACK: any tactic overlap (entity_type mismatch)
        - NONE: no match found
        """
        best: PlaybookCandidate | None = None
        best_overlap = 0

        alert_tactics = set(alert.tactics_seen)

        for pb in self._playbooks:
            pb_tactics = set(pb["tactics"])
            overlap = len(alert_tactics & pb_tactics)
            entity_match = alert.entity_type in pb["entity_types"]

            if overlap == 0:
                continue

            if entity_match and overlap >= 2:
                match_type = PlaybookMatch.EXACT
                confidence = min(1.0, 0.7 + overlap * 0.1)
            elif entity_match and overlap >= 1:
                match_type = PlaybookMatch.PARTIAL
                confidence = min(1.0, 0.5 + overlap * 0.1)
            else:
                match_type = PlaybookMatch.FALLBACK
                confidence = min(1.0, 0.3 + overlap * 0.05)

            if overlap > best_overlap or (
                overlap == best_overlap and best is not None and confidence > best.confidence
            ):
                best_overlap = overlap
                best = PlaybookCandidate(
                    playbook_id=pb["playbook_id"],
                    name=pb["name"],
                    match_type=match_type,
                    confidence=confidence,
                    estimated_duration_seconds=pb["estimated_duration_seconds"],
                    actions=[str(a) for a in pb["actions"]],
                )

        if best is not None:
            logger.info(
                "playbook_matched",
                playbook_id=best.playbook_id,
                match_type=best.match_type,
                confidence=best.confidence,
                entity=alert.entity,
            )
            return best

        logger.warning("no_playbook_match", entity=alert.entity)
        return PlaybookCandidate(
            playbook_id="none",
            name="No matching playbook",
            match_type=PlaybookMatch.NONE,
            confidence=0.0,
        )

    async def execute_containment(
        self,
        action: ContainmentAction,
        target: str,
        dry_run: bool = True,
    ) -> ContainmentResult:
        """Execute a containment action against a target.

        Always defaults to dry_run=True for safety. In dry-run mode,
        simulates the action without making changes.
        """
        start = datetime.now(UTC)

        logger.info(
            "containment_executing",
            action=action,
            target=target,
            dry_run=dry_run,
        )

        # In dry-run mode, simulate execution
        if dry_run:
            duration = (datetime.now(UTC) - start).total_seconds()
            return ContainmentResult(
                action=action,
                target=target,
                success=True,
                duration_seconds=duration,
                rollback_available=action != ContainmentAction.NONE,
                details=f"DRY RUN: Would execute {action} on {target}",
            )

        # Live execution — dispatch based on action type
        try:
            result = await self._dispatch_containment(action, target)
            duration = (datetime.now(UTC) - start).total_seconds()
            result.duration_seconds = duration
            return result
        except Exception as e:
            duration = (datetime.now(UTC) - start).total_seconds()
            logger.error(
                "containment_failed",
                action=action,
                target=target,
                error=str(e),
            )
            return ContainmentResult(
                action=action,
                target=target,
                success=False,
                duration_seconds=duration,
                rollback_available=False,
                details=f"Execution failed: {e}",
            )

    def validate_containment(
        self,
        results: list[ContainmentResult],
    ) -> bool:
        """Verify containment was effective.

        Returns True if all actions succeeded.
        """
        if not results:
            return False

        all_success = all(r.success for r in results)

        logger.info(
            "containment_validated",
            total_actions=len(results),
            successful=sum(1 for r in results if r.success),
            all_success=all_success,
        )
        return all_success

    def record_learning(
        self,
        alert: RiskAlert,
        playbook: PlaybookCandidate,
        results: list[ContainmentResult],
        accepted: bool = True,
        feedback: str = "",
    ) -> LearningOutcome:
        """Record outcome for the accept/reject auto-learning loop.

        Inspired by Splunk's autoresearch accept/reject pattern.
        Stores whether this alert+playbook+action combination was
        successful and accepted for future automated responses.
        """
        outcome = LearningOutcome(
            alert_entity=alert.entity,
            playbook_id=playbook.playbook_id,
            actions_taken=[str(r.action) for r in results],
            success=all(r.success for r in results),
            feedback=feedback,
            accepted=accepted,
        )

        self._learning_store.append(outcome)

        logger.info(
            "learning_recorded",
            entity=alert.entity,
            playbook_id=playbook.playbook_id,
            success=outcome.success,
            accepted=accepted,
        )
        return outcome

    @property
    def learning_history(self) -> list[LearningOutcome]:
        """Return the recorded learning outcomes."""
        return list(self._learning_store)

    # --- Private helpers ---

    async def _dispatch_containment(
        self,
        action: ContainmentAction,
        target: str,
    ) -> ContainmentResult:
        """Dispatch a live containment action to the appropriate connector.

        In production, this would call actual infrastructure APIs.
        """
        # Placeholder — real implementation would integrate with
        # ConnectorRouter to execute against infrastructure.
        rollback = action not in (ContainmentAction.NONE,)
        return ContainmentResult(
            action=action,
            target=target,
            success=True,
            rollback_available=rollback,
            details=f"Executed {action} on {target}",
        )
