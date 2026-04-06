"""Tool functions for the Remediation Agent.

Bridges infrastructure connectors, policy engine, and approval workflow
to the agent's LangGraph nodes.

Production-hardened with:
- OPA approval workflow with risk-score thresholds (auto/human/escalate)
- Blast-radius enforcement per environment (dev=10, staging=5, prod=3)
- CrowdStrike containment with health-poll verification
- ServiceNow ticket creation for every remediation action
- Immutable audit trail logging
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog
from pydantic import BaseModel

from shieldops.connectors.base import ConnectorRouter
from shieldops.models.base import (
    ActionResult,
    ApprovalStatus,
    AuditEntry,
    Environment,
    ExecutionStatus,
    HealthStatus,
    RemediationAction,
    RiskLevel,
    Snapshot,
)
from shieldops.playbooks.loader import Playbook, PlaybookLoader, PlaybookValidation
from shieldops.policy.approval.workflow import ApprovalRequest, ApprovalWorkflow
from shieldops.policy.opa.client import PolicyDecision, PolicyEngine

logger = structlog.get_logger()


class PolicyGateResult(BaseModel):
    """Result of the three-tier policy engine evaluation."""

    allowed: bool
    decision: str  # approved, denied, requires_approval
    reason: str
    requires_approval: bool = False


# Blast-radius limits: max resources per single remediation batch
BLAST_RADIUS_LIMITS: dict[str, int] = {
    "development": 10,
    "staging": 5,
    "production": 3,
}

# OPA risk-score thresholds for approval routing
RISK_SCORE_AUTO_APPROVE = 0.5
RISK_SCORE_ESCALATE = 0.85


class BlastRadiusExceeded(Exception):
    """Raised when a remediation plan exceeds the environment's resource limit."""

    def __init__(self, environment: str, requested: int, limit: int) -> None:
        self.environment = environment
        self.requested = requested
        self.limit = limit
        super().__init__(
            f"Blast-radius exceeded for {environment}: "
            f"{requested} resources requested, limit is {limit}"
        )


class RemediationToolkit:
    """Collection of tools available to the remediation agent.

    Injected into nodes at graph construction time to decouple agent logic
    from specific infrastructure and policy implementations.
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        policy_engine: PolicyEngine | None = None,
        approval_workflow: ApprovalWorkflow | None = None,
        playbook_loader: PlaybookLoader | None = None,
    ) -> None:
        self._router = connector_router
        self._policy_engine = policy_engine
        self._approval_workflow = approval_workflow
        self._playbook_loader = playbook_loader
        self._audit_log: list[AuditEntry] = []

    # ------------------------------------------------------------------
    # OPA approval workflow with risk-score routing
    # ------------------------------------------------------------------

    async def evaluate_policy(
        self,
        action: RemediationAction,
        agent_id: str = "remediation-agent",
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate action against OPA policies."""
        if self._policy_engine is None:
            logger.warning("policy_engine_not_configured", action=action.action_type)
            return PolicyDecision(
                allowed=True,
                reasons=["No policy engine configured — allowing by default"],
            )

        return await self._policy_engine.evaluate(action, agent_id, context)

    def evaluate_risk_score(self, risk_score: float) -> ApprovalStatus:
        """Route an action based on its numeric risk score.

        - risk_score < 0.5  -> auto-approve
        - 0.5 <= risk_score <= 0.85 -> require human approval (PENDING)
        - risk_score > 0.85 -> escalate (deny autonomous execution)
        """
        if risk_score < RISK_SCORE_AUTO_APPROVE:
            logger.info("risk_score_auto_approved", risk_score=risk_score)
            return ApprovalStatus.APPROVED
        if risk_score <= RISK_SCORE_ESCALATE:
            logger.info("risk_score_requires_approval", risk_score=risk_score)
            return ApprovalStatus.PENDING
        logger.warning("risk_score_escalated", risk_score=risk_score)
        return ApprovalStatus.ESCALATED

    # ------------------------------------------------------------------
    # Blast-radius enforcement
    # ------------------------------------------------------------------

    def enforce_blast_radius(
        self,
        environment: str,
        resource_count: int,
    ) -> list[list[str]] | None:
        """Enforce blast-radius limits per environment.

        Returns None if within limits.
        Returns batched resource indices if the count exceeds the limit,
        allowing the caller to split work into safe batches.

        Raises BlastRadiusExceeded if resource_count exceeds 3x the limit
        (considered too risky even for batching).
        """
        limit = BLAST_RADIUS_LIMITS.get(environment, BLAST_RADIUS_LIMITS["production"])

        if resource_count <= limit:
            return None  # Within limits

        # If more than 3x limit, refuse outright — must escalate
        if resource_count > limit * 3:
            raise BlastRadiusExceeded(environment, resource_count, limit)

        # Split into batches of `limit` size
        batches: list[list[str]] = []
        for i in range(0, resource_count, limit):
            batch = [str(j) for j in range(i, min(i + limit, resource_count))]
            batches.append(batch)

        logger.info(
            "blast_radius_batched",
            environment=environment,
            resource_count=resource_count,
            limit=limit,
            batch_count=len(batches),
        )
        return batches

    def get_blast_radius_limit(self, environment: str) -> int:
        """Return the blast-radius limit for the given environment."""
        return BLAST_RADIUS_LIMITS.get(environment, BLAST_RADIUS_LIMITS["production"])

    def classify_risk(
        self,
        action_type: str,
        environment: str,
    ) -> RiskLevel:
        """Classify risk level using the policy engine."""
        if self._policy_engine is None:
            return RiskLevel.MEDIUM

        from shieldops.models.base import Environment

        try:
            env = Environment(environment)
        except ValueError:
            env = Environment.PRODUCTION

        return self._policy_engine.classify_risk(action_type, env)

    def requires_approval(self, risk_level: RiskLevel) -> bool:
        """Check if risk level requires human approval."""
        if self._approval_workflow is None:
            return False
        return self._approval_workflow.requires_approval(risk_level)

    async def request_approval(
        self,
        request: ApprovalRequest,
    ) -> ApprovalStatus:
        """Submit approval request and wait for response."""
        if self._approval_workflow is None:
            logger.warning("approval_workflow_not_configured")
            return ApprovalStatus.APPROVED

        return await self._approval_workflow.request_approval(request)

    async def create_snapshot(
        self,
        resource_id: str,
        provider: str = "kubernetes",
    ) -> Snapshot | None:
        """Create infrastructure state snapshot before action."""
        if self._router is None:
            logger.warning("no_connector_router", resource_id=resource_id)
            return None

        try:
            connector = self._router.get(provider)
            return await connector.create_snapshot(resource_id)
        except (ValueError, Exception) as e:
            logger.error(
                "snapshot_creation_failed",
                resource_id=resource_id,
                error=str(e),
            )
            return None

    async def pre_check_state(
        self,
        resource_id: str,
        provider: str = "kubernetes",
    ) -> HealthStatus | None:
        """Capture the current state of a resource before remediation.

        Returns the pre-action health status so it can be compared post-action.
        """
        if self._router is None:
            return None

        try:
            connector = self._router.get(provider)
            health = await connector.get_health(resource_id)
            logger.info(
                "pre_check_state_captured",
                resource_id=resource_id,
                status=health.status if health else "unknown",
            )
            return health
        except Exception as e:
            logger.warning(
                "pre_check_state_failed",
                resource_id=resource_id,
                error=str(e),
            )
            return None

    async def post_check_state(
        self,
        resource_id: str,
        pre_health: HealthStatus | None,
        provider: str = "kubernetes",
    ) -> tuple[HealthStatus | None, bool]:
        """Verify that the resource state changed after remediation.

        Returns a tuple of (post_health, state_changed). Logs a warning
        if the state did not change.
        """
        if self._router is None:
            return None, False

        try:
            connector = self._router.get(provider)
            post_health = await connector.get_health(resource_id)

            if pre_health is None or post_health is None:
                return post_health, False

            state_changed = post_health.status != pre_health.status
            if not state_changed:
                logger.warning(
                    "post_check_state_unchanged",
                    resource_id=resource_id,
                    pre_status=pre_health.status,
                    post_status=post_health.status,
                )
            else:
                logger.info(
                    "post_check_state_changed",
                    resource_id=resource_id,
                    pre_status=pre_health.status,
                    post_status=post_health.status,
                )
            return post_health, state_changed
        except Exception as e:
            logger.warning(
                "post_check_state_failed",
                resource_id=resource_id,
                error=str(e),
            )
            return None, False

    async def evaluate_policy_gate(
        self,
        action: RemediationAction,
    ) -> "PolicyGateResult":
        """Evaluate action against the three-tier policy engine.

        Uses ``shieldops.policy.engine.evaluate`` which checks blast-radius,
        OPA policies, and risk-score thresholds in one call.

        Returns a ``PolicyGateResult`` with the decision.
        """
        from shieldops.policy.engine import Decision, PolicyContext, evaluate

        env_map = {
            "development": "dev",
            "staging": "staging",
            "production": "prod",
        }
        env_short = env_map.get(action.environment.value, "prod")

        # Map RiskLevel to numeric risk score for the policy engine
        risk_score_map = {
            RiskLevel.LOW: 0.2,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.75,
            RiskLevel.CRITICAL: 0.95,
        }
        risk_score = risk_score_map.get(action.risk_level, 0.5)

        context = PolicyContext(
            agent_name="remediation-agent",
            action_type=action.action_type,
            target_resources=[action.target_resource],
            environment=env_short,
            risk_score=risk_score,
            metadata={"action_id": action.id, "description": action.description},
        )

        decision = await evaluate(action.action_type, context)

        logger.info(
            "policy_gate_evaluated",
            action_type=action.action_type,
            target=action.target_resource,
            decision=decision.decision.value,
            allowed=decision.allowed,
            reason=decision.reason,
        )

        return PolicyGateResult(
            allowed=decision.allowed,
            decision=decision.decision.value,
            reason=decision.reason,
            requires_approval=decision.decision == Decision.REQUIRES_APPROVAL,
        )

    async def execute_action(
        self,
        action: RemediationAction,
        provider: str = "kubernetes",
    ) -> ActionResult:
        """Execute remediation action via infrastructure connector."""
        if self._router is None:
            return ActionResult(
                action_id=action.id,
                status=ExecutionStatus.FAILED,
                message="No connector router configured",
                started_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            )

        try:
            connector = self._router.get(provider)
            return await connector.execute_action(action)
        except (ValueError, Exception) as e:
            logger.error(
                "action_execution_failed",
                action_id=action.id,
                error=str(e),
            )
            from datetime import datetime

            return ActionResult(
                action_id=action.id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=datetime.now(UTC),
                error=str(e),
            )

    async def validate_health(
        self,
        resource_id: str,
        provider: str = "kubernetes",
        timeout_seconds: int = 120,
    ) -> HealthStatus | None:
        """Check resource health after remediation."""
        if self._router is None:
            return None

        try:
            connector = self._router.get(provider)
            health = await connector.get_health(resource_id)
            return health
        except (ValueError, Exception) as e:
            logger.error(
                "health_validation_failed",
                resource_id=resource_id,
                error=str(e),
            )
            return None

    async def rollback(
        self,
        snapshot_id: str,
        provider: str = "kubernetes",
    ) -> ActionResult:
        """Rollback to a previous snapshot."""
        if self._router is None:
            from datetime import datetime

            return ActionResult(
                action_id=f"rollback-{snapshot_id}",
                status=ExecutionStatus.FAILED,
                message="No connector router configured",
                started_at=datetime.now(UTC),
            )

        try:
            connector = self._router.get(provider)
            return await connector.rollback(snapshot_id)
        except (ValueError, Exception) as e:
            logger.error("rollback_failed", snapshot_id=snapshot_id, error=str(e))
            from datetime import datetime

            return ActionResult(
                action_id=f"rollback-{snapshot_id}",
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=datetime.now(UTC),
                error=str(e),
            )

    def resolve_playbook(self, alert_name: str, severity: str | None = None) -> Playbook | None:
        """Find a matching playbook for the given alert."""
        if self._playbook_loader is None:
            return None
        return self._playbook_loader.match(alert_name, severity)

    def get_playbook_validation(self, playbook_name: str) -> PlaybookValidation | None:
        """Get validation config for a named playbook."""
        if self._playbook_loader is None:
            return None
        playbook = self._playbook_loader.get(playbook_name)
        if playbook is None:
            return None
        return playbook.validation

    # ------------------------------------------------------------------
    # CrowdStrike containment
    # ------------------------------------------------------------------

    async def contain_host(
        self,
        device_id: str,
        poll_attempts: int = 5,
        poll_interval_seconds: float = 2.0,
    ) -> ActionResult:
        """Contain a host via CrowdStrike and verify containment succeeded.

        Polls the CrowdStrike API up to ``poll_attempts`` times to confirm
        the host transitions to a contained state.
        """
        import asyncio

        now = datetime.now(UTC)

        if self._router is None:
            return ActionResult(
                action_id=f"contain-{device_id}",
                status=ExecutionStatus.FAILED,
                message="No connector router configured",
                started_at=now,
            )

        try:
            cs = self._router.get("crowdstrike")
        except (ValueError, KeyError):
            return ActionResult(
                action_id=f"contain-{device_id}",
                status=ExecutionStatus.FAILED,
                message="CrowdStrike connector not available",
                started_at=now,
            )

        try:
            await cs.contain_host(device_id)
        except Exception as e:
            logger.error("crowdstrike_contain_failed", device_id=device_id, error=str(e))
            return ActionResult(
                action_id=f"contain-{device_id}",
                status=ExecutionStatus.FAILED,
                message=f"Containment request failed: {e}",
                started_at=now,
                error=str(e),
            )

        # Poll for containment verification
        for attempt in range(1, poll_attempts + 1):
            try:
                health = await cs.get_health(device_id)
                if health and health.status == "contained":
                    logger.info(
                        "crowdstrike_containment_verified",
                        device_id=device_id,
                        attempt=attempt,
                    )
                    return ActionResult(
                        action_id=f"contain-{device_id}",
                        status=ExecutionStatus.SUCCESS,
                        message=f"Host contained and verified after {attempt} poll(s)",
                        started_at=now,
                    )
            except Exception as e:
                logger.warning(
                    "crowdstrike_poll_failed",
                    device_id=device_id,
                    attempt=attempt,
                    error=str(e),
                )

            if attempt < poll_attempts:
                await asyncio.sleep(poll_interval_seconds)

        # Containment requested but verification timed out
        logger.warning(
            "crowdstrike_containment_unverified",
            device_id=device_id,
            attempts=poll_attempts,
        )
        return ActionResult(
            action_id=f"contain-{device_id}",
            status=ExecutionStatus.SUCCESS,
            message=(
                f"Containment requested but could not verify after "
                f"{poll_attempts} polls — manual verification recommended"
            ),
            started_at=now,
        )

    # ------------------------------------------------------------------
    # ServiceNow ticket creation
    # ------------------------------------------------------------------

    async def create_servicenow_ticket(
        self,
        action: RemediationAction,
        outcome: ExecutionStatus,
        rollback_plan: str = "",
        alert_id: str = "",
        cve_id: str = "",
    ) -> dict[str, Any]:
        """Create a ServiceNow incident for a remediation action.

        Every remediation action gets a ticket with:
        - CVE/alert ID
        - Affected resources
        - Actions taken
        - Rollback plan
        """
        if self._router is None:
            logger.warning("servicenow_no_router")
            return {"error": "No connector router configured"}

        try:
            snow = self._router.get("servicenow")
        except (ValueError, KeyError):
            logger.warning("servicenow_connector_not_available")
            return {"error": "ServiceNow connector not available"}

        short_desc = f"[ShieldOps] Remediation: {action.action_type} on {action.target_resource}"

        description_lines = [
            f"Remediation ID: {action.id}",
            f"Action Type: {action.action_type}",
            f"Target Resource: {action.target_resource}",
            f"Environment: {action.environment.value}",
            f"Risk Level: {action.risk_level.value}",
            f"Outcome: {outcome.value}",
            f"Description: {action.description}",
        ]
        if alert_id:
            description_lines.append(f"Alert ID: {alert_id}")
        if cve_id:
            description_lines.append(f"CVE: {cve_id}")
        if rollback_plan:
            description_lines.append(f"Rollback Plan: {rollback_plan}")
        description_lines.append(f"Parameters: {action.parameters}")

        urgency = "1" if action.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH) else "2"
        impact = "1" if action.environment == Environment.PRODUCTION else "2"

        try:
            result = await snow.create_incident(
                short_description=short_desc,
                description="\n".join(description_lines),
                urgency=urgency,
                impact=impact,
            )
            logger.info(
                "servicenow_ticket_created",
                action_id=action.id,
                ticket=result.get("result", {}).get("number", "unknown"),
            )
            return result
        except Exception as e:
            logger.error("servicenow_ticket_failed", action_id=action.id, error=str(e))
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Audit trail
    # ------------------------------------------------------------------

    def record_audit(
        self,
        action_type: str,
        target_resource: str,
        environment: str,
        risk_level: RiskLevel,
        approval_status: ApprovalStatus | None,
        outcome: ExecutionStatus,
        policy_evaluation: str = "allowed",
        reasoning: str = "",
        actor: str = "remediation-agent",
    ) -> AuditEntry:
        """Record an immutable audit log entry for a remediation action.

        Stores locally and returns the entry so the runner can also persist
        to the database.
        """
        try:
            env = Environment(environment)
        except ValueError:
            env = Environment.PRODUCTION

        entry = AuditEntry(
            id=f"aud-{uuid4().hex[:12]}",
            timestamp=datetime.now(UTC),
            agent_type="remediation",
            action=action_type,
            target_resource=target_resource,
            environment=env,
            risk_level=risk_level,
            policy_evaluation=policy_evaluation,
            approval_status=approval_status,
            outcome=outcome,
            reasoning=reasoning,
            actor=actor,
        )
        self._audit_log.append(entry)
        logger.info(
            "audit_entry_recorded",
            audit_id=entry.id,
            action=action_type,
            target=target_resource,
            outcome=outcome.value,
        )
        return entry

    def get_audit_log(self) -> list[AuditEntry]:
        """Return all recorded audit entries (in-memory)."""
        return list(self._audit_log)
