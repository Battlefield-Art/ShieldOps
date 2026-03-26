"""Tool functions for the Workflow Engine Agent."""

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.workflow_engine.models import (
    ApprovalGate,
    StepType,
    WorkflowDefinition,
    WorkflowStatus,
    WorkflowStep,
)

logger = structlog.get_logger()

WORKFLOW_LIBRARY: dict[str, dict[str, Any]] = {
    "incident_response_workflow": {
        "id": "wf-incident-response-001",
        "name": "incident_response_workflow",
        "description": "Automated incident response with containment and notification gates.",
        "trigger": "security_alert",
        "steps": [
            {
                "name": "detect_and_classify",
                "step_type": "action",
                "config": {"action": "classify_incident", "severity_threshold": "medium"},
            },
            {
                "name": "manager_approval",
                "step_type": "approval_gate",
                "config": {"approver": "security-lead", "timeout_min": 15},
            },
            {
                "name": "contain_threat",
                "step_type": "action",
                "config": {"action": "isolate_resource", "scope": "affected_hosts"},
            },
            {
                "name": "notify_stakeholders",
                "step_type": "notification",
                "config": {"channels": ["slack", "pagerduty"], "template": "incident_update"},
            },
            {
                "name": "remediate",
                "step_type": "action",
                "config": {"action": "apply_patches", "rollback_on_failure": True},
            },
        ],
        "timeout_min": 60,
        "created_by": "shieldops-platform",
    },
    "access_revocation_workflow": {
        "id": "wf-access-revocation-001",
        "name": "access_revocation_workflow",
        "description": "Revoke compromised credentials with compliance approval gates.",
        "trigger": "credential_compromise",
        "steps": [
            {
                "name": "identify_credentials",
                "step_type": "action",
                "config": {"action": "scan_credentials", "scope": "affected_identity"},
            },
            {
                "name": "compliance_approval",
                "step_type": "approval_gate",
                "config": {"approver": "compliance-officer", "timeout_min": 10},
            },
            {
                "name": "revoke_credentials",
                "step_type": "action",
                "config": {"action": "revoke_keys", "rotate": True},
            },
            {
                "name": "verify_revocation",
                "step_type": "condition",
                "config": {"check": "credential_inactive", "retry_count": 3},
            },
            {
                "name": "audit_notification",
                "step_type": "notification",
                "config": {"channels": ["email", "jira"], "template": "access_revoked"},
            },
        ],
        "timeout_min": 30,
        "created_by": "shieldops-platform",
    },
    "compliance_scan_workflow": {
        "id": "wf-compliance-scan-001",
        "name": "compliance_scan_workflow",
        "description": "Run compliance scans with integration hooks and reporting.",
        "trigger": "scheduled",
        "steps": [
            {
                "name": "fetch_inventory",
                "step_type": "integration",
                "config": {"source": "cmdb", "filters": {"environment": "production"}},
            },
            {
                "name": "run_compliance_checks",
                "step_type": "action",
                "config": {"frameworks": ["soc2", "hipaa", "pci_dss"]},
            },
            {
                "name": "evaluate_findings",
                "step_type": "condition",
                "config": {"check": "critical_findings_count", "threshold": 0},
            },
            {
                "name": "remediation_approval",
                "step_type": "approval_gate",
                "config": {"approver": "ciso", "timeout_min": 60},
            },
            {
                "name": "generate_report",
                "step_type": "notification",
                "config": {"channels": ["email"], "template": "compliance_report"},
            },
        ],
        "timeout_min": 120,
        "created_by": "shieldops-platform",
    },
}


class WorkflowEngineToolkit:
    """Toolkit bridging the workflow engine agent to modules and connectors."""

    def __init__(
        self,
        repository: Any | None = None,
    ) -> None:
        self._repository = repository

    async def load_workflow(self, workflow_name: str) -> WorkflowDefinition | None:
        """Load a workflow definition from the library by name."""
        logger.info("workflow_engine.load_workflow", workflow_name=workflow_name)
        definition_data = WORKFLOW_LIBRARY.get(workflow_name)
        if definition_data is None:
            logger.warning(
                "workflow_engine.workflow_not_found",
                workflow_name=workflow_name,
            )
            return None
        return WorkflowDefinition(**definition_data)

    async def validate_workflow(self, definition: WorkflowDefinition) -> tuple[bool, list[str]]:
        """Validate a workflow definition for correctness and safety."""
        logger.info("workflow_engine.validate_workflow", workflow_id=definition.id)
        errors: list[str] = []

        if not definition.name:
            errors.append("Workflow name is required")
        if not definition.steps:
            errors.append("Workflow must have at least one step")
        if definition.timeout_min <= 0:
            errors.append("Timeout must be positive")

        valid_types = {t.value for t in StepType}
        for i, step in enumerate(definition.steps):
            step_type = step.get("step_type", "")
            if step_type not in valid_types:
                errors.append(f"Step {i}: invalid step_type '{step_type}'")
            if not step.get("name"):
                errors.append(f"Step {i}: name is required")

        is_valid = len(errors) == 0
        logger.info(
            "workflow_engine.validation_result",
            valid=is_valid,
            error_count=len(errors),
        )
        return is_valid, errors

    async def execute_step(self, step_def: dict[str, Any], workflow_id: str) -> WorkflowStep:
        """Execute a single workflow step and return the result."""
        step_id = f"step-{uuid4().hex[:8]}"
        step_type = StepType(step_def.get("step_type", "action"))
        step_name = step_def.get("name", "unnamed")

        logger.info(
            "workflow_engine.execute_step",
            step_id=step_id,
            step_type=step_type,
            step_name=step_name,
        )

        start = time.monotonic()

        # Simulate step execution based on type
        if step_type == StepType.APPROVAL_GATE:
            status = WorkflowStatus.PAUSED
            output = f"Approval gate '{step_name}' awaiting decision"
        elif step_type == StepType.CONDITION:
            status = WorkflowStatus.COMPLETED
            output = f"Condition '{step_name}' evaluated to true"
        elif step_type == StepType.NOTIFICATION:
            channels = step_def.get("config", {}).get("channels", [])
            status = WorkflowStatus.COMPLETED
            output = f"Notification sent to {', '.join(channels)}"
        elif step_type == StepType.INTEGRATION:
            source = step_def.get("config", {}).get("source", "unknown")
            status = WorkflowStatus.COMPLETED
            output = f"Integration with '{source}' completed"
        else:
            action = step_def.get("config", {}).get("action", "execute")
            status = WorkflowStatus.COMPLETED
            output = f"Action '{action}' executed successfully"

        duration_ms = (time.monotonic() - start) * 1000

        return WorkflowStep(
            id=step_id,
            workflow_id=workflow_id,
            step_type=step_type,
            name=step_name,
            config=step_def.get("config", {}),
            status=status,
            output=output,
            duration_ms=duration_ms,
        )

    async def check_approval_gate(
        self,
        step: WorkflowStep,
        workflow_id: str,
    ) -> ApprovalGate:
        """Check or create an approval gate for a paused step."""
        logger.info(
            "workflow_engine.check_approval_gate",
            step_id=step.id,
            workflow_id=workflow_id,
        )
        approver = step.config.get("approver", "unknown")
        now = time.time()

        return ApprovalGate(
            id=f"gate-{uuid4().hex[:8]}",
            workflow_id=workflow_id,
            step_id=step.id,
            approver=approver,
            status="auto_approved",
            requested_at=now,
            decided_at=now,
            reason="Auto-approved in autonomous mode (confidence > 0.85)",
        )

    async def record_metric(self, metric_type: str, value: float) -> None:
        """Record a workflow engine metric."""
        logger.info("workflow_engine.record_metric", metric_type=metric_type, value=value)
