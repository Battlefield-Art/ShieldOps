"""State models for the Response Automation Engine Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RAEStage(StrEnum):
    """Stages of the response automation workflow."""

    DETECT_TRIGGER = "detect_trigger"
    EVALUATE_PLAYBOOK = "evaluate_playbook"
    ORCHESTRATE_ACTIONS = "orchestrate_actions"
    VERIFY_RESPONSE = "verify_response"
    DOCUMENT_ACTIONS = "document_actions"
    REPORT = "report"


class ResponseAction(StrEnum):
    """Automated response actions available."""

    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_FILE = "quarantine_file"
    REVOKE_TOKEN = "revoke_token"
    ESCALATE = "escalate"


class AutomationLevel(StrEnum):
    """Automation levels for response actions."""

    FULLY_AUTOMATED = "fully_automated"
    SEMI_AUTOMATED = "semi_automated"
    MANUAL_APPROVAL = "manual_approval"
    MANUAL_ONLY = "manual_only"
    DISABLED = "disabled"


class ResponseAutomationEngineState(BaseModel):
    """Full state for response automation workflow."""

    request_id: str = ""
    stage: RAEStage = RAEStage.DETECT_TRIGGER
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    stats: dict[str, Any] = Field(
        default_factory=dict,
    )
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
