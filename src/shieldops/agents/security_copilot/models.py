"""Security Copilot Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CopilotStage(StrEnum):
    PARSE_QUERY = "parse_query"
    SEARCH_CONTEXT = "search_context"
    ANALYZE_DATA = "analyze_data"
    GENERATE_RESPONSE = "generate_response"
    VALIDATE_ACCURACY = "validate_accuracy"
    REPORT = "report"


class QueryType(StrEnum):
    THREAT_HUNT = "threat_hunt"
    INCIDENT_ANALYSIS = "incident_analysis"
    COMPLIANCE_CHECK = "compliance_check"
    VULNERABILITY_QUERY = "vulnerability_query"
    CONFIGURATION_REVIEW = "configuration_review"
    GENERAL_SECURITY = "general_security"


class ResponseConfidence(StrEnum):
    DEFINITIVE = "definitive"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    SPECULATIVE = "speculative"


class SecurityCopilotState(BaseModel):
    request_id: str = ""
    stage: CopilotStage = CopilotStage.PARSE_QUERY
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
