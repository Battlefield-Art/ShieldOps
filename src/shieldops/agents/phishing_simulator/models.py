"""State models for the Phishing Simulator Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PhishingStage(StrEnum):
    """Stages of the phishing simulation."""

    design_campaign = "design_campaign"
    select_targets = "select_targets"
    send_simulations = "send_simulations"
    track_responses = "track_responses"
    analyze_results = "analyze_results"
    report = "report"


class CampaignType(StrEnum):
    """Types of phishing campaigns."""

    credential_harvest = "credential_harvest"
    malware_link = "malware_link"
    attachment = "attachment"
    vishing_prep = "vishing_prep"
    smishing_prep = "smishing_prep"


class EmployeeRisk(StrEnum):
    """Employee phishing risk levels."""

    high_risk = "high_risk"
    moderate_risk = "moderate_risk"
    low_risk = "low_risk"
    trained = "trained"


class PhishingCampaign(BaseModel):
    """A phishing simulation campaign."""

    campaign_id: str = ""
    campaign_type: str = CampaignType.credential_harvest
    subject_line: str = ""
    sender_display: str = ""
    template_name: str = ""
    landing_page_url: str = ""
    is_simulation: bool = True


class TargetSelection(BaseModel):
    """Target selection for phishing campaign."""

    employee_id: str = ""
    email: str = ""
    department: str = ""
    role: str = ""
    previous_click_rate: float = 0.0
    training_completed: bool = False


class SimulationDelivery(BaseModel):
    """Delivery status of a simulation email."""

    employee_id: str = ""
    delivered: bool = False
    delivery_time: str = ""
    simulation_marked: bool = True


class ResponseTracking(BaseModel):
    """Response tracking for a simulation."""

    employee_id: str = ""
    email_opened: bool = False
    link_clicked: bool = False
    credentials_submitted: bool = False
    reported_as_phishing: bool = False
    response_time_seconds: int = 0


class AwarenessAnalysis(BaseModel):
    """Awareness analysis per employee/department."""

    group_id: str = ""
    group_type: str = "department"
    click_rate: float = 0.0
    report_rate: float = 0.0
    risk_level: str = EmployeeRisk.moderate_risk
    training_recommended: bool = False


class PhishingSimulatorState(BaseModel):
    """Full state for the phishing simulator workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: PhishingStage = PhishingStage.design_campaign

    # Input
    campaign_type: str = CampaignType.credential_harvest
    target_departments: list[str] = Field(default_factory=list)
    target_roles: list[str] = Field(default_factory=list)

    # Pipeline
    campaigns_designed: list[dict[str, Any]] = Field(default_factory=list)
    targets_selected: list[dict[str, Any]] = Field(default_factory=list)
    simulations_sent: list[dict[str, Any]] = Field(default_factory=list)
    responses_tracked: list[dict[str, Any]] = Field(default_factory=list)
    risk_assessments: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    click_rate: float = 0.0
    report_rate: float = 0.0

    # Output
    report_summary: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
