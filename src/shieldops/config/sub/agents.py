"""Agent configuration."""

from pydantic import BaseModel


class AgentConfig(BaseModel):
    """Agent orchestration settings."""

    agent_confidence_threshold_auto: float = 0.85
    agent_confidence_threshold_approval: float = 0.50
    agent_max_investigation_time_seconds: int = 600
    agent_max_remediation_retries: int = 3
    agent_global_max_concurrent: int = 20
    agent_quota_enabled: bool = True
    agent_collaboration_enabled: bool = True
    agent_collaboration_max_messages: int = 1000
    agent_collaboration_session_timeout_minutes: int = 60
    agent_benchmark_enabled: bool = True
    agent_benchmark_baseline_days: int = 30
    agent_benchmark_regression_threshold: float = 0.2
    agent_decision_tracking_enabled: bool = True
    agent_decision_max_records: int = 50000
    agent_decision_retention_days: int = 90
