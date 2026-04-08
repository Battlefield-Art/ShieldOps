"""Application configuration via environment variables."""

import os
from typing import Any

from pydantic import BaseModel, model_validator
from pydantic_settings import BaseSettings

from shieldops.config.sub.engines import EnginesConfig

# ---------------------------------------------------------------------------
# Inlined non-engines sub-configs (RFC #241 PR-3 / #251).
#
# Previously these lived in src/shieldops/config/sub/<name>.py. They were
# inlined here because (a) no external callers imported them directly and
# (b) FlatSettings in flat.py now mirrors every field. The legacy Settings
# class below still uses them via _FLAT_TO_NESTED for backwards compat.
# `EnginesConfig` is intentionally still imported from sub/engines.py — it
# gets its own Phase 3 decomposition PR.
# ---------------------------------------------------------------------------


class AppConfig(BaseModel):
    """Core application settings."""

    app_name: str = "ShieldOps"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"


class ApiConfig(BaseModel):
    """API server settings."""

    api_host: str = "0.0.0.0"  # noqa: S104  # nosec B104
    api_port: int = 8000
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = ["http://localhost:3000"]


class DatabaseConfig(BaseModel):
    """Database connection settings."""

    database_url: str = "postgresql+asyncpg://shieldops:shieldops@localhost:5432/shieldops"
    database_pool_size: int = 20


class RedisConfig(BaseModel):
    """Redis connection settings."""

    redis_url: str = "redis://localhost:6379/0"


class KafkaConfig(BaseModel):
    """Kafka broker settings."""

    kafka_brokers: str = "localhost:9092"
    kafka_consumer_group: str = "shieldops-agents"


class LlmConfig(BaseModel):
    """LLM provider and routing settings."""

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    llm_routing_enabled: bool = False
    llm_simple_model: str = "claude-haiku-4-5-20251001"
    llm_moderate_model: str = "claude-sonnet-4-20250514"
    llm_complex_model: str = "claude-opus-4-20250514"
    rag_enabled: bool = False
    rag_embedding_model: str = "text-embedding-3-small"


class AuthConfig(BaseModel):
    """JWT and OIDC/SSO authentication settings."""

    jwt_secret_key: str = "change-me-in-production"  # noqa: S105
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    oidc_enabled: bool = False
    oidc_issuer_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = "http://localhost:8000/api/v1/auth/oidc/callback"
    oidc_scopes: str = "openid email profile"


class BillingConfig(BaseModel):
    """Stripe, GCP, and Azure billing settings."""

    # Stripe
    stripe_secret_key: str = ""
    stripe_publishable_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_api_key: str = ""
    stripe_success_url: str = "http://localhost:5173/settings?billing=success"
    stripe_cancel_url: str = "http://localhost:5173/settings?billing=cancel"
    stripe_price_starter: str = ""
    stripe_price_professional: str = ""
    stripe_price_enterprise: str = ""

    # GCP Billing
    gcp_billing_dataset: str = "billing_export"
    gcp_billing_table: str = "gcp_billing_export_v1"

    # Azure Billing
    azure_billing_enabled: bool = False


class ObservabilityConfig(BaseModel):
    """Observability, tracing, and monitoring settings."""

    langsmith_api_key: str = ""
    langsmith_project: str = "shieldops"
    langsmith_enabled: bool = False
    otel_exporter_endpoint: str = "http://localhost:4317"
    otel_endpoint: str = "http://localhost:4317"
    prometheus_url: str = "http://localhost:9090"
    splunk_url: str = ""
    splunk_token: str = ""
    splunk_index: str = "main"
    splunk_verify_ssl: bool = True
    datadog_api_key: str = ""
    datadog_app_key: str = ""
    datadog_site: str = "datadoghq.com"
    jaeger_url: str = ""
    newrelic_api_key: str = ""
    newrelic_account_id: str = ""
    elastic_url: str = ""
    elastic_api_key: str = ""
    tracing_enabled: bool = False


class RateLimitConfig(BaseModel):
    """HTTP API rate limiting settings."""

    rate_limit_enabled: bool = True
    rate_limit_window_seconds: int = 60
    sliding_window_rate_limit_enabled: bool = False
    rate_limit_admin: int = 300
    rate_limit_operator: int = 120
    rate_limit_viewer: int = 60
    rate_limit_default: int = 60
    rate_limit_auth_login: int = 10
    rate_limit_auth_register: int = 5


class ScannersConfig(BaseModel):
    """Security scanner and SBOM settings."""

    nvd_api_key: str = ""
    trivy_server_url: str = ""
    trivy_timeout: int = 300
    gitleaks_path: str = "gitleaks"
    osv_scanner_path: str = "osv-scanner"
    checkov_path: str = "checkov"
    iac_scanner_enabled: bool = False
    git_scanner_enabled: bool = False
    k8s_scanner_enabled: bool = False
    network_scanner_enabled: bool = False
    syft_path: str = "syft"
    sbom_enabled: bool = False
    mitre_attack_enabled: bool = False
    epss_enabled: bool = False
    ghsa_enabled: bool = False
    os_advisory_feeds_enabled: bool = False


class NotificationsConfig(BaseModel):
    """Slack, PagerDuty, webhook, and email notification settings."""

    # Slack
    slack_bot_token: str = ""
    slack_signing_secret: str = ""
    slack_approval_channel: str = "#shieldops-approvals"

    # PagerDuty
    pagerduty_routing_key: str = ""
    pagerduty_api_key: str = ""
    pagerduty_service_ids: str = ""

    # Webhooks
    webhook_url: str = ""
    webhook_secret: str = ""
    webhook_timeout: float = 10.0

    # Email / SMTP
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_from_address: str = "shieldops@localhost"
    smtp_to_addresses: list[str] = []

    # Chat session
    chat_session_ttl_seconds: int = 86400
    chat_max_messages_per_session: int = 50


class ConnectorsConfig(BaseModel):
    """Cloud, security, and ITSM connector settings."""

    # AWS
    aws_region: str = ""
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    cloudwatch_log_group: str = ""

    # GCP
    gcp_project_id: str = ""
    gcp_region: str = "us-central1"

    # Azure
    azure_subscription_id: str = ""
    azure_resource_group: str = ""
    azure_location: str = "eastus"

    # OPA
    opa_endpoint: str = "http://localhost:8181"

    # Linux SSH
    linux_host: str = ""
    linux_username: str = ""
    linux_private_key_path: str = ""

    # Windows WinRM
    windows_host: str = ""
    windows_username: str = ""
    windows_password: str = ""
    windows_use_ssl: bool = True
    windows_port: int = 5986

    # CrowdStrike
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    crowdstrike_base_url: str = "https://api.crowdstrike.com"

    # Microsoft Defender
    defender_tenant_id: str = ""
    defender_client_id: str = ""
    defender_client_secret: str = ""

    # Wiz
    wiz_client_id: str = ""
    wiz_client_secret: str = ""
    wiz_api_endpoint: str = "https://api.us1.app.wiz.io/graphql"

    # Splunk (extended connector fields)
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""

    # Elastic (extended)
    elastic_cloud_id: str = ""

    # New Relic (extended)
    newrelic_region: str = "US"

    # ServiceNow
    servicenow_instance_url: str = ""
    servicenow_username: str = ""
    servicenow_password: str = ""

    # Jira
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""

    # OpsGenie
    opsgenie_api_key: str = ""


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


class SecurityConfig(BaseModel):
    """Vault, secret management, and security settings."""

    vault_addr: str = ""
    vault_token: str = ""
    vault_mount_point: str = "secret"
    vault_namespace: str = ""
    gcp_secret_manager_enabled: bool = False
    azure_keyvault_url: str = ""
    github_advisory_token: str = ""


# Map flat field names to (sub_config_name, nested_field_name)
_FLAT_TO_NESTED: dict[str, tuple[str, str]] = {
    "app_name": ("app", "app_name"),
    "app_version": ("app", "app_version"),
    "debug": ("app", "debug"),
    "environment": ("app", "environment"),
    "api_host": ("api", "api_host"),
    "api_port": ("api", "api_port"),
    "api_prefix": ("api", "api_prefix"),
    "cors_origins": ("api", "cors_origins"),
    "database_url": ("database", "database_url"),
    "database_pool_size": ("database", "database_pool_size"),
    "redis_url": ("redis", "redis_url"),
    "rate_limit_enabled": ("rate_limiting", "rate_limit_enabled"),
    "rate_limit_window_seconds": ("rate_limiting", "rate_limit_window_seconds"),
    "sliding_window_rate_limit_enabled": ("rate_limiting", "sliding_window_rate_limit_enabled"),
    "rate_limit_admin": ("rate_limiting", "rate_limit_admin"),
    "rate_limit_operator": ("rate_limiting", "rate_limit_operator"),
    "rate_limit_viewer": ("rate_limiting", "rate_limit_viewer"),
    "rate_limit_default": ("rate_limiting", "rate_limit_default"),
    "rate_limit_auth_login": ("rate_limiting", "rate_limit_auth_login"),
    "rate_limit_auth_register": ("rate_limiting", "rate_limit_auth_register"),
    "kafka_brokers": ("kafka", "kafka_brokers"),
    "kafka_consumer_group": ("kafka", "kafka_consumer_group"),
    "anthropic_api_key": ("llm", "anthropic_api_key"),
    "anthropic_model": ("llm", "anthropic_model"),
    "openai_api_key": ("llm", "openai_api_key"),
    "openai_model": ("llm", "openai_model"),
    "agent_confidence_threshold_auto": ("agents", "agent_confidence_threshold_auto"),
    "agent_confidence_threshold_approval": ("agents", "agent_confidence_threshold_approval"),
    "agent_max_investigation_time_seconds": ("agents", "agent_max_investigation_time_seconds"),
    "agent_max_remediation_retries": ("agents", "agent_max_remediation_retries"),
    "opa_endpoint": ("connectors", "opa_endpoint"),
    "langsmith_api_key": ("observability", "langsmith_api_key"),
    "langsmith_project": ("observability", "langsmith_project"),
    "langsmith_enabled": ("observability", "langsmith_enabled"),
    "otel_exporter_endpoint": ("observability", "otel_exporter_endpoint"),
    "prometheus_url": ("observability", "prometheus_url"),
    "splunk_url": ("observability", "splunk_url"),
    "splunk_token": ("observability", "splunk_token"),
    "splunk_index": ("observability", "splunk_index"),
    "splunk_verify_ssl": ("observability", "splunk_verify_ssl"),
    "datadog_api_key": ("observability", "datadog_api_key"),
    "datadog_app_key": ("observability", "datadog_app_key"),
    "datadog_site": ("observability", "datadog_site"),
    "jaeger_url": ("observability", "jaeger_url"),
    "slack_bot_token": ("notifications", "slack_bot_token"),
    "slack_signing_secret": ("notifications", "slack_signing_secret"),
    "slack_approval_channel": ("notifications", "slack_approval_channel"),
    "pagerduty_routing_key": ("notifications", "pagerduty_routing_key"),
    "pagerduty_api_key": ("notifications", "pagerduty_api_key"),
    "pagerduty_service_ids": ("notifications", "pagerduty_service_ids"),
    "webhook_url": ("notifications", "webhook_url"),
    "webhook_secret": ("notifications", "webhook_secret"),
    "webhook_timeout": ("notifications", "webhook_timeout"),
    "smtp_host": ("notifications", "smtp_host"),
    "smtp_port": ("notifications", "smtp_port"),
    "smtp_username": ("notifications", "smtp_username"),
    "smtp_password": ("notifications", "smtp_password"),
    "smtp_use_tls": ("notifications", "smtp_use_tls"),
    "smtp_from_address": ("notifications", "smtp_from_address"),
    "smtp_to_addresses": ("notifications", "smtp_to_addresses"),
    "aws_region": ("connectors", "aws_region"),
    "aws_access_key_id": ("connectors", "aws_access_key_id"),
    "aws_secret_access_key": ("connectors", "aws_secret_access_key"),
    "cloudwatch_log_group": ("connectors", "cloudwatch_log_group"),
    "gcp_project_id": ("connectors", "gcp_project_id"),
    "gcp_region": ("connectors", "gcp_region"),
    "azure_subscription_id": ("connectors", "azure_subscription_id"),
    "azure_resource_group": ("connectors", "azure_resource_group"),
    "azure_location": ("connectors", "azure_location"),
    "gcp_billing_dataset": ("billing", "gcp_billing_dataset"),
    "gcp_billing_table": ("billing", "gcp_billing_table"),
    "azure_billing_enabled": ("billing", "azure_billing_enabled"),
    "stripe_secret_key": ("billing", "stripe_secret_key"),
    "stripe_publishable_key": ("billing", "stripe_publishable_key"),
    "stripe_webhook_secret": ("billing", "stripe_webhook_secret"),
    "stripe_api_key": ("billing", "stripe_api_key"),
    "stripe_success_url": ("billing", "stripe_success_url"),
    "stripe_cancel_url": ("billing", "stripe_cancel_url"),
    "stripe_price_starter": ("billing", "stripe_price_starter"),
    "stripe_price_professional": ("billing", "stripe_price_professional"),
    "stripe_price_enterprise": ("billing", "stripe_price_enterprise"),
    "nvd_api_key": ("scanners", "nvd_api_key"),
    "trivy_server_url": ("scanners", "trivy_server_url"),
    "trivy_timeout": ("scanners", "trivy_timeout"),
    "gitleaks_path": ("scanners", "gitleaks_path"),
    "osv_scanner_path": ("scanners", "osv_scanner_path"),
    "checkov_path": ("scanners", "checkov_path"),
    "iac_scanner_enabled": ("scanners", "iac_scanner_enabled"),
    "git_scanner_enabled": ("scanners", "git_scanner_enabled"),
    "k8s_scanner_enabled": ("scanners", "k8s_scanner_enabled"),
    "network_scanner_enabled": ("scanners", "network_scanner_enabled"),
    "vault_addr": ("security", "vault_addr"),
    "vault_token": ("security", "vault_token"),
    "vault_mount_point": ("security", "vault_mount_point"),
    "vault_namespace": ("security", "vault_namespace"),
    "linux_host": ("connectors", "linux_host"),
    "linux_username": ("connectors", "linux_username"),
    "linux_private_key_path": ("connectors", "linux_private_key_path"),
    "windows_host": ("connectors", "windows_host"),
    "windows_username": ("connectors", "windows_username"),
    "windows_password": ("connectors", "windows_password"),
    "windows_use_ssl": ("connectors", "windows_use_ssl"),
    "windows_port": ("connectors", "windows_port"),
    "chat_session_ttl_seconds": ("notifications", "chat_session_ttl_seconds"),
    "chat_max_messages_per_session": ("notifications", "chat_max_messages_per_session"),
    "gcp_secret_manager_enabled": ("security", "gcp_secret_manager_enabled"),
    "azure_keyvault_url": ("security", "azure_keyvault_url"),
    "github_advisory_token": ("security", "github_advisory_token"),
    "ghsa_enabled": ("scanners", "ghsa_enabled"),
    "os_advisory_feeds_enabled": ("scanners", "os_advisory_feeds_enabled"),
    "syft_path": ("scanners", "syft_path"),
    "sbom_enabled": ("scanners", "sbom_enabled"),
    "mitre_attack_enabled": ("scanners", "mitre_attack_enabled"),
    "epss_enabled": ("scanners", "epss_enabled"),
    "jwt_secret_key": ("auth", "jwt_secret_key"),
    "jwt_algorithm": ("auth", "jwt_algorithm"),
    "jwt_expire_minutes": ("auth", "jwt_expire_minutes"),
    "prediction_confidence_threshold": ("engines", "prediction_confidence_threshold"),
    "prediction_schedule_minutes": ("engines", "prediction_schedule_minutes"),
    "rag_enabled": ("llm", "rag_enabled"),
    "rag_embedding_model": ("llm", "rag_embedding_model"),
    "llm_routing_enabled": ("llm", "llm_routing_enabled"),
    "llm_simple_model": ("llm", "llm_simple_model"),
    "llm_moderate_model": ("llm", "llm_moderate_model"),
    "llm_complex_model": ("llm", "llm_complex_model"),
    "newrelic_api_key": ("observability", "newrelic_api_key"),
    "newrelic_account_id": ("observability", "newrelic_account_id"),
    "elastic_url": ("observability", "elastic_url"),
    "elastic_api_key": ("observability", "elastic_api_key"),
    "tracing_enabled": ("observability", "tracing_enabled"),
    "otel_endpoint": ("observability", "otel_endpoint"),
    "slo_burn_rate_threshold": ("engines", "slo_burn_rate_threshold"),
    "idempotency_ttl_seconds": ("engines", "idempotency_ttl_seconds"),
    "hot_reload_enabled": ("engines", "hot_reload_enabled"),
    "oidc_enabled": ("auth", "oidc_enabled"),
    "oidc_issuer_url": ("auth", "oidc_issuer_url"),
    "oidc_client_id": ("auth", "oidc_client_id"),
    "oidc_client_secret": ("auth", "oidc_client_secret"),
    "oidc_redirect_uri": ("auth", "oidc_redirect_uri"),
    "oidc_scopes": ("auth", "oidc_scopes"),
    "cache_l1_max_size": ("engines", "cache_l1_max_size"),
    "cache_l1_ttl_seconds": ("engines", "cache_l1_ttl_seconds"),
    "cache_l1_enabled": ("engines", "cache_l1_enabled"),
    "feature_flags_enabled": ("engines", "feature_flags_enabled"),
    "feature_flags_sync_interval_seconds": ("engines", "feature_flags_sync_interval_seconds"),
    "health_history_size": ("engines", "health_history_size"),
    "health_check_interval_seconds": ("engines", "health_check_interval_seconds"),
    "health_degraded_threshold": ("engines", "health_degraded_threshold"),
    "health_unhealthy_threshold": ("engines", "health_unhealthy_threshold"),
    "correlation_enabled": ("engines", "correlation_enabled"),
    "correlation_max_traces": ("engines", "correlation_max_traces"),
    "correlation_trace_ttl_minutes": ("engines", "correlation_trace_ttl_minutes"),
    "escalation_enabled": ("engines", "escalation_enabled"),
    "escalation_default_timeout_seconds": ("engines", "escalation_default_timeout_seconds"),
    "escalation_max_retries": ("engines", "escalation_max_retries"),
    "agent_global_max_concurrent": ("agents", "agent_global_max_concurrent"),
    "agent_quota_enabled": ("agents", "agent_quota_enabled"),
    "batch_max_size": ("engines", "batch_max_size"),
    "batch_max_parallel": ("engines", "batch_max_parallel"),
    "batch_job_ttl_hours": ("engines", "batch_job_ttl_hours"),
    "timeline_max_events_per_incident": ("engines", "timeline_max_events_per_incident"),
    "timeline_retention_days": ("engines", "timeline_retention_days"),
    "export_max_rows": ("engines", "export_max_rows"),
    "export_pdf_enabled": ("engines", "export_pdf_enabled"),
    "export_xlsx_enabled": ("engines", "export_xlsx_enabled"),
    "promotion_require_approval_for_prod": ("engines", "promotion_require_approval_for_prod"),
    "promotion_allowed_source_envs": ("engines", "promotion_allowed_source_envs"),
    "api_deprecation_header_enabled": ("engines", "api_deprecation_header_enabled"),
    "api_sunset_warning_days": ("engines", "api_sunset_warning_days"),
    "agent_collaboration_enabled": ("agents", "agent_collaboration_enabled"),
    "agent_collaboration_max_messages": ("agents", "agent_collaboration_max_messages"),
    "agent_collaboration_session_timeout_minutes": (
        "agents",
        "agent_collaboration_session_timeout_minutes",
    ),
    "postmortem_enabled": ("engines", "postmortem_enabled"),
    "postmortem_max_reports": ("engines", "postmortem_max_reports"),
    "dora_enabled": ("engines", "dora_enabled"),
    "dora_default_period_days": ("engines", "dora_default_period_days"),
    "dora_max_records": ("engines", "dora_max_records"),
    "alert_suppression_enabled": ("engines", "alert_suppression_enabled"),
    "alert_suppression_max_rules": ("engines", "alert_suppression_max_rules"),
    "maintenance_window_max_duration_hours": ("engines", "maintenance_window_max_duration_hours"),
    "oncall_enabled": ("engines", "oncall_enabled"),
    "oncall_default_rotation": ("engines", "oncall_default_rotation"),
    "oncall_max_schedules": ("engines", "oncall_max_schedules"),
    "service_ownership_enabled": ("engines", "service_ownership_enabled"),
    "service_ownership_max_entries": ("engines", "service_ownership_max_entries"),
    "runbook_tracking_enabled": ("engines", "runbook_tracking_enabled"),
    "runbook_max_executions": ("engines", "runbook_max_executions"),
    "runbook_execution_ttl_days": ("engines", "runbook_execution_ttl_days"),
    "impact_scoring_enabled": ("engines", "impact_scoring_enabled"),
    "impact_max_records": ("engines", "impact_max_records"),
    "drift_detection_enabled": ("engines", "drift_detection_enabled"),
    "drift_max_snapshots_per_env": ("engines", "drift_max_snapshots_per_env"),
    "drift_retention_days": ("engines", "drift_retention_days"),
    "cost_anomaly_enabled": ("engines", "cost_anomaly_enabled"),
    "cost_anomaly_z_threshold": ("engines", "cost_anomaly_z_threshold"),
    "cost_anomaly_lookback_days": ("engines", "cost_anomaly_lookback_days"),
    "compliance_reports_enabled": ("engines", "compliance_reports_enabled"),
    "compliance_max_reports": ("engines", "compliance_max_reports"),
    "agent_benchmark_enabled": ("agents", "agent_benchmark_enabled"),
    "agent_benchmark_baseline_days": ("agents", "agent_benchmark_baseline_days"),
    "agent_benchmark_regression_threshold": ("agents", "agent_benchmark_regression_threshold"),
    "webhook_replay_enabled": ("engines", "webhook_replay_enabled"),
    "webhook_replay_max_retries": ("engines", "webhook_replay_max_retries"),
    "webhook_replay_max_deliveries": ("engines", "webhook_replay_max_deliveries"),
    "dependency_health_enabled": ("engines", "dependency_health_enabled"),
    "dependency_health_max_checks": ("engines", "dependency_health_max_checks"),
    "dependency_cascade_threshold": ("engines", "dependency_cascade_threshold"),
    "deployment_freeze_enabled": ("engines", "deployment_freeze_enabled"),
    "deployment_freeze_max_windows": ("engines", "deployment_freeze_max_windows"),
    "deployment_freeze_max_duration_days": ("engines", "deployment_freeze_max_duration_days"),
    "error_budget_enabled": ("engines", "error_budget_enabled"),
    "error_budget_warning_threshold": ("engines", "error_budget_warning_threshold"),
    "error_budget_critical_threshold": ("engines", "error_budget_critical_threshold"),
    "alert_grouping_enabled": ("engines", "alert_grouping_enabled"),
    "alert_grouping_window_seconds": ("engines", "alert_grouping_window_seconds"),
    "alert_grouping_max_groups": ("engines", "alert_grouping_max_groups"),
    "status_page_enabled": ("engines", "status_page_enabled"),
    "status_page_max_components": ("engines", "status_page_max_components"),
    "status_page_max_incidents": ("engines", "status_page_max_incidents"),
    "rollback_registry_enabled": ("engines", "rollback_registry_enabled"),
    "rollback_registry_max_events": ("engines", "rollback_registry_max_events"),
    "rollback_pattern_lookback_days": ("engines", "rollback_pattern_lookback_days"),
    "capacity_reservation_enabled": ("engines", "capacity_reservation_enabled"),
    "capacity_reservation_max_active": ("engines", "capacity_reservation_max_active"),
    "capacity_reservation_max_duration_days": ("engines", "capacity_reservation_max_duration_days"),
    "dep_vuln_mapping_enabled": ("engines", "dep_vuln_mapping_enabled"),
    "dep_vuln_max_services": ("engines", "dep_vuln_max_services"),
    "dep_vuln_max_depth": ("engines", "dep_vuln_max_depth"),
    "readiness_review_enabled": ("engines", "readiness_review_enabled"),
    "readiness_review_max_checklists": ("engines", "readiness_review_max_checklists"),
    "readiness_review_passing_threshold": ("engines", "readiness_review_passing_threshold"),
    "rate_limit_analytics_enabled": ("engines", "rate_limit_analytics_enabled"),
    "rate_limit_analytics_max_events": ("engines", "rate_limit_analytics_max_events"),
    "rate_limit_analytics_retention_hours": ("engines", "rate_limit_analytics_retention_hours"),
    "agent_decision_tracking_enabled": ("agents", "agent_decision_tracking_enabled"),
    "agent_decision_max_records": ("agents", "agent_decision_max_records"),
    "agent_decision_retention_days": ("agents", "agent_decision_retention_days"),
    "runbook_scheduler_enabled": ("engines", "runbook_scheduler_enabled"),
    "runbook_scheduler_max_schedules": ("engines", "runbook_scheduler_max_schedules"),
    "runbook_scheduler_lookahead_minutes": ("engines", "runbook_scheduler_lookahead_minutes"),
    "war_room_enabled": ("engines", "war_room_enabled"),
    "war_room_max_rooms": ("engines", "war_room_max_rooms"),
    "war_room_auto_escalate_minutes": ("engines", "war_room_auto_escalate_minutes"),
    "retrospective_enabled": ("engines", "retrospective_enabled"),
    "retrospective_max_retros": ("engines", "retrospective_max_retros"),
    "retrospective_action_overdue_days": ("engines", "retrospective_action_overdue_days"),
    "change_risk_enabled": ("engines", "change_risk_enabled"),
    "change_risk_max_records": ("engines", "change_risk_max_records"),
    "change_risk_high_threshold": ("engines", "change_risk_high_threshold"),
    "change_risk_critical_threshold": ("engines", "change_risk_critical_threshold"),
    "sla_violation_enabled": ("engines", "sla_violation_enabled"),
    "sla_violation_max_targets": ("engines", "sla_violation_max_targets"),
    "sla_violation_max_violations": ("engines", "sla_violation_max_violations"),
    "tagging_compliance_enabled": ("engines", "tagging_compliance_enabled"),
    "tagging_compliance_max_policies": ("engines", "tagging_compliance_max_policies"),
    "tagging_compliance_max_records": ("engines", "tagging_compliance_max_records"),
    "cost_attribution_enabled": ("engines", "cost_attribution_enabled"),
    "cost_attribution_max_rules": ("engines", "cost_attribution_max_rules"),
    "cost_attribution_max_entries": ("engines", "cost_attribution_max_entries"),
    "cost_normalizer_enabled": ("engines", "cost_normalizer_enabled"),
    "cost_normalizer_max_pricing": ("engines", "cost_normalizer_max_pricing"),
    "temporal_patterns_enabled": ("engines", "temporal_patterns_enabled"),
    "temporal_patterns_max_events": ("engines", "temporal_patterns_max_events"),
    "temporal_patterns_min_occurrences": ("engines", "temporal_patterns_min_occurrences"),
    "continuous_compliance_enabled": ("engines", "continuous_compliance_enabled"),
    "continuous_compliance_max_controls": ("engines", "continuous_compliance_max_controls"),
    "continuous_compliance_max_records": ("engines", "continuous_compliance_max_records"),
    "third_party_risk_enabled": ("engines", "third_party_risk_enabled"),
    "third_party_risk_max_vendors": ("engines", "third_party_risk_max_vendors"),
    "third_party_risk_reassessment_days": ("engines", "third_party_risk_reassessment_days"),
    "roi_tracker_enabled": ("engines", "roi_tracker_enabled"),
    "roi_tracker_max_entries": ("engines", "roi_tracker_max_entries"),
    "infrastructure_map_enabled": ("engines", "infrastructure_map_enabled"),
    "infrastructure_map_max_nodes": ("engines", "infrastructure_map_max_nodes"),
    "infrastructure_map_max_relationships": ("engines", "infrastructure_map_max_relationships"),
    "secret_rotation_enabled": ("engines", "secret_rotation_enabled"),
    "secret_rotation_max_secrets": ("engines", "secret_rotation_max_secrets"),
    "secret_rotation_default_days": ("engines", "secret_rotation_default_days"),
    "anomaly_correlation_enabled": ("engines", "anomaly_correlation_enabled"),
    "anomaly_correlation_max_events": ("engines", "anomaly_correlation_max_events"),
    "anomaly_correlation_window_seconds": ("engines", "anomaly_correlation_window_seconds"),
    "synthetic_monitor_enabled": ("engines", "synthetic_monitor_enabled"),
    "synthetic_monitor_max_monitors": ("engines", "synthetic_monitor_max_monitors"),
    "synthetic_monitor_max_results": ("engines", "synthetic_monitor_max_results"),
    "synthetic_monitor_failure_threshold": ("engines", "synthetic_monitor_failure_threshold"),
    "chaos_experiments_enabled": ("engines", "chaos_experiments_enabled"),
    "chaos_experiments_max_experiments": ("engines", "chaos_experiments_max_experiments"),
    "chaos_experiments_max_results": ("engines", "chaos_experiments_max_results"),
    "data_quality_enabled": ("engines", "data_quality_enabled"),
    "data_quality_max_rules": ("engines", "data_quality_max_rules"),
    "data_quality_max_results": ("engines", "data_quality_max_results"),
    "data_quality_alert_cooldown": ("engines", "data_quality_alert_cooldown"),
    "canary_tracker_enabled": ("engines", "canary_tracker_enabled"),
    "canary_tracker_max_deployments": ("engines", "canary_tracker_max_deployments"),
    "canary_tracker_max_metrics": ("engines", "canary_tracker_max_metrics"),
    "incident_comms_enabled": ("engines", "incident_comms_enabled"),
    "incident_comms_max_templates": ("engines", "incident_comms_max_templates"),
    "incident_comms_max_messages": ("engines", "incident_comms_max_messages"),
    "dependency_sla_enabled": ("engines", "dependency_sla_enabled"),
    "dependency_sla_max_slas": ("engines", "dependency_sla_max_slas"),
    "dependency_sla_max_evaluations": ("engines", "dependency_sla_max_evaluations"),
    "posture_scorer_enabled": ("engines", "posture_scorer_enabled"),
    "posture_scorer_max_checks": ("engines", "posture_scorer_max_checks"),
    "posture_scorer_max_scores": ("engines", "posture_scorer_max_scores"),
    "workload_fingerprint_enabled": ("engines", "workload_fingerprint_enabled"),
    "workload_fingerprint_max_samples": ("engines", "workload_fingerprint_max_samples"),
    "workload_fingerprint_min_stable": ("engines", "workload_fingerprint_min_stable"),
    "workload_fingerprint_drift_threshold": ("engines", "workload_fingerprint_drift_threshold"),
    "maintenance_window_enabled": ("engines", "maintenance_window_enabled"),
    "maintenance_window_max_windows": ("engines", "maintenance_window_max_windows"),
    "evidence_collector_enabled": ("engines", "evidence_collector_enabled"),
    "evidence_collector_max_evidence": ("engines", "evidence_collector_max_evidence"),
    "evidence_collector_max_packages": ("engines", "evidence_collector_max_packages"),
    "runbook_recommender_enabled": ("engines", "runbook_recommender_enabled"),
    "runbook_recommender_max_profiles": ("engines", "runbook_recommender_max_profiles"),
    "runbook_recommender_max_candidates": ("engines", "runbook_recommender_max_candidates"),
    "runbook_recommender_min_score": ("engines", "runbook_recommender_min_score"),
    "incident_clustering_enabled": ("engines", "incident_clustering_enabled"),
    "incident_clustering_max_incidents": ("engines", "incident_clustering_max_incidents"),
    "incident_clustering_max_clusters": ("engines", "incident_clustering_max_clusters"),
    "incident_clustering_similarity": ("engines", "incident_clustering_similarity"),
    "policy_generator_enabled": ("engines", "policy_generator_enabled"),
    "policy_generator_max_requirements": ("engines", "policy_generator_max_requirements"),
    "policy_generator_max_policies": ("engines", "policy_generator_max_policies"),
    "change_advisory_enabled": ("engines", "change_advisory_enabled"),
    "change_advisory_max_requests": ("engines", "change_advisory_max_requests"),
    "change_advisory_max_votes": ("engines", "change_advisory_max_votes"),
    "change_advisory_auto_approve": ("engines", "change_advisory_auto_approve"),
    "sre_metrics_enabled": ("engines", "sre_metrics_enabled"),
    "sre_metrics_max_datapoints": ("engines", "sre_metrics_max_datapoints"),
    "sre_metrics_max_scorecards": ("engines", "sre_metrics_max_scorecards"),
    "health_report_enabled": ("engines", "health_report_enabled"),
    "health_report_max_reports": ("engines", "health_report_max_reports"),
    "approval_delegation_enabled": ("engines", "approval_delegation_enabled"),
    "approval_delegation_max_rules": ("engines", "approval_delegation_max_rules"),
    "approval_delegation_max_audit": ("engines", "approval_delegation_max_audit"),
    "gap_analyzer_enabled": ("engines", "gap_analyzer_enabled"),
    "gap_analyzer_max_controls": ("engines", "gap_analyzer_max_controls"),
    "gap_analyzer_max_gaps": ("engines", "gap_analyzer_max_gaps"),
    "cost_forecast_enabled": ("engines", "cost_forecast_enabled"),
    "cost_forecast_max_datapoints": ("engines", "cost_forecast_max_datapoints"),
    "cost_forecast_max_forecasts": ("engines", "cost_forecast_max_forecasts"),
    "cost_forecast_alert_threshold": ("engines", "cost_forecast_alert_threshold"),
    "deployment_risk_enabled": ("engines", "deployment_risk_enabled"),
    "deployment_risk_max_records": ("engines", "deployment_risk_max_records"),
    "deployment_risk_max_assessments": ("engines", "deployment_risk_max_assessments"),
    "capacity_trends_enabled": ("engines", "capacity_trends_enabled"),
    "capacity_trends_max_snapshots": ("engines", "capacity_trends_max_snapshots"),
    "capacity_trends_max_analyses": ("engines", "capacity_trends_max_analyses"),
    "capacity_trends_exhaustion_threshold": ("engines", "capacity_trends_exhaustion_threshold"),
    "incident_learning_enabled": ("engines", "incident_learning_enabled"),
    "incident_learning_max_lessons": ("engines", "incident_learning_max_lessons"),
    "incident_learning_max_applications": ("engines", "incident_learning_max_applications"),
    "tenant_isolation_enabled": ("engines", "tenant_isolation_enabled"),
    "tenant_isolation_max_tenants": ("engines", "tenant_isolation_max_tenants"),
    "tenant_isolation_max_violations": ("engines", "tenant_isolation_max_violations"),
    "alert_noise_enabled": ("engines", "alert_noise_enabled"),
    "alert_noise_max_records": ("engines", "alert_noise_max_records"),
    "alert_noise_threshold": ("engines", "alert_noise_threshold"),
    "threshold_tuner_enabled": ("engines", "threshold_tuner_enabled"),
    "threshold_tuner_max_thresholds": ("engines", "threshold_tuner_max_thresholds"),
    "threshold_tuner_max_samples": ("engines", "threshold_tuner_max_samples"),
    "severity_predictor_enabled": ("engines", "severity_predictor_enabled"),
    "severity_predictor_max_predictions": ("engines", "severity_predictor_max_predictions"),
    "severity_predictor_max_profiles": ("engines", "severity_predictor_max_profiles"),
    "impact_analyzer_enabled": ("engines", "impact_analyzer_enabled"),
    "impact_analyzer_max_dependencies": ("engines", "impact_analyzer_max_dependencies"),
    "impact_analyzer_max_simulations": ("engines", "impact_analyzer_max_simulations"),
    "config_audit_enabled": ("engines", "config_audit_enabled"),
    "config_audit_max_entries": ("engines", "config_audit_max_entries"),
    "config_audit_max_versions_per_key": ("engines", "config_audit_max_versions_per_key"),
    "deployment_velocity_enabled": ("engines", "deployment_velocity_enabled"),
    "deployment_velocity_max_events": ("engines", "deployment_velocity_max_events"),
    "deployment_velocity_default_period_days": (
        "engines",
        "deployment_velocity_default_period_days",
    ),
    "compliance_automation_enabled": ("engines", "compliance_automation_enabled"),
    "compliance_automation_max_rules": ("engines", "compliance_automation_max_rules"),
    "compliance_automation_max_executions": ("engines", "compliance_automation_max_executions"),
    "knowledge_base_enabled": ("engines", "knowledge_base_enabled"),
    "knowledge_base_max_articles": ("engines", "knowledge_base_max_articles"),
    "knowledge_base_max_votes": ("engines", "knowledge_base_max_votes"),
    "oncall_fatigue_enabled": ("engines", "oncall_fatigue_enabled"),
    "oncall_fatigue_max_events": ("engines", "oncall_fatigue_max_events"),
    "oncall_fatigue_burnout_threshold": ("engines", "oncall_fatigue_burnout_threshold"),
    "backup_verification_enabled": ("engines", "backup_verification_enabled"),
    "backup_verification_max_backups": ("engines", "backup_verification_max_backups"),
    "backup_verification_stale_hours": ("engines", "backup_verification_stale_hours"),
    "cost_tag_enforcer_enabled": ("engines", "cost_tag_enforcer_enabled"),
    "cost_tag_enforcer_max_policies": ("engines", "cost_tag_enforcer_max_policies"),
    "cost_tag_enforcer_max_checks": ("engines", "cost_tag_enforcer_max_checks"),
    "dr_readiness_enabled": ("engines", "dr_readiness_enabled"),
    "dr_readiness_max_plans": ("engines", "dr_readiness_max_plans"),
    "dr_readiness_drill_max_age_days": ("engines", "dr_readiness_drill_max_age_days"),
    "service_catalog_enabled": ("engines", "service_catalog_enabled"),
    "service_catalog_max_services": ("engines", "service_catalog_max_services"),
    "service_catalog_stale_days": ("engines", "service_catalog_stale_days"),
    "contract_testing_enabled": ("engines", "contract_testing_enabled"),
    "contract_testing_max_schemas": ("engines", "contract_testing_max_schemas"),
    "contract_testing_max_checks": ("engines", "contract_testing_max_checks"),
    "orphan_detector_enabled": ("engines", "orphan_detector_enabled"),
    "orphan_detector_max_resources": ("engines", "orphan_detector_max_resources"),
    "orphan_detector_stale_days": ("engines", "orphan_detector_stale_days"),
    "latency_profiler_enabled": ("engines", "latency_profiler_enabled"),
    "latency_profiler_max_samples": ("engines", "latency_profiler_max_samples"),
    "latency_profiler_regression_threshold": ("engines", "latency_profiler_regression_threshold"),
    "license_scanner_enabled": ("engines", "license_scanner_enabled"),
    "license_scanner_max_dependencies": ("engines", "license_scanner_max_dependencies"),
    "license_scanner_max_violations": ("engines", "license_scanner_max_violations"),
    "release_manager_enabled": ("engines", "release_manager_enabled"),
    "release_manager_max_releases": ("engines", "release_manager_max_releases"),
    "release_manager_require_approval": ("engines", "release_manager_require_approval"),
    "budget_manager_enabled": ("engines", "budget_manager_enabled"),
    "budget_manager_max_budgets": ("engines", "budget_manager_max_budgets"),
    "budget_manager_warning_threshold": ("engines", "budget_manager_warning_threshold"),
    "config_parity_enabled": ("engines", "config_parity_enabled"),
    "config_parity_max_configs": ("engines", "config_parity_max_configs"),
    "config_parity_max_violations": ("engines", "config_parity_max_violations"),
    "incident_dedup_enabled": ("engines", "incident_dedup_enabled"),
    "incident_dedup_max_incidents": ("engines", "incident_dedup_max_incidents"),
    "incident_dedup_similarity_threshold": ("engines", "incident_dedup_similarity_threshold"),
    "access_certification_enabled": ("engines", "access_certification_enabled"),
    "access_certification_max_grants": ("engines", "access_certification_max_grants"),
    "access_certification_default_expiry_days": (
        "engines",
        "access_certification_default_expiry_days",
    ),
    "toil_tracker_enabled": ("engines", "toil_tracker_enabled"),
    "toil_tracker_max_entries": ("engines", "toil_tracker_max_entries"),
    "toil_tracker_automation_min_occurrences": (
        "engines",
        "toil_tracker_automation_min_occurrences",
    ),
    "trace_analyzer_enabled": ("engines", "trace_analyzer_enabled"),
    "trace_analyzer_max_traces": ("engines", "trace_analyzer_max_traces"),
    "trace_analyzer_bottleneck_threshold": ("engines", "trace_analyzer_bottleneck_threshold"),
    "log_anomaly_enabled": ("engines", "log_anomaly_enabled"),
    "log_anomaly_max_patterns": ("engines", "log_anomaly_max_patterns"),
    "log_anomaly_sensitivity": ("engines", "log_anomaly_sensitivity"),
    "event_correlation_enabled": ("engines", "event_correlation_enabled"),
    "event_correlation_max_events": ("engines", "event_correlation_max_events"),
    "event_correlation_window_minutes": ("engines", "event_correlation_window_minutes"),
    "security_incident_enabled": ("engines", "security_incident_enabled"),
    "security_incident_max_incidents": ("engines", "security_incident_max_incidents"),
    "security_incident_auto_escalate_minutes": (
        "engines",
        "security_incident_auto_escalate_minutes",
    ),
    "vuln_lifecycle_enabled": ("engines", "vuln_lifecycle_enabled"),
    "vuln_lifecycle_max_records": ("engines", "vuln_lifecycle_max_records"),
    "vuln_lifecycle_patch_sla_days": ("engines", "vuln_lifecycle_patch_sla_days"),
    "api_security_enabled": ("engines", "api_security_enabled"),
    "api_security_max_endpoints": ("engines", "api_security_max_endpoints"),
    "api_security_alert_threshold": ("engines", "api_security_alert_threshold"),
    "tag_governance_enabled": ("engines", "tag_governance_enabled"),
    "tag_governance_max_policies": ("engines", "tag_governance_max_policies"),
    "tag_governance_max_reports": ("engines", "tag_governance_max_reports"),
    "team_performance_enabled": ("engines", "team_performance_enabled"),
    "team_performance_max_members": ("engines", "team_performance_max_members"),
    "team_performance_burnout_threshold": ("engines", "team_performance_burnout_threshold"),
    "runbook_engine_enabled": ("engines", "runbook_engine_enabled"),
    "runbook_engine_max_executions": ("engines", "runbook_engine_max_executions"),
    "runbook_engine_step_timeout": ("engines", "runbook_engine_step_timeout"),
    "dependency_scorer_enabled": ("engines", "dependency_scorer_enabled"),
    "dependency_scorer_max_dependencies": ("engines", "dependency_scorer_max_dependencies"),
    "dependency_scorer_check_interval": ("engines", "dependency_scorer_check_interval"),
    "burn_predictor_enabled": ("engines", "burn_predictor_enabled"),
    "burn_predictor_max_slos": ("engines", "burn_predictor_max_slos"),
    "burn_predictor_forecast_hours": ("engines", "burn_predictor_forecast_hours"),
    "change_intelligence_enabled": ("engines", "change_intelligence_enabled"),
    "change_intelligence_max_records": ("engines", "change_intelligence_max_records"),
    "change_intelligence_risk_threshold": ("engines", "change_intelligence_risk_threshold"),
    "db_performance_enabled": ("engines", "db_performance_enabled"),
    "db_performance_max_queries": ("engines", "db_performance_max_queries"),
    "db_performance_slow_threshold_ms": ("engines", "db_performance_slow_threshold_ms"),
    "queue_health_enabled": ("engines", "queue_health_enabled"),
    "queue_health_max_metrics": ("engines", "queue_health_max_metrics"),
    "queue_health_stall_threshold_seconds": ("engines", "queue_health_stall_threshold_seconds"),
    "cert_monitor_enabled": ("engines", "cert_monitor_enabled"),
    "cert_monitor_max_certificates": ("engines", "cert_monitor_max_certificates"),
    "cert_monitor_expiry_warning_days": ("engines", "cert_monitor_expiry_warning_days"),
    "network_flow_enabled": ("engines", "network_flow_enabled"),
    "network_flow_max_records": ("engines", "network_flow_max_records"),
    "network_flow_anomaly_threshold": ("engines", "network_flow_anomaly_threshold"),
    "dns_health_enabled": ("engines", "dns_health_enabled"),
    "dns_health_max_checks": ("engines", "dns_health_max_checks"),
    "dns_health_timeout_ms": ("engines", "dns_health_timeout_ms"),
    "escalation_analyzer_enabled": ("engines", "escalation_analyzer_enabled"),
    "escalation_analyzer_max_events": ("engines", "escalation_analyzer_max_events"),
    "escalation_analyzer_false_alarm_threshold": (
        "engines",
        "escalation_analyzer_false_alarm_threshold",
    ),
    "right_sizer_enabled": ("engines", "right_sizer_enabled"),
    "right_sizer_max_samples": ("engines", "right_sizer_max_samples"),
    "right_sizer_underutil_threshold": ("engines", "right_sizer_underutil_threshold"),
    "storage_optimizer_enabled": ("engines", "storage_optimizer_enabled"),
    "storage_optimizer_max_assets": ("engines", "storage_optimizer_max_assets"),
    "storage_optimizer_cold_threshold_days": ("engines", "storage_optimizer_cold_threshold_days"),
    "resource_lifecycle_enabled": ("engines", "resource_lifecycle_enabled"),
    "resource_lifecycle_max_resources": ("engines", "resource_lifecycle_max_resources"),
    "resource_lifecycle_stale_days": ("engines", "resource_lifecycle_stale_days"),
    "alert_routing_enabled": ("engines", "alert_routing_enabled"),
    "alert_routing_max_records": ("engines", "alert_routing_max_records"),
    "alert_routing_reroute_threshold": ("engines", "alert_routing_reroute_threshold"),
    "slo_advisor_enabled": ("engines", "slo_advisor_enabled"),
    "slo_advisor_max_samples": ("engines", "slo_advisor_max_samples"),
    "slo_advisor_min_sample_count": ("engines", "slo_advisor_min_sample_count"),
    "workload_scheduler_enabled": ("engines", "workload_scheduler_enabled"),
    "workload_scheduler_max_workloads": ("engines", "workload_scheduler_max_workloads"),
    "workload_scheduler_conflict_window_seconds": (
        "engines",
        "workload_scheduler_conflict_window_seconds",
    ),
    "cascade_predictor_enabled": ("engines", "cascade_predictor_enabled"),
    "cascade_predictor_max_services": ("engines", "cascade_predictor_max_services"),
    "cascade_predictor_max_cascade_depth": ("engines", "cascade_predictor_max_cascade_depth"),
    "resilience_scorer_enabled": ("engines", "resilience_scorer_enabled"),
    "resilience_scorer_max_profiles": ("engines", "resilience_scorer_max_profiles"),
    "resilience_scorer_minimum_score_threshold": (
        "engines",
        "resilience_scorer_minimum_score_threshold",
    ),
    "timeline_reconstructor_enabled": ("engines", "timeline_reconstructor_enabled"),
    "timeline_reconstructor_max_events": ("engines", "timeline_reconstructor_max_events"),
    "timeline_reconstructor_correlation_window_seconds": (
        "engines",
        "timeline_reconstructor_correlation_window_seconds",
    ),
    "reserved_instance_optimizer_enabled": ("engines", "reserved_instance_optimizer_enabled"),
    "reserved_instance_optimizer_max_reservations": (
        "engines",
        "reserved_instance_optimizer_max_reservations",
    ),
    "reserved_instance_optimizer_expiry_warning_days": (
        "engines",
        "reserved_instance_optimizer_expiry_warning_days",
    ),
    "cost_anomaly_rca_enabled": ("engines", "cost_anomaly_rca_enabled"),
    "cost_anomaly_rca_max_spikes": ("engines", "cost_anomaly_rca_max_spikes"),
    "cost_anomaly_rca_deviation_threshold_pct": (
        "engines",
        "cost_anomaly_rca_deviation_threshold_pct",
    ),
    "spend_allocation_enabled": ("engines", "spend_allocation_enabled"),
    "spend_allocation_max_pools": ("engines", "spend_allocation_max_pools"),
    "spend_allocation_min_allocation_threshold": (
        "engines",
        "spend_allocation_min_allocation_threshold",
    ),
    "container_scanner_enabled": ("engines", "container_scanner_enabled"),
    "container_scanner_max_images": ("engines", "container_scanner_max_images"),
    "container_scanner_stale_threshold_days": ("engines", "container_scanner_stale_threshold_days"),
    "cloud_posture_manager_enabled": ("engines", "cloud_posture_manager_enabled"),
    "cloud_posture_manager_max_resources": ("engines", "cloud_posture_manager_max_resources"),
    "cloud_posture_manager_auto_resolve_days": (
        "engines",
        "cloud_posture_manager_auto_resolve_days",
    ),
    "secrets_detector_enabled": ("engines", "secrets_detector_enabled"),
    "secrets_detector_max_findings": ("engines", "secrets_detector_max_findings"),
    "secrets_detector_high_severity_threshold": (
        "engines",
        "secrets_detector_high_severity_threshold",
    ),
    "runbook_effectiveness_enabled": ("engines", "runbook_effectiveness_enabled"),
    "runbook_effectiveness_max_outcomes": ("engines", "runbook_effectiveness_max_outcomes"),
    "runbook_effectiveness_decay_window_days": (
        "engines",
        "runbook_effectiveness_decay_window_days",
    ),
    "api_deprecation_tracker_enabled": ("engines", "api_deprecation_tracker_enabled"),
    "api_deprecation_tracker_max_records": ("engines", "api_deprecation_tracker_max_records"),
    "api_deprecation_tracker_sunset_warning_days": (
        "engines",
        "api_deprecation_tracker_sunset_warning_days",
    ),
    "dependency_freshness_enabled": ("engines", "dependency_freshness_enabled"),
    "dependency_freshness_max_dependencies": ("engines", "dependency_freshness_max_dependencies"),
    "dependency_freshness_stale_version_threshold": (
        "engines",
        "dependency_freshness_stale_version_threshold",
    ),
    "chaos_designer_enabled": ("engines", "chaos_designer_enabled"),
    "chaos_designer_max_experiments": ("engines", "chaos_designer_max_experiments"),
    "chaos_designer_max_blast_radius": ("engines", "chaos_designer_max_blast_radius"),
    "game_day_planner_enabled": ("engines", "game_day_planner_enabled"),
    "game_day_planner_max_game_days": ("engines", "game_day_planner_max_game_days"),
    "game_day_planner_min_scenarios_per_day": ("engines", "game_day_planner_min_scenarios_per_day"),
    "failure_mode_catalog_enabled": ("engines", "failure_mode_catalog_enabled"),
    "failure_mode_catalog_max_modes": ("engines", "failure_mode_catalog_max_modes"),
    "failure_mode_catalog_mtbf_window_days": ("engines", "failure_mode_catalog_mtbf_window_days"),
    "oncall_optimizer_enabled": ("engines", "oncall_optimizer_enabled"),
    "oncall_optimizer_max_members": ("engines", "oncall_optimizer_max_members"),
    "oncall_optimizer_max_consecutive_days": ("engines", "oncall_optimizer_max_consecutive_days"),
    "alert_correlation_rules_enabled": ("engines", "alert_correlation_rules_enabled"),
    "alert_correlation_rules_max_rules": ("engines", "alert_correlation_rules_max_rules"),
    "alert_correlation_rules_time_window_seconds": (
        "engines",
        "alert_correlation_rules_time_window_seconds",
    ),
    "review_board_enabled": ("engines", "review_board_enabled"),
    "review_board_max_reviews": ("engines", "review_board_max_reviews"),
    "review_board_action_sla_days": ("engines", "review_board_action_sla_days"),
    "commitment_planner_enabled": ("engines", "commitment_planner_enabled"),
    "commitment_planner_max_workloads": ("engines", "commitment_planner_max_workloads"),
    "commitment_planner_min_savings_threshold_pct": (
        "engines",
        "commitment_planner_min_savings_threshold_pct",
    ),
    "cost_simulator_enabled": ("engines", "cost_simulator_enabled"),
    "cost_simulator_max_scenarios": ("engines", "cost_simulator_max_scenarios"),
    "cost_simulator_budget_breach_threshold_pct": (
        "engines",
        "cost_simulator_budget_breach_threshold_pct",
    ),
    "finops_maturity_enabled": ("engines", "finops_maturity_enabled"),
    "finops_maturity_max_assessments": ("engines", "finops_maturity_max_assessments"),
    "finops_maturity_target_level": ("engines", "finops_maturity_target_level"),
    "change_failure_tracker_enabled": ("engines", "change_failure_tracker_enabled"),
    "change_failure_tracker_max_deployments": ("engines", "change_failure_tracker_max_deployments"),
    "change_failure_tracker_trend_window_days": (
        "engines",
        "change_failure_tracker_trend_window_days",
    ),
    "toil_recommender_enabled": ("engines", "toil_recommender_enabled"),
    "toil_recommender_max_patterns": ("engines", "toil_recommender_max_patterns"),
    "toil_recommender_min_roi_multiplier": ("engines", "toil_recommender_min_roi_multiplier"),
    "sli_pipeline_enabled": ("engines", "sli_pipeline_enabled"),
    "sli_pipeline_max_definitions": ("engines", "sli_pipeline_max_definitions"),
    "sli_pipeline_data_retention_hours": ("engines", "sli_pipeline_data_retention_hours"),
    "deployment_cadence_enabled": ("engines", "deployment_cadence_enabled"),
    "deployment_cadence_max_deployments": ("engines", "deployment_cadence_max_deployments"),
    "metric_baseline_enabled": ("engines", "metric_baseline_enabled"),
    "metric_baseline_max_baselines": ("engines", "metric_baseline_max_baselines"),
    "metric_baseline_deviation_threshold_pct": (
        "engines",
        "metric_baseline_deviation_threshold_pct",
    ),
    "incident_timeline_enabled": ("engines", "incident_timeline_enabled"),
    "incident_timeline_max_entries": ("engines", "incident_timeline_max_entries"),
    "incident_timeline_target_resolution_minutes": (
        "engines",
        "incident_timeline_target_resolution_minutes",
    ),
    "service_health_agg_enabled": ("engines", "service_health_agg_enabled"),
    "service_health_agg_max_signals": ("engines", "service_health_agg_max_signals"),
    "service_health_agg_health_threshold": ("engines", "service_health_agg_health_threshold"),
    "alert_fatigue_enabled": ("engines", "alert_fatigue_enabled"),
    "alert_fatigue_max_records": ("engines", "alert_fatigue_max_records"),
    "alert_fatigue_threshold": ("engines", "alert_fatigue_threshold"),
    "change_window_enabled": ("engines", "change_window_enabled"),
    "change_window_max_records": ("engines", "change_window_max_records"),
    "change_window_min_success_rate": ("engines", "change_window_min_success_rate"),
    "resource_waste_enabled": ("engines", "resource_waste_enabled"),
    "resource_waste_max_records": ("engines", "resource_waste_max_records"),
    "resource_waste_idle_threshold_pct": ("engines", "resource_waste_idle_threshold_pct"),
    "evidence_chain_enabled": ("engines", "evidence_chain_enabled"),
    "evidence_chain_max_chains": ("engines", "evidence_chain_max_chains"),
    "evidence_chain_max_items_per_chain": ("engines", "evidence_chain_max_items_per_chain"),
    "dependency_update_planner_enabled": ("engines", "dependency_update_planner_enabled"),
    "dependency_update_planner_max_updates": ("engines", "dependency_update_planner_max_updates"),
    "dependency_update_planner_max_risk_threshold": (
        "engines",
        "dependency_update_planner_max_risk_threshold",
    ),
    "capacity_forecast_engine_enabled": ("engines", "capacity_forecast_engine_enabled"),
    "capacity_forecast_engine_max_data_points": (
        "engines",
        "capacity_forecast_engine_max_data_points",
    ),
    "capacity_forecast_engine_headroom_target_pct": (
        "engines",
        "capacity_forecast_engine_headroom_target_pct",
    ),
    "runbook_versioner_enabled": ("engines", "runbook_versioner_enabled"),
    "runbook_versioner_max_versions": ("engines", "runbook_versioner_max_versions"),
    "runbook_versioner_stale_age_days": ("engines", "runbook_versioner_stale_age_days"),
    "team_skill_matrix_enabled": ("engines", "team_skill_matrix_enabled"),
    "team_skill_matrix_max_entries": ("engines", "team_skill_matrix_max_entries"),
    "team_skill_matrix_min_coverage_per_domain": (
        "engines",
        "team_skill_matrix_min_coverage_per_domain",
    ),
    "error_budget_policy_enabled": ("engines", "error_budget_policy_enabled"),
    "error_budget_policy_max_policies": ("engines", "error_budget_policy_max_policies"),
    "error_budget_policy_warning_threshold_pct": (
        "engines",
        "error_budget_policy_warning_threshold_pct",
    ),
    "reliability_target_enabled": ("engines", "reliability_target_enabled"),
    "reliability_target_max_targets": ("engines", "reliability_target_max_targets"),
    "reliability_target_default_target_pct": ("engines", "reliability_target_default_target_pct"),
    "severity_calibrator_enabled": ("engines", "severity_calibrator_enabled"),
    "severity_calibrator_max_records": ("engines", "severity_calibrator_max_records"),
    "severity_calibrator_accuracy_target_pct": (
        "engines",
        "severity_calibrator_accuracy_target_pct",
    ),
    "dependency_mapper_enabled": ("engines", "dependency_mapper_enabled"),
    "dependency_mapper_max_edges": ("engines", "dependency_mapper_max_edges"),
    "dependency_mapper_max_chain_depth": ("engines", "dependency_mapper_max_chain_depth"),
    "alert_rule_linter_enabled": ("engines", "alert_rule_linter_enabled"),
    "alert_rule_linter_max_rules": ("engines", "alert_rule_linter_max_rules"),
    "alert_rule_linter_min_quality_score": ("engines", "alert_rule_linter_min_quality_score"),
    "deployment_gate_enabled": ("engines", "deployment_gate_enabled"),
    "deployment_gate_max_gates": ("engines", "deployment_gate_max_gates"),
    "deployment_gate_expiry_hours": ("engines", "deployment_gate_expiry_hours"),
    "billing_reconciler_enabled": ("engines", "billing_reconciler_enabled"),
    "billing_reconciler_max_records": ("engines", "billing_reconciler_max_records"),
    "billing_reconciler_discrepancy_threshold_pct": (
        "engines",
        "billing_reconciler_discrepancy_threshold_pct",
    ),
    "chargeback_engine_enabled": ("engines", "chargeback_engine_enabled"),
    "chargeback_engine_max_records": ("engines", "chargeback_engine_max_records"),
    "chargeback_engine_unallocated_threshold_pct": (
        "engines",
        "chargeback_engine_unallocated_threshold_pct",
    ),
    "compliance_drift_enabled": ("engines", "compliance_drift_enabled"),
    "compliance_drift_max_records": ("engines", "compliance_drift_max_records"),
    "compliance_drift_max_drift_rate_pct": ("engines", "compliance_drift_max_drift_rate_pct"),
    "comm_planner_enabled": ("engines", "comm_planner_enabled"),
    "comm_planner_max_plans": ("engines", "comm_planner_max_plans"),
    "comm_planner_max_overdue_minutes": ("engines", "comm_planner_max_overdue_minutes"),
    "infra_drift_reconciler_enabled": ("engines", "infra_drift_reconciler_enabled"),
    "infra_drift_reconciler_max_drifts": ("engines", "infra_drift_reconciler_max_drifts"),
    "infra_drift_reconciler_auto_reconcile_enabled": (
        "engines",
        "infra_drift_reconciler_auto_reconcile_enabled",
    ),
    "service_maturity_enabled": ("engines", "service_maturity_enabled"),
    "service_maturity_max_assessments": ("engines", "service_maturity_max_assessments"),
    "service_maturity_target_level": ("engines", "service_maturity_target_level"),
    "capacity_right_timing_enabled": ("engines", "capacity_right_timing_enabled"),
    "capacity_right_timing_max_records": ("engines", "capacity_right_timing_max_records"),
    "capacity_right_timing_lookahead_hours": ("engines", "capacity_right_timing_lookahead_hours"),
    "outage_predictor_enabled": ("engines", "outage_predictor_enabled"),
    "outage_predictor_max_records": ("engines", "outage_predictor_max_records"),
    "outage_predictor_composite_threshold": ("engines", "outage_predictor_composite_threshold"),
    "impact_quantifier_enabled": ("engines", "impact_quantifier_enabled"),
    "impact_quantifier_max_assessments": ("engines", "impact_quantifier_max_assessments"),
    "impact_quantifier_default_hourly_rate_usd": (
        "engines",
        "impact_quantifier_default_hourly_rate_usd",
    ),
    "policy_violation_tracker_enabled": ("engines", "policy_violation_tracker_enabled"),
    "policy_violation_tracker_max_records": ("engines", "policy_violation_tracker_max_records"),
    "policy_violation_tracker_repeat_threshold": (
        "engines",
        "policy_violation_tracker_repeat_threshold",
    ),
    "deploy_health_scorer_enabled": ("engines", "deploy_health_scorer_enabled"),
    "deploy_health_scorer_max_records": ("engines", "deploy_health_scorer_max_records"),
    "deploy_health_scorer_failing_threshold": ("engines", "deploy_health_scorer_failing_threshold"),
    "runbook_gap_analyzer_enabled": ("engines", "runbook_gap_analyzer_enabled"),
    "runbook_gap_analyzer_max_gaps": ("engines", "runbook_gap_analyzer_max_gaps"),
    "runbook_gap_analyzer_critical_incident_threshold": (
        "engines",
        "runbook_gap_analyzer_critical_incident_threshold",
    ),
    "credential_expiry_forecaster_enabled": ("engines", "credential_expiry_forecaster_enabled"),
    "credential_expiry_forecaster_max_records": (
        "engines",
        "credential_expiry_forecaster_max_records",
    ),
    "credential_expiry_forecaster_warning_days": (
        "engines",
        "credential_expiry_forecaster_warning_days",
    ),
    "oncall_workload_balancer_enabled": ("engines", "oncall_workload_balancer_enabled"),
    "oncall_workload_balancer_max_records": ("engines", "oncall_workload_balancer_max_records"),
    "oncall_workload_balancer_imbalance_threshold_pct": (
        "engines",
        "oncall_workload_balancer_imbalance_threshold_pct",
    ),
    "cost_anomaly_predictor_enabled": ("engines", "cost_anomaly_predictor_enabled"),
    "cost_anomaly_predictor_max_records": ("engines", "cost_anomaly_predictor_max_records"),
    "cost_anomaly_predictor_spike_threshold_usd": (
        "engines",
        "cost_anomaly_predictor_spike_threshold_usd",
    ),
    "evidence_scheduler_enabled": ("engines", "evidence_scheduler_enabled"),
    "evidence_scheduler_max_schedules": ("engines", "evidence_scheduler_max_schedules"),
    "evidence_scheduler_overdue_grace_days": ("engines", "evidence_scheduler_overdue_grace_days"),
    "latency_budget_tracker_enabled": ("engines", "latency_budget_tracker_enabled"),
    "latency_budget_tracker_max_records": ("engines", "latency_budget_tracker_max_records"),
    "latency_budget_tracker_chronic_violation_threshold": (
        "engines",
        "latency_budget_tracker_chronic_violation_threshold",
    ),
    "change_conflict_detector_enabled": ("engines", "change_conflict_detector_enabled"),
    "change_conflict_detector_max_records": ("engines", "change_conflict_detector_max_records"),
    "change_conflict_detector_lookahead_hours": (
        "engines",
        "change_conflict_detector_lookahead_hours",
    ),
    "duration_predictor_enabled": ("engines", "duration_predictor_enabled"),
    "duration_predictor_max_records": ("engines", "duration_predictor_max_records"),
    "duration_predictor_accuracy_target_pct": ("engines", "duration_predictor_accuracy_target_pct"),
    "resource_exhaustion_enabled": ("engines", "resource_exhaustion_enabled"),
    "resource_exhaustion_max_records": ("engines", "resource_exhaustion_max_records"),
    "resource_exhaustion_default_critical_hours": (
        "engines",
        "resource_exhaustion_default_critical_hours",
    ),
    "alert_storm_correlator_enabled": ("engines", "alert_storm_correlator_enabled"),
    "alert_storm_correlator_max_records": ("engines", "alert_storm_correlator_max_records"),
    "alert_storm_correlator_storm_window_seconds": (
        "engines",
        "alert_storm_correlator_storm_window_seconds",
    ),
    "canary_analyzer_enabled": ("engines", "canary_analyzer_enabled"),
    "canary_analyzer_max_records": ("engines", "canary_analyzer_max_records"),
    "canary_analyzer_deviation_threshold_pct": (
        "engines",
        "canary_analyzer_deviation_threshold_pct",
    ),
    "sla_cascader_enabled": ("engines", "sla_cascader_enabled"),
    "sla_cascader_max_records": ("engines", "sla_cascader_max_records"),
    "sla_cascader_min_acceptable_sla_pct": ("engines", "sla_cascader_min_acceptable_sla_pct"),
    "handoff_tracker_enabled": ("engines", "handoff_tracker_enabled"),
    "handoff_tracker_max_records": ("engines", "handoff_tracker_max_records"),
    "handoff_tracker_quality_threshold": ("engines", "handoff_tracker_quality_threshold"),
    "unit_economics_enabled": ("engines", "unit_economics_enabled"),
    "unit_economics_max_records": ("engines", "unit_economics_max_records"),
    "unit_economics_high_cost_threshold": ("engines", "unit_economics_high_cost_threshold"),
    "idle_resource_detector_enabled": ("engines", "idle_resource_detector_enabled"),
    "idle_resource_detector_max_records": ("engines", "idle_resource_detector_max_records"),
    "idle_resource_detector_idle_threshold_pct": (
        "engines",
        "idle_resource_detector_idle_threshold_pct",
    ),
    "penalty_calculator_enabled": ("engines", "penalty_calculator_enabled"),
    "penalty_calculator_max_records": ("engines", "penalty_calculator_max_records"),
    "penalty_calculator_default_credit_multiplier": (
        "engines",
        "penalty_calculator_default_credit_multiplier",
    ),
    "posture_trend_enabled": ("engines", "posture_trend_enabled"),
    "posture_trend_max_records": ("engines", "posture_trend_max_records"),
    "posture_trend_regression_threshold": ("engines", "posture_trend_regression_threshold"),
    "evidence_freshness_enabled": ("engines", "evidence_freshness_enabled"),
    "evidence_freshness_max_records": ("engines", "evidence_freshness_max_records"),
    "evidence_freshness_stale_days": ("engines", "evidence_freshness_stale_days"),
    "access_anomaly_enabled": ("engines", "access_anomaly_enabled"),
    "access_anomaly_max_records": ("engines", "access_anomaly_max_records"),
    "access_anomaly_threat_threshold": ("engines", "access_anomaly_threat_threshold"),
    "response_advisor_enabled": ("engines", "response_advisor_enabled"),
    "response_advisor_max_records": ("engines", "response_advisor_max_records"),
    "response_advisor_confidence_threshold": ("engines", "response_advisor_confidence_threshold"),
    "metric_rca_enabled": ("engines", "metric_rca_enabled"),
    "metric_rca_max_records": ("engines", "metric_rca_max_records"),
    "metric_rca_deviation_threshold_pct": ("engines", "metric_rca_deviation_threshold_pct"),
    "slo_forecast_enabled": ("engines", "slo_forecast_enabled"),
    "slo_forecast_max_records": ("engines", "slo_forecast_max_records"),
    "slo_forecast_risk_threshold_pct": ("engines", "slo_forecast_risk_threshold_pct"),
    "remediation_decision_enabled": ("engines", "remediation_decision_enabled"),
    "remediation_decision_max_records": ("engines", "remediation_decision_max_records"),
    "remediation_decision_max_risk_score": ("engines", "remediation_decision_max_risk_score"),
    "dependency_lag_enabled": ("engines", "dependency_lag_enabled"),
    "dependency_lag_max_records": ("engines", "dependency_lag_max_records"),
    "dependency_lag_degradation_threshold_pct": (
        "engines",
        "dependency_lag_degradation_threshold_pct",
    ),
    "escalation_effectiveness_enabled": ("engines", "escalation_effectiveness_enabled"),
    "escalation_effectiveness_max_records": ("engines", "escalation_effectiveness_max_records"),
    "escalation_effectiveness_false_rate_threshold": (
        "engines",
        "escalation_effectiveness_false_rate_threshold",
    ),
    "discount_optimizer_enabled": ("engines", "discount_optimizer_enabled"),
    "discount_optimizer_max_records": ("engines", "discount_optimizer_max_records"),
    "discount_optimizer_min_coverage_pct": ("engines", "discount_optimizer_min_coverage_pct"),
    "audit_trail_analyzer_enabled": ("engines", "audit_trail_analyzer_enabled"),
    "audit_trail_analyzer_max_records": ("engines", "audit_trail_analyzer_max_records"),
    "audit_trail_analyzer_min_completeness_pct": (
        "engines",
        "audit_trail_analyzer_min_completeness_pct",
    ),
    "velocity_throttle_enabled": ("engines", "velocity_throttle_enabled"),
    "velocity_throttle_max_records": ("engines", "velocity_throttle_max_records"),
    "velocity_throttle_max_changes_per_hour": ("engines", "velocity_throttle_max_changes_per_hour"),
    "alert_tuning_feedback_enabled": ("engines", "alert_tuning_feedback_enabled"),
    "alert_tuning_feedback_max_records": ("engines", "alert_tuning_feedback_max_records"),
    "alert_tuning_feedback_precision_threshold": (
        "engines",
        "alert_tuning_feedback_precision_threshold",
    ),
    "knowledge_decay_enabled": ("engines", "knowledge_decay_enabled"),
    "knowledge_decay_max_records": ("engines", "knowledge_decay_max_records"),
    "knowledge_decay_stale_days": ("engines", "knowledge_decay_stale_days"),
    "coverage_scorer_enabled": ("engines", "coverage_scorer_enabled"),
    "coverage_scorer_max_records": ("engines", "coverage_scorer_max_records"),
    "coverage_scorer_min_coverage_pct": ("engines", "coverage_scorer_min_coverage_pct"),
    "cardinality_manager_enabled": ("engines", "cardinality_manager_enabled"),
    "cardinality_manager_max_records": ("engines", "cardinality_manager_max_records"),
    "cardinality_manager_max_cardinality_threshold": (
        "engines",
        "cardinality_manager_max_cardinality_threshold",
    ),
    "log_retention_optimizer_enabled": ("engines", "log_retention_optimizer_enabled"),
    "log_retention_optimizer_max_records": ("engines", "log_retention_optimizer_max_records"),
    "log_retention_optimizer_default_retention_days": (
        "engines",
        "log_retention_optimizer_default_retention_days",
    ),
    "dashboard_quality_enabled": ("engines", "dashboard_quality_enabled"),
    "dashboard_quality_max_records": ("engines", "dashboard_quality_max_records"),
    "dashboard_quality_min_quality_score": ("engines", "dashboard_quality_min_quality_score"),
    "action_tracker_enabled": ("engines", "action_tracker_enabled"),
    "action_tracker_max_records": ("engines", "action_tracker_max_records"),
    "action_tracker_overdue_threshold_days": ("engines", "action_tracker_overdue_threshold_days"),
    "deployment_confidence_enabled": ("engines", "deployment_confidence_enabled"),
    "deployment_confidence_max_records": ("engines", "deployment_confidence_max_records"),
    "deployment_confidence_min_confidence_score": (
        "engines",
        "deployment_confidence_min_confidence_score",
    ),
    "reliability_regression_enabled": ("engines", "reliability_regression_enabled"),
    "reliability_regression_max_records": ("engines", "reliability_regression_max_records"),
    "reliability_regression_deviation_threshold_pct": (
        "engines",
        "reliability_regression_deviation_threshold_pct",
    ),
    "permission_drift_enabled": ("engines", "permission_drift_enabled"),
    "permission_drift_max_records": ("engines", "permission_drift_max_records"),
    "permission_drift_unused_days_threshold": ("engines", "permission_drift_unused_days_threshold"),
    "flag_lifecycle_enabled": ("engines", "flag_lifecycle_enabled"),
    "flag_lifecycle_max_records": ("engines", "flag_lifecycle_max_records"),
    "flag_lifecycle_stale_days_threshold": ("engines", "flag_lifecycle_stale_days_threshold"),
    "api_version_health_enabled": ("engines", "api_version_health_enabled"),
    "api_version_health_max_records": ("engines", "api_version_health_max_records"),
    "api_version_health_sunset_warning_days": ("engines", "api_version_health_sunset_warning_days"),
    "sre_maturity_enabled": ("engines", "sre_maturity_enabled"),
    "sre_maturity_max_records": ("engines", "sre_maturity_max_records"),
    "sre_maturity_target_maturity_score": ("engines", "sre_maturity_target_maturity_score"),
    "learning_tracker_enabled": ("engines", "learning_tracker_enabled"),
    "learning_tracker_max_records": ("engines", "learning_tracker_max_records"),
    "learning_tracker_min_adoption_rate_pct": ("engines", "learning_tracker_min_adoption_rate_pct"),
    "cache_effectiveness_enabled": ("engines", "cache_effectiveness_enabled"),
    "cache_effectiveness_max_records": ("engines", "cache_effectiveness_max_records"),
    "cache_effectiveness_min_hit_rate_pct": ("engines", "cache_effectiveness_min_hit_rate_pct"),
    "build_pipeline_enabled": ("engines", "build_pipeline_enabled"),
    "build_pipeline_max_records": ("engines", "build_pipeline_max_records"),
    "build_pipeline_min_success_rate_pct": ("engines", "build_pipeline_min_success_rate_pct"),
    "review_velocity_enabled": ("engines", "review_velocity_enabled"),
    "review_velocity_max_records": ("engines", "review_velocity_max_records"),
    "review_velocity_max_cycle_hours": ("engines", "review_velocity_max_cycle_hours"),
    "dev_environment_enabled": ("engines", "dev_environment_enabled"),
    "dev_environment_max_records": ("engines", "dev_environment_max_records"),
    "dev_environment_max_drift_days": ("engines", "dev_environment_max_drift_days"),
    "traffic_pattern_enabled": ("engines", "traffic_pattern_enabled"),
    "traffic_pattern_max_records": ("engines", "traffic_pattern_max_records"),
    "traffic_pattern_error_threshold_pct": ("engines", "traffic_pattern_error_threshold_pct"),
    "rate_limit_policy_enabled": ("engines", "rate_limit_policy_enabled"),
    "rate_limit_policy_max_records": ("engines", "rate_limit_policy_max_records"),
    "rate_limit_policy_violation_threshold": ("engines", "rate_limit_policy_violation_threshold"),
    "circuit_breaker_health_enabled": ("engines", "circuit_breaker_health_enabled"),
    "circuit_breaker_health_max_records": ("engines", "circuit_breaker_health_max_records"),
    "circuit_breaker_health_max_trip_count_24h": (
        "engines",
        "circuit_breaker_health_max_trip_count_24h",
    ),
    "data_pipeline_enabled": ("engines", "data_pipeline_enabled"),
    "data_pipeline_max_records": ("engines", "data_pipeline_max_records"),
    "data_pipeline_freshness_threshold_seconds": (
        "engines",
        "data_pipeline_freshness_threshold_seconds",
    ),
    "queue_depth_forecast_enabled": ("engines", "queue_depth_forecast_enabled"),
    "queue_depth_forecast_max_records": ("engines", "queue_depth_forecast_max_records"),
    "queue_depth_forecast_overflow_threshold": (
        "engines",
        "queue_depth_forecast_overflow_threshold",
    ),
    "connection_pool_enabled": ("engines", "connection_pool_enabled"),
    "connection_pool_max_records": ("engines", "connection_pool_max_records"),
    "connection_pool_saturation_threshold_pct": (
        "engines",
        "connection_pool_saturation_threshold_pct",
    ),
    "license_risk_enabled": ("engines", "license_risk_enabled"),
    "license_risk_max_records": ("engines", "license_risk_max_records"),
    "license_risk_max_transitive_depth": ("engines", "license_risk_max_transitive_depth"),
    "comm_effectiveness_enabled": ("engines", "comm_effectiveness_enabled"),
    "comm_effectiveness_max_records": ("engines", "comm_effectiveness_max_records"),
    "comm_effectiveness_min_delivery_rate_pct": (
        "engines",
        "comm_effectiveness_min_delivery_rate_pct",
    ),
    "readiness_scorer_enabled": ("engines", "readiness_scorer_enabled"),
    "readiness_scorer_max_records": ("engines", "readiness_scorer_max_records"),
    "readiness_scorer_min_readiness_score": ("engines", "readiness_scorer_min_readiness_score"),
    "auto_triage_enabled": ("engines", "auto_triage_enabled"),
    "auto_triage_max_records": ("engines", "auto_triage_max_records"),
    "auto_triage_min_confidence_pct": ("engines", "auto_triage_min_confidence_pct"),
    "self_healing_enabled": ("engines", "self_healing_enabled"),
    "self_healing_max_records": ("engines", "self_healing_max_records"),
    "self_healing_min_success_rate_pct": ("engines", "self_healing_min_success_rate_pct"),
    "recurrence_pattern_enabled": ("engines", "recurrence_pattern_enabled"),
    "recurrence_pattern_max_records": ("engines", "recurrence_pattern_max_records"),
    "recurrence_pattern_min_incidents": ("engines", "recurrence_pattern_min_incidents"),
    "policy_impact_enabled": ("engines", "policy_impact_enabled"),
    "policy_impact_max_records": ("engines", "policy_impact_max_records"),
    "policy_impact_max_conflict_count": ("engines", "policy_impact_max_conflict_count"),
    "audit_intelligence_enabled": ("engines", "audit_intelligence_enabled"),
    "audit_intelligence_max_records": ("engines", "audit_intelligence_max_records"),
    "audit_intelligence_anomaly_threshold_pct": (
        "engines",
        "audit_intelligence_anomaly_threshold_pct",
    ),
    "automation_gap_enabled": ("engines", "automation_gap_enabled"),
    "automation_gap_max_records": ("engines", "automation_gap_max_records"),
    "automation_gap_min_roi_score": ("engines", "automation_gap_min_roi_score"),
    "capacity_demand_enabled": ("engines", "capacity_demand_enabled"),
    "capacity_demand_max_records": ("engines", "capacity_demand_max_records"),
    "capacity_demand_deficit_threshold_pct": ("engines", "capacity_demand_deficit_threshold_pct"),
    "spot_advisor_enabled": ("engines", "spot_advisor_enabled"),
    "spot_advisor_max_records": ("engines", "spot_advisor_max_records"),
    "spot_advisor_min_savings_pct": ("engines", "spot_advisor_min_savings_pct"),
    "scaling_efficiency_enabled": ("engines", "scaling_efficiency_enabled"),
    "scaling_efficiency_max_records": ("engines", "scaling_efficiency_max_records"),
    "scaling_efficiency_max_duration_seconds": (
        "engines",
        "scaling_efficiency_max_duration_seconds",
    ),
    "reliability_antipattern_enabled": ("engines", "reliability_antipattern_enabled"),
    "reliability_antipattern_max_records": ("engines", "reliability_antipattern_max_records"),
    "reliability_antipattern_max_accepted_risks": (
        "engines",
        "reliability_antipattern_max_accepted_risks",
    ),
    "error_budget_forecast_enabled": ("engines", "error_budget_forecast_enabled"),
    "error_budget_forecast_max_records": ("engines", "error_budget_forecast_max_records"),
    "error_budget_forecast_risk_threshold_pct": (
        "engines",
        "error_budget_forecast_risk_threshold_pct",
    ),
    "dependency_risk_enabled": ("engines", "dependency_risk_enabled"),
    "dependency_risk_max_records": ("engines", "dependency_risk_max_records"),
    "dependency_risk_critical_threshold": ("engines", "dependency_risk_critical_threshold"),
    "incident_similarity_enabled": ("engines", "incident_similarity_enabled"),
    "incident_similarity_max_records": ("engines", "incident_similarity_max_records"),
    "incident_similarity_min_confidence_pct": ("engines", "incident_similarity_min_confidence_pct"),
    "incident_cost_enabled": ("engines", "incident_cost_enabled"),
    "incident_cost_max_records": ("engines", "incident_cost_max_records"),
    "incident_cost_high_threshold": ("engines", "incident_cost_high_threshold"),
    "followup_tracker_enabled": ("engines", "followup_tracker_enabled"),
    "followup_tracker_max_records": ("engines", "followup_tracker_max_records"),
    "followup_tracker_overdue_days": ("engines", "followup_tracker_overdue_days"),
    "cognitive_load_enabled": ("engines", "cognitive_load_enabled"),
    "cognitive_load_max_records": ("engines", "cognitive_load_max_records"),
    "cognitive_load_critical_threshold": ("engines", "cognitive_load_critical_threshold"),
    "collaboration_scorer_enabled": ("engines", "collaboration_scorer_enabled"),
    "collaboration_scorer_max_records": ("engines", "collaboration_scorer_max_records"),
    "collaboration_scorer_min_score": ("engines", "collaboration_scorer_min_score"),
    "contribution_tracker_enabled": ("engines", "contribution_tracker_enabled"),
    "contribution_tracker_max_records": ("engines", "contribution_tracker_max_records"),
    "contribution_tracker_min_quality_score": ("engines", "contribution_tracker_min_quality_score"),
    "api_performance_enabled": ("engines", "api_performance_enabled"),
    "api_performance_max_records": ("engines", "api_performance_max_records"),
    "api_performance_slow_threshold_ms": ("engines", "api_performance_slow_threshold_ms"),
    "resource_contention_enabled": ("engines", "resource_contention_enabled"),
    "resource_contention_max_records": ("engines", "resource_contention_max_records"),
    "resource_contention_critical_threshold_pct": (
        "engines",
        "resource_contention_critical_threshold_pct",
    ),
    "rollback_analyzer_enabled": ("engines", "rollback_analyzer_enabled"),
    "rollback_analyzer_max_records": ("engines", "rollback_analyzer_max_records"),
    "rollback_analyzer_max_rate_pct": ("engines", "rollback_analyzer_max_rate_pct"),
    "attack_surface_enabled": ("engines", "attack_surface_enabled"),
    "attack_surface_max_records": ("engines", "attack_surface_max_records"),
    "attack_surface_max_critical_exposures": ("engines", "attack_surface_max_critical_exposures"),
    "runbook_recommendation_enabled": ("engines", "runbook_recommendation_enabled"),
    "runbook_recommendation_max_records": ("engines", "runbook_recommendation_max_records"),
    "runbook_recommendation_min_confidence_pct": (
        "engines",
        "runbook_recommendation_min_confidence_pct",
    ),
    "reliability_scorecard_enabled": ("engines", "reliability_scorecard_enabled"),
    "reliability_scorecard_max_records": ("engines", "reliability_scorecard_max_records"),
    "reliability_scorecard_min_grade_score": ("engines", "reliability_scorecard_min_grade_score"),
    "llm_cost_tracker_enabled": ("engines", "llm_cost_tracker_enabled"),
    "llm_cost_tracker_max_records": ("engines", "llm_cost_tracker_max_records"),
    "llm_cost_tracker_high_cost_threshold": ("engines", "llm_cost_tracker_high_cost_threshold"),
    "cloud_arbitrage_enabled": ("engines", "cloud_arbitrage_enabled"),
    "cloud_arbitrage_max_records": ("engines", "cloud_arbitrage_max_records"),
    "cloud_arbitrage_min_savings_pct": ("engines", "cloud_arbitrage_min_savings_pct"),
    "observability_cost_enabled": ("engines", "observability_cost_enabled"),
    "observability_cost_max_records": ("engines", "observability_cost_max_records"),
    "observability_cost_high_cost_threshold": ("engines", "observability_cost_high_cost_threshold"),
    "lead_time_analyzer_enabled": ("engines", "lead_time_analyzer_enabled"),
    "lead_time_analyzer_max_records": ("engines", "lead_time_analyzer_max_records"),
    "lead_time_analyzer_max_lead_time_hours": ("engines", "lead_time_analyzer_max_lead_time_hours"),
    "flag_impact_enabled": ("engines", "flag_impact_enabled"),
    "flag_impact_max_records": ("engines", "flag_impact_max_records"),
    "flag_impact_min_reliability_pct": ("engines", "flag_impact_min_reliability_pct"),
    "deployment_dependency_enabled": ("engines", "deployment_dependency_enabled"),
    "deployment_dependency_max_records": ("engines", "deployment_dependency_max_records"),
    "deployment_dependency_max_depth": ("engines", "deployment_dependency_max_depth"),
    "postmortem_quality_enabled": ("engines", "postmortem_quality_enabled"),
    "postmortem_quality_max_records": ("engines", "postmortem_quality_max_records"),
    "postmortem_quality_min_score": ("engines", "postmortem_quality_min_score"),
    "dr_drill_tracker_enabled": ("engines", "dr_drill_tracker_enabled"),
    "dr_drill_tracker_max_records": ("engines", "dr_drill_tracker_max_records"),
    "dr_drill_tracker_min_success_rate_pct": ("engines", "dr_drill_tracker_min_success_rate_pct"),
    "escalation_optimizer_enabled": ("engines", "escalation_optimizer_enabled"),
    "escalation_optimizer_max_records": ("engines", "escalation_optimizer_max_records"),
    "escalation_optimizer_max_escalation_time_min": (
        "engines",
        "escalation_optimizer_max_escalation_time_min",
    ),
    "tenant_quota_enabled": ("engines", "tenant_quota_enabled"),
    "tenant_quota_max_records": ("engines", "tenant_quota_max_records"),
    "tenant_quota_max_utilization_pct": ("engines", "tenant_quota_max_utilization_pct"),
    "decision_audit_enabled": ("engines", "decision_audit_enabled"),
    "decision_audit_max_records": ("engines", "decision_audit_max_records"),
    "decision_audit_min_confidence_pct": ("engines", "decision_audit_min_confidence_pct"),
    "retention_policy_enabled": ("engines", "retention_policy_enabled"),
    "retention_policy_max_records": ("engines", "retention_policy_max_records"),
    "retention_policy_max_retention_days": ("engines", "retention_policy_max_retention_days"),
    "twilio_sms_enabled": ("engines", "twilio_sms_enabled"),
    "twilio_sms_max_records": ("engines", "twilio_sms_max_records"),
    "twilio_sms_max_retries": ("engines", "twilio_sms_max_retries"),
    "twilio_voice_enabled": ("engines", "twilio_voice_enabled"),
    "twilio_voice_max_records": ("engines", "twilio_voice_max_records"),
    "twilio_voice_max_ring_seconds": ("engines", "twilio_voice_max_ring_seconds"),
    "teams_notifier_enabled": ("engines", "teams_notifier_enabled"),
    "teams_notifier_max_records": ("engines", "teams_notifier_max_records"),
    "teams_notifier_max_retries": ("engines", "teams_notifier_max_retries"),
    "swarm_coordinator_enabled": ("engines", "swarm_coordinator_enabled"),
    "swarm_coordinator_max_records": ("engines", "swarm_coordinator_max_records"),
    "swarm_coordinator_max_agents": ("engines", "swarm_coordinator_max_agents"),
    "consensus_engine_enabled": ("engines", "consensus_engine_enabled"),
    "consensus_engine_max_records": ("engines", "consensus_engine_max_records"),
    "consensus_engine_quorum_pct": ("engines", "consensus_engine_quorum_pct"),
    "knowledge_mesh_enabled": ("engines", "knowledge_mesh_enabled"),
    "knowledge_mesh_max_records": ("engines", "knowledge_mesh_max_records"),
    "knowledge_mesh_ttl_seconds": ("engines", "knowledge_mesh_ttl_seconds"),
    "risk_aggregator_enabled": ("engines", "risk_aggregator_enabled"),
    "risk_aggregator_max_records": ("engines", "risk_aggregator_max_records"),
    "risk_aggregator_critical_threshold": ("engines", "risk_aggregator_critical_threshold"),
    "dynamic_risk_scorer_enabled": ("engines", "dynamic_risk_scorer_enabled"),
    "dynamic_risk_scorer_max_records": ("engines", "dynamic_risk_scorer_max_records"),
    "dynamic_risk_scorer_high_threshold": ("engines", "dynamic_risk_scorer_high_threshold"),
    "predictive_alert_enabled": ("engines", "predictive_alert_enabled"),
    "predictive_alert_max_records": ("engines", "predictive_alert_max_records"),
    "predictive_alert_min_confidence_pct": ("engines", "predictive_alert_min_confidence_pct"),
    "token_optimizer_enabled": ("engines", "token_optimizer_enabled"),
    "token_optimizer_max_records": ("engines", "token_optimizer_max_records"),
    "token_optimizer_target_savings_pct": ("engines", "token_optimizer_target_savings_pct"),
    "prompt_cache_enabled": ("engines", "prompt_cache_enabled"),
    "prompt_cache_max_records": ("engines", "prompt_cache_max_records"),
    "prompt_cache_ttl_seconds": ("engines", "prompt_cache_ttl_seconds"),
    "routing_optimizer_enabled": ("engines", "routing_optimizer_enabled"),
    "routing_optimizer_max_records": ("engines", "routing_optimizer_max_records"),
    "routing_optimizer_cost_limit": ("engines", "routing_optimizer_cost_limit"),
    "threat_hunt_enabled": ("engines", "threat_hunt_enabled"),
    "threat_hunt_max_records": ("engines", "threat_hunt_max_records"),
    "threat_hunt_min_detection_rate_pct": ("engines", "threat_hunt_min_detection_rate_pct"),
    "response_automator_enabled": ("engines", "response_automator_enabled"),
    "response_automator_max_records": ("engines", "response_automator_max_records"),
    "response_automator_min_success_rate_pct": (
        "engines",
        "response_automator_min_success_rate_pct",
    ),
    "zero_trust_enabled": ("engines", "zero_trust_enabled"),
    "zero_trust_max_records": ("engines", "zero_trust_max_records"),
    "zero_trust_min_trust_score": ("engines", "zero_trust_min_trust_score"),
    "remediation_pipeline_enabled": ("engines", "remediation_pipeline_enabled"),
    "remediation_pipeline_max_records": ("engines", "remediation_pipeline_max_records"),
    "remediation_pipeline_max_step_count": ("engines", "remediation_pipeline_max_step_count"),
    "recovery_coordinator_enabled": ("engines", "recovery_coordinator_enabled"),
    "recovery_coordinator_max_records": ("engines", "recovery_coordinator_max_records"),
    "recovery_coordinator_max_recovery_hours": (
        "engines",
        "recovery_coordinator_max_recovery_hours",
    ),
    "runbook_chainer_enabled": ("engines", "runbook_chainer_enabled"),
    "runbook_chainer_max_records": ("engines", "runbook_chainer_max_records"),
    "runbook_chainer_max_chain_length": ("engines", "runbook_chainer_max_chain_length"),
    "slo_auto_scaler_enabled": ("engines", "slo_auto_scaler_enabled"),
    "slo_auto_scaler_max_records": ("engines", "slo_auto_scaler_max_records"),
    "slo_auto_scaler_max_replica_delta": ("engines", "slo_auto_scaler_max_replica_delta"),
    "reliability_automator_enabled": ("engines", "reliability_automator_enabled"),
    "reliability_automator_max_records": ("engines", "reliability_automator_max_records"),
    "reliability_automator_min_impact_score": ("engines", "reliability_automator_min_impact_score"),
    "prevention_engine_enabled": ("engines", "prevention_engine_enabled"),
    "prevention_engine_max_records": ("engines", "prevention_engine_max_records"),
    "prevention_engine_min_confidence_pct": ("engines", "prevention_engine_min_confidence_pct"),
    "cross_agent_enforcer_enabled": ("engines", "cross_agent_enforcer_enabled"),
    "cross_agent_enforcer_max_records": ("engines", "cross_agent_enforcer_max_records"),
    "cross_agent_enforcer_max_violations": ("engines", "cross_agent_enforcer_max_violations"),
    "telemetry_analyzer_enabled": ("engines", "telemetry_analyzer_enabled"),
    "telemetry_analyzer_max_records": ("engines", "telemetry_analyzer_max_records"),
    "telemetry_analyzer_min_performance_pct": ("engines", "telemetry_analyzer_min_performance_pct"),
    "compliance_auditor_enabled": ("engines", "compliance_auditor_enabled"),
    "compliance_auditor_max_records": ("engines", "compliance_auditor_max_records"),
    "compliance_auditor_min_pass_rate_pct": ("engines", "compliance_auditor_min_pass_rate_pct"),
    "war_room_orchestrator_enabled": ("engines", "war_room_orchestrator_enabled"),
    "war_room_orchestrator_max_records": ("engines", "war_room_orchestrator_max_records"),
    "war_room_orchestrator_min_resolution_rate_pct": (
        "engines",
        "war_room_orchestrator_min_resolution_rate_pct",
    ),
    "root_cause_verifier_enabled": ("engines", "root_cause_verifier_enabled"),
    "root_cause_verifier_max_records": ("engines", "root_cause_verifier_max_records"),
    "root_cause_verifier_min_confidence_pct": ("engines", "root_cause_verifier_min_confidence_pct"),
    "comm_automator_enabled": ("engines", "comm_automator_enabled"),
    "comm_automator_max_records": ("engines", "comm_automator_max_records"),
    "comm_automator_min_delivery_rate_pct": ("engines", "comm_automator_min_delivery_rate_pct"),
    "posture_simulator_enabled": ("engines", "posture_simulator_enabled"),
    "posture_simulator_max_records": ("engines", "posture_simulator_max_records"),
    "posture_simulator_min_blocked_rate_pct": ("engines", "posture_simulator_min_blocked_rate_pct"),
    "credential_rotator_enabled": ("engines", "credential_rotator_enabled"),
    "credential_rotator_max_records": ("engines", "credential_rotator_max_records"),
    "credential_rotator_min_completion_rate_pct": (
        "engines",
        "credential_rotator_min_completion_rate_pct",
    ),
    "evidence_automator_enabled": ("engines", "evidence_automator_enabled"),
    "evidence_automator_max_records": ("engines", "evidence_automator_max_records"),
    "evidence_automator_min_freshness_pct": ("engines", "evidence_automator_min_freshness_pct"),
    "chaos_automator_enabled": ("engines", "chaos_automator_enabled"),
    "chaos_automator_max_records": ("engines", "chaos_automator_max_records"),
    "chaos_automator_min_pass_rate_pct": ("engines", "chaos_automator_min_pass_rate_pct"),
    "failover_coordinator_enabled": ("engines", "failover_coordinator_enabled"),
    "failover_coordinator_max_records": ("engines", "failover_coordinator_max_records"),
    "failover_coordinator_max_rto_seconds": ("engines", "failover_coordinator_max_rto_seconds"),
    "burst_manager_enabled": ("engines", "burst_manager_enabled"),
    "burst_manager_max_records": ("engines", "burst_manager_max_records"),
    "burst_manager_max_burst_budget": ("engines", "burst_manager_max_burst_budget"),
    "platform_cost_enabled": ("engines", "platform_cost_enabled"),
    "platform_cost_max_records": ("engines", "platform_cost_max_records"),
    "platform_cost_min_savings_threshold": ("engines", "platform_cost_min_savings_threshold"),
    "service_mesh_intel_enabled": ("engines", "service_mesh_intel_enabled"),
    "service_mesh_intel_max_records": ("engines", "service_mesh_intel_max_records"),
    "service_mesh_intel_max_latency_ms": ("engines", "service_mesh_intel_max_latency_ms"),
    "runbook_generator_enabled": ("engines", "runbook_generator_enabled"),
    "runbook_generator_max_records": ("engines", "runbook_generator_max_records"),
    "runbook_generator_min_accuracy_pct": ("engines", "runbook_generator_min_accuracy_pct"),
    "breach_predictor_enabled": ("engines", "breach_predictor_enabled"),
    "breach_predictor_max_records": ("engines", "breach_predictor_max_records"),
    "breach_predictor_min_confidence_pct": ("engines", "breach_predictor_min_confidence_pct"),
    "error_budget_allocator_enabled": ("engines", "error_budget_allocator_enabled"),
    "error_budget_allocator_max_records": ("engines", "error_budget_allocator_max_records"),
    "error_budget_allocator_min_healthy_rate_pct": (
        "engines",
        "error_budget_allocator_min_healthy_rate_pct",
    ),
    "dependency_topology_enabled": ("engines", "dependency_topology_enabled"),
    "dependency_topology_max_records": ("engines", "dependency_topology_max_records"),
    "dependency_topology_max_coupling_depth": ("engines", "dependency_topology_max_coupling_depth"),
    "infra_capacity_planner_enabled": ("engines", "infra_capacity_planner_enabled"),
    "infra_capacity_planner_max_records": ("engines", "infra_capacity_planner_max_records"),
    "infra_capacity_planner_target_utilization_pct": (
        "engines",
        "infra_capacity_planner_target_utilization_pct",
    ),
    "dns_health_monitor_enabled": ("engines", "dns_health_monitor_enabled"),
    "dns_health_monitor_max_records": ("engines", "dns_health_monitor_max_records"),
    "dns_health_monitor_max_resolution_ms": ("engines", "dns_health_monitor_max_resolution_ms"),
    "drift_analyzer_enabled": ("engines", "drift_analyzer_enabled"),
    "drift_analyzer_max_records": ("engines", "drift_analyzer_max_records"),
    "drift_analyzer_max_deviation_pct": ("engines", "drift_analyzer_max_deviation_pct"),
    "timeline_correlator_enabled": ("engines", "timeline_correlator_enabled"),
    "timeline_correlator_max_records": ("engines", "timeline_correlator_max_records"),
    "timeline_correlator_min_confidence_pct": ("engines", "timeline_correlator_min_confidence_pct"),
    "deployment_impact_enabled": ("engines", "deployment_impact_enabled"),
    "deployment_impact_max_records": ("engines", "deployment_impact_max_records"),
    "deployment_impact_max_impact_score": ("engines", "deployment_impact_max_impact_score"),
    "alert_routing_optimizer_enabled": ("engines", "alert_routing_optimizer_enabled"),
    "alert_routing_optimizer_max_records": ("engines", "alert_routing_optimizer_max_records"),
    "alert_routing_optimizer_max_response_seconds": (
        "engines",
        "alert_routing_optimizer_max_response_seconds",
    ),
    "compliance_posture_enabled": ("engines", "compliance_posture_enabled"),
    "compliance_posture_max_records": ("engines", "compliance_posture_max_records"),
    "compliance_posture_min_score_pct": ("engines", "compliance_posture_min_score_pct"),
    "toil_quantifier_enabled": ("engines", "toil_quantifier_enabled"),
    "toil_quantifier_max_records": ("engines", "toil_quantifier_max_records"),
    "toil_quantifier_max_toil_hours_weekly": ("engines", "toil_quantifier_max_toil_hours_weekly"),
    "governance_dashboard_enabled": ("engines", "governance_dashboard_enabled"),
    "governance_dashboard_max_records": ("engines", "governance_dashboard_max_records"),
    "governance_dashboard_min_governance_score_pct": (
        "engines",
        "governance_dashboard_min_governance_score_pct",
    ),
    "incident_replay_enabled": ("engines", "incident_replay_enabled"),
    "incident_replay_max_records": ("engines", "incident_replay_max_records"),
    "incident_replay_min_effectiveness_pct": ("engines", "incident_replay_min_effectiveness_pct"),
    "response_timer_enabled": ("engines", "response_timer_enabled"),
    "response_timer_max_records": ("engines", "response_timer_max_records"),
    "response_timer_target_minutes": ("engines", "response_timer_target_minutes"),
    "slo_aggregator_enabled": ("engines", "slo_aggregator_enabled"),
    "slo_aggregator_max_records": ("engines", "slo_aggregator_max_records"),
    "slo_aggregator_min_compliance_pct": ("engines", "slo_aggregator_min_compliance_pct"),
    "network_latency_enabled": ("engines", "network_latency_enabled"),
    "network_latency_max_records": ("engines", "network_latency_max_records"),
    "network_latency_max_acceptable_ms": ("engines", "network_latency_max_acceptable_ms"),
    "health_index_enabled": ("engines", "health_index_enabled"),
    "health_index_max_records": ("engines", "health_index_max_records"),
    "health_index_min_score_pct": ("engines", "health_index_min_score_pct"),
    "observability_gap_enabled": ("engines", "observability_gap_enabled"),
    "observability_gap_max_records": ("engines", "observability_gap_max_records"),
    "observability_gap_min_coverage_pct": ("engines", "observability_gap_min_coverage_pct"),
    "capacity_anomaly_enabled": ("engines", "capacity_anomaly_enabled"),
    "capacity_anomaly_max_records": ("engines", "capacity_anomaly_max_records"),
    "capacity_anomaly_min_confidence_pct": ("engines", "capacity_anomaly_min_confidence_pct"),
    "change_freeze_enabled": ("engines", "change_freeze_enabled"),
    "change_freeze_max_records": ("engines", "change_freeze_max_records"),
    "change_freeze_max_exception_rate_pct": ("engines", "change_freeze_max_exception_rate_pct"),
    "pipeline_analyzer_enabled": ("engines", "pipeline_analyzer_enabled"),
    "pipeline_analyzer_max_records": ("engines", "pipeline_analyzer_max_records"),
    "pipeline_analyzer_max_duration_minutes": ("engines", "pipeline_analyzer_max_duration_minutes"),
    "release_readiness_enabled": ("engines", "release_readiness_enabled"),
    "release_readiness_max_records": ("engines", "release_readiness_max_records"),
    "release_readiness_min_score_pct": ("engines", "release_readiness_min_score_pct"),
    "config_validator_enabled": ("engines", "config_validator_enabled"),
    "config_validator_max_records": ("engines", "config_validator_max_records"),
    "config_validator_max_failure_rate_pct": ("engines", "config_validator_max_failure_rate_pct"),
    "ownership_tracker_enabled": ("engines", "ownership_tracker_enabled"),
    "ownership_tracker_max_records": ("engines", "ownership_tracker_max_records"),
    "ownership_tracker_max_orphan_days": ("engines", "ownership_tracker_max_orphan_days"),
    "vendor_lockin_enabled": ("engines", "vendor_lockin_enabled"),
    "vendor_lockin_max_records": ("engines", "vendor_lockin_max_records"),
    "vendor_lockin_max_risk_score": ("engines", "vendor_lockin_max_risk_score"),
    "cost_efficiency_enabled": ("engines", "cost_efficiency_enabled"),
    "cost_efficiency_max_records": ("engines", "cost_efficiency_max_records"),
    "cost_efficiency_min_efficiency_pct": ("engines", "cost_efficiency_min_efficiency_pct"),
    "budget_variance_enabled": ("engines", "budget_variance_enabled"),
    "budget_variance_max_records": ("engines", "budget_variance_max_records"),
    "budget_variance_max_variance_pct": ("engines", "budget_variance_max_variance_pct"),
    "evidence_validator_enabled": ("engines", "evidence_validator_enabled"),
    "evidence_validator_max_records": ("engines", "evidence_validator_max_records"),
    "evidence_validator_min_validity_pct": ("engines", "evidence_validator_min_validity_pct"),
    "policy_enforcer_enabled": ("engines", "policy_enforcer_enabled"),
    "policy_enforcer_max_records": ("engines", "policy_enforcer_max_records"),
    "policy_enforcer_max_violation_rate_pct": ("engines", "policy_enforcer_max_violation_rate_pct"),
    "audit_readiness_enabled": ("engines", "audit_readiness_enabled"),
    "audit_readiness_max_records": ("engines", "audit_readiness_max_records"),
    "audit_readiness_min_readiness_pct": ("engines", "audit_readiness_min_readiness_pct"),
    "toil_classifier_enabled": ("engines", "toil_classifier_enabled"),
    "toil_classifier_max_records": ("engines", "toil_classifier_max_records"),
    "toil_classifier_max_toil_hours_weekly": ("engines", "toil_classifier_max_toil_hours_weekly"),
    "governance_scorer_enabled": ("engines", "governance_scorer_enabled"),
    "governance_scorer_max_records": ("engines", "governance_scorer_max_records"),
    "governance_scorer_min_governance_score": ("engines", "governance_scorer_min_governance_score"),
    "deprecation_tracker_enabled": ("engines", "deprecation_tracker_enabled"),
    "deprecation_tracker_max_records": ("engines", "deprecation_tracker_max_records"),
    "deprecation_tracker_max_overdue_days": ("engines", "deprecation_tracker_max_overdue_days"),
    "severity_validator_enabled": ("engines", "severity_validator_enabled"),
    "severity_validator_max_records": ("engines", "severity_validator_max_records"),
    "severity_validator_min_accuracy_pct": ("engines", "severity_validator_min_accuracy_pct"),
    "approval_analyzer_enabled": ("engines", "approval_analyzer_enabled"),
    "approval_analyzer_max_records": ("engines", "approval_analyzer_max_records"),
    "approval_analyzer_max_approval_hours": ("engines", "approval_analyzer_max_approval_hours"),
    "slo_compliance_enabled": ("engines", "slo_compliance_enabled"),
    "slo_compliance_max_records": ("engines", "slo_compliance_max_records"),
    "slo_compliance_min_compliance_pct": ("engines", "slo_compliance_min_compliance_pct"),
    "alert_dedup_enabled": ("engines", "alert_dedup_enabled"),
    "alert_dedup_max_records": ("engines", "alert_dedup_max_records"),
    "alert_dedup_min_dedup_ratio_pct": ("engines", "alert_dedup_min_dedup_ratio_pct"),
    "priority_ranker_enabled": ("engines", "priority_ranker_enabled"),
    "priority_ranker_max_records": ("engines", "priority_ranker_max_records"),
    "priority_ranker_min_accuracy_pct": ("engines", "priority_ranker_min_accuracy_pct"),
    "deploy_frequency_enabled": ("engines", "deploy_frequency_enabled"),
    "deploy_frequency_max_records": ("engines", "deploy_frequency_max_records"),
    "deploy_frequency_min_deploy_per_week": ("engines", "deploy_frequency_min_deploy_per_week"),
    "infra_cost_allocator_enabled": ("engines", "infra_cost_allocator_enabled"),
    "infra_cost_allocator_max_records": ("engines", "infra_cost_allocator_max_records"),
    "infra_cost_allocator_max_unallocated_pct": (
        "engines",
        "infra_cost_allocator_max_unallocated_pct",
    ),
    "team_velocity_enabled": ("engines", "team_velocity_enabled"),
    "team_velocity_max_records": ("engines", "team_velocity_max_records"),
    "team_velocity_min_velocity_score": ("engines", "team_velocity_min_velocity_score"),
    "comm_mapper_enabled": ("engines", "comm_mapper_enabled"),
    "comm_mapper_max_records": ("engines", "comm_mapper_max_records"),
    "comm_mapper_max_unhealthy_links": ("engines", "comm_mapper_max_unhealthy_links"),
    "automation_scorer_enabled": ("engines", "automation_scorer_enabled"),
    "automation_scorer_max_records": ("engines", "automation_scorer_max_records"),
    "automation_scorer_min_automation_pct": ("engines", "automation_scorer_min_automation_pct"),
    "scaling_advisor_enabled": ("engines", "scaling_advisor_enabled"),
    "scaling_advisor_max_records": ("engines", "scaling_advisor_max_records"),
    "scaling_advisor_min_confidence_pct": ("engines", "scaling_advisor_min_confidence_pct"),
    "error_classifier_enabled": ("engines", "error_classifier_enabled"),
    "error_classifier_max_records": ("engines", "error_classifier_max_records"),
    "error_classifier_max_error_rate_pct": ("engines", "error_classifier_max_error_rate_pct"),
    "compliance_bridge_enabled": ("engines", "compliance_bridge_enabled"),
    "compliance_bridge_max_records": ("engines", "compliance_bridge_max_records"),
    "compliance_bridge_min_alignment_pct": ("engines", "compliance_bridge_min_alignment_pct"),
    "utilization_scorer_enabled": ("engines", "utilization_scorer_enabled"),
    "utilization_scorer_max_records": ("engines", "utilization_scorer_max_records"),
    "utilization_scorer_optimal_utilization_pct": (
        "engines",
        "utilization_scorer_optimal_utilization_pct",
    ),
    "knowledge_linker_enabled": ("engines", "knowledge_linker_enabled"),
    "knowledge_linker_max_records": ("engines", "knowledge_linker_max_records"),
    "knowledge_linker_min_relevance_pct": ("engines", "knowledge_linker_min_relevance_pct"),
    "dep_vuln_mapper_enabled": ("engines", "dep_vuln_mapper_enabled"),
    "dep_vuln_mapper_max_records": ("engines", "dep_vuln_mapper_max_records"),
    "dep_vuln_mapper_max_critical_vulns": ("engines", "dep_vuln_mapper_max_critical_vulns"),
    "trend_forecaster_enabled": ("engines", "trend_forecaster_enabled"),
    "trend_forecaster_max_records": ("engines", "trend_forecaster_max_records"),
    "trend_forecaster_max_growth_rate_pct": ("engines", "trend_forecaster_max_growth_rate_pct"),
    "risk_predictor_enabled": ("engines", "risk_predictor_enabled"),
    "risk_predictor_max_records": ("engines", "risk_predictor_max_records"),
    "risk_predictor_max_risk_threshold": ("engines", "risk_predictor_max_risk_threshold"),
    "optimization_planner_enabled": ("engines", "optimization_planner_enabled"),
    "optimization_planner_max_records": ("engines", "optimization_planner_max_records"),
    "optimization_planner_min_savings_pct": ("engines", "optimization_planner_min_savings_pct"),
    "noise_classifier_enabled": ("engines", "noise_classifier_enabled"),
    "noise_classifier_max_records": ("engines", "noise_classifier_max_records"),
    "noise_classifier_max_noise_ratio_pct": ("engines", "noise_classifier_max_noise_ratio_pct"),
    "sla_impact_analyzer_enabled": ("engines", "sla_impact_analyzer_enabled"),
    "sla_impact_analyzer_max_records": ("engines", "sla_impact_analyzer_max_records"),
    "sla_impact_analyzer_max_breach_count": ("engines", "sla_impact_analyzer_max_breach_count"),
    "runbook_coverage_enabled": ("engines", "runbook_coverage_enabled"),
    "runbook_coverage_max_records": ("engines", "runbook_coverage_max_records"),
    "runbook_coverage_min_coverage_pct": ("engines", "runbook_coverage_min_coverage_pct"),
    "posture_benchmark_enabled": ("engines", "posture_benchmark_enabled"),
    "posture_benchmark_max_records": ("engines", "posture_benchmark_max_records"),
    "posture_benchmark_min_benchmark_score": ("engines", "posture_benchmark_min_benchmark_score"),
    "workload_balancer_enabled": ("engines", "workload_balancer_enabled"),
    "workload_balancer_max_records": ("engines", "workload_balancer_max_records"),
    "workload_balancer_max_imbalance_pct": ("engines", "workload_balancer_max_imbalance_pct"),
    "report_automator_enabled": ("engines", "report_automator_enabled"),
    "report_automator_max_records": ("engines", "report_automator_max_records"),
    "report_automator_max_overdue_days": ("engines", "report_automator_max_overdue_days"),
    "infra_health_scorer_enabled": ("engines", "infra_health_scorer_enabled"),
    "infra_health_scorer_max_records": ("engines", "infra_health_scorer_max_records"),
    "infra_health_scorer_min_health_score": ("engines", "infra_health_scorer_min_health_score"),
    "impact_predictor_enabled": ("engines", "impact_predictor_enabled"),
    "impact_predictor_max_records": ("engines", "impact_predictor_max_records"),
    "impact_predictor_max_impact_score": ("engines", "impact_predictor_max_impact_score"),
    "response_time_enabled": ("engines", "response_time_enabled"),
    "response_time_max_records": ("engines", "response_time_max_records"),
    "response_time_max_response_time_minutes": (
        "engines",
        "response_time_max_response_time_minutes",
    ),
    "service_dep_risk_enabled": ("engines", "service_dep_risk_enabled"),
    "service_dep_risk_max_records": ("engines", "service_dep_risk_max_records"),
    "service_dep_risk_max_risk_score": ("engines", "service_dep_risk_max_risk_score"),
    "alert_escalation_enabled": ("engines", "alert_escalation_enabled"),
    "alert_escalation_max_records": ("engines", "alert_escalation_max_records"),
    "alert_escalation_max_escalation_rate_pct": (
        "engines",
        "alert_escalation_max_escalation_rate_pct",
    ),
    "capacity_utilizer_enabled": ("engines", "capacity_utilizer_enabled"),
    "capacity_utilizer_max_records": ("engines", "capacity_utilizer_max_records"),
    "capacity_utilizer_optimal_utilization_pct": (
        "engines",
        "capacity_utilizer_optimal_utilization_pct",
    ),
    "freeze_validator_enabled": ("engines", "freeze_validator_enabled"),
    "freeze_validator_max_records": ("engines", "freeze_validator_max_records"),
    "freeze_validator_max_violation_rate_pct": (
        "engines",
        "freeze_validator_max_violation_rate_pct",
    ),
    "availability_tracker_enabled": ("engines", "availability_tracker_enabled"),
    "availability_tracker_max_records": ("engines", "availability_tracker_max_records"),
    "availability_tracker_min_availability_pct": (
        "engines",
        "availability_tracker_min_availability_pct",
    ),
    "root_cause_classifier_enabled": ("engines", "root_cause_classifier_enabled"),
    "root_cause_classifier_max_records": ("engines", "root_cause_classifier_max_records"),
    "root_cause_classifier_min_confidence_pct": (
        "engines",
        "root_cause_classifier_min_confidence_pct",
    ),
    "canary_scorer_enabled": ("engines", "canary_scorer_enabled"),
    "canary_scorer_max_records": ("engines", "canary_scorer_max_records"),
    "canary_scorer_min_canary_score": ("engines", "canary_scorer_min_canary_score"),
    "config_drift_monitor_enabled": ("engines", "config_drift_monitor_enabled"),
    "config_drift_monitor_max_records": ("engines", "config_drift_monitor_max_records"),
    "config_drift_monitor_max_drift_count": ("engines", "config_drift_monitor_max_drift_count"),
    "compliance_mapper_enabled": ("engines", "compliance_mapper_enabled"),
    "compliance_mapper_max_records": ("engines", "compliance_mapper_max_records"),
    "compliance_mapper_min_compliance_score": ("engines", "compliance_mapper_min_compliance_score"),
    "oncall_equity_enabled": ("engines", "oncall_equity_enabled"),
    "oncall_equity_max_records": ("engines", "oncall_equity_max_records"),
    "oncall_equity_max_inequity_pct": ("engines", "oncall_equity_max_inequity_pct"),
    "incident_cluster_enabled": ("engines", "incident_cluster_enabled"),
    "incident_cluster_max_records": ("engines", "incident_cluster_max_records"),
    "incident_cluster_min_cluster_confidence": (
        "engines",
        "incident_cluster_min_cluster_confidence",
    ),
    "dep_latency_enabled": ("engines", "dep_latency_enabled"),
    "dep_latency_max_records": ("engines", "dep_latency_max_records"),
    "dep_latency_max_latency_ms": ("engines", "dep_latency_max_latency_ms"),
    "suppression_mgr_enabled": ("engines", "suppression_mgr_enabled"),
    "suppression_mgr_max_records": ("engines", "suppression_mgr_max_records"),
    "suppression_mgr_max_suppression_rate_pct": (
        "engines",
        "suppression_mgr_max_suppression_rate_pct",
    ),
    "cost_trend_enabled": ("engines", "cost_trend_enabled"),
    "cost_trend_max_records": ("engines", "cost_trend_max_records"),
    "cost_trend_max_growth_rate_pct": ("engines", "cost_trend_max_growth_rate_pct"),
    "batch_analyzer_enabled": ("engines", "batch_analyzer_enabled"),
    "batch_analyzer_max_records": ("engines", "batch_analyzer_max_records"),
    "batch_analyzer_max_batch_risk_score": ("engines", "batch_analyzer_max_batch_risk_score"),
    "slo_alignment_enabled": ("engines", "slo_alignment_enabled"),
    "slo_alignment_max_records": ("engines", "slo_alignment_max_records"),
    "slo_alignment_min_alignment_score": ("engines", "slo_alignment_min_alignment_score"),
    "runbook_exec_tracker_enabled": ("engines", "runbook_exec_tracker_enabled"),
    "runbook_exec_tracker_max_records": ("engines", "runbook_exec_tracker_max_records"),
    "runbook_exec_tracker_min_success_rate_pct": (
        "engines",
        "runbook_exec_tracker_min_success_rate_pct",
    ),
    "threat_correlator_enabled": ("engines", "threat_correlator_enabled"),
    "threat_correlator_max_records": ("engines", "threat_correlator_max_records"),
    "threat_correlator_min_relevance_score": ("engines", "threat_correlator_min_relevance_score"),
    "freshness_monitor_enabled": ("engines", "freshness_monitor_enabled"),
    "freshness_monitor_max_records": ("engines", "freshness_monitor_max_records"),
    "freshness_monitor_max_stale_days": ("engines", "freshness_monitor_max_stale_days"),
    "control_tester_enabled": ("engines", "control_tester_enabled"),
    "control_tester_max_records": ("engines", "control_tester_max_records"),
    "control_tester_min_pass_rate_pct": ("engines", "control_tester_min_pass_rate_pct"),
    "bottleneck_detector_enabled": ("engines", "bottleneck_detector_enabled"),
    "bottleneck_detector_max_records": ("engines", "bottleneck_detector_max_records"),
    "bottleneck_detector_critical_utilization_pct": (
        "engines",
        "bottleneck_detector_critical_utilization_pct",
    ),
    "anomaly_scorer_enabled": ("engines", "anomaly_scorer_enabled"),
    "anomaly_scorer_max_records": ("engines", "anomaly_scorer_max_records"),
    "anomaly_scorer_min_anomaly_score": ("engines", "anomaly_scorer_min_anomaly_score"),
    "noise_filter_enabled": ("engines", "noise_filter_enabled"),
    "noise_filter_max_records": ("engines", "noise_filter_max_records"),
    "noise_filter_max_false_alarm_rate_pct": ("engines", "noise_filter_max_false_alarm_rate_pct"),
    "dep_validator_enabled": ("engines", "dep_validator_enabled"),
    "dep_validator_max_records": ("engines", "dep_validator_max_records"),
    "dep_validator_max_invalid_pct": ("engines", "dep_validator_max_invalid_pct"),
    "alert_priority_enabled": ("engines", "alert_priority_enabled"),
    "alert_priority_max_records": ("engines", "alert_priority_max_records"),
    "alert_priority_max_misalignment_pct": ("engines", "alert_priority_max_misalignment_pct"),
    "cost_alloc_validator_enabled": ("engines", "cost_alloc_validator_enabled"),
    "cost_alloc_validator_max_records": ("engines", "cost_alloc_validator_max_records"),
    "cost_alloc_validator_max_variance_pct": ("engines", "cost_alloc_validator_max_variance_pct"),
    "change_correlator_enabled": ("engines", "change_correlator_enabled"),
    "change_correlator_max_records": ("engines", "change_correlator_max_records"),
    "change_correlator_min_correlation_strength_pct": (
        "engines",
        "change_correlator_min_correlation_strength_pct",
    ),
    "slo_dep_mapper_enabled": ("engines", "slo_dep_mapper_enabled"),
    "slo_dep_mapper_max_records": ("engines", "slo_dep_mapper_max_records"),
    "slo_dep_mapper_min_slo_target_pct": ("engines", "slo_dep_mapper_min_slo_target_pct"),
    "metric_aggregator_enabled": ("engines", "metric_aggregator_enabled"),
    "metric_aggregator_max_records": ("engines", "metric_aggregator_max_records"),
    "metric_aggregator_min_metric_health_pct": (
        "engines",
        "metric_aggregator_min_metric_health_pct",
    ),
    "security_event_correlator_enabled": ("engines", "security_event_correlator_enabled"),
    "security_event_correlator_max_records": ("engines", "security_event_correlator_max_records"),
    "security_event_correlator_min_threat_confidence_pct": (
        "engines",
        "security_event_correlator_min_threat_confidence_pct",
    ),
    "knowledge_search_enabled": ("engines", "knowledge_search_enabled"),
    "knowledge_search_max_records": ("engines", "knowledge_search_max_records"),
    "knowledge_search_min_relevance_score": ("engines", "knowledge_search_min_relevance_score"),
    "evidence_consolidator_enabled": ("engines", "evidence_consolidator_enabled"),
    "evidence_consolidator_max_records": ("engines", "evidence_consolidator_max_records"),
    "evidence_consolidator_min_completeness_pct": (
        "engines",
        "evidence_consolidator_min_completeness_pct",
    ),
    "service_latency_enabled": ("engines", "service_latency_enabled"),
    "service_latency_max_records": ("engines", "service_latency_max_records"),
    "service_latency_max_latency_threshold_ms": (
        "engines",
        "service_latency_max_latency_threshold_ms",
    ),
    "audit_compliance_reporter_enabled": ("engines", "audit_compliance_reporter_enabled"),
    "audit_compliance_reporter_max_records": ("engines", "audit_compliance_reporter_max_records"),
    "audit_compliance_reporter_min_compliance_score": (
        "engines",
        "audit_compliance_reporter_min_compliance_score",
    ),
    "response_optimizer_enabled": ("engines", "response_optimizer_enabled"),
    "response_optimizer_max_records": ("engines", "response_optimizer_max_records"),
    "response_optimizer_max_response_time_minutes": (
        "engines",
        "response_optimizer_max_response_time_minutes",
    ),
    "dep_change_tracker_enabled": ("engines", "dep_change_tracker_enabled"),
    "dep_change_tracker_max_records": ("engines", "dep_change_tracker_max_records"),
    "dep_change_tracker_max_breaking_change_pct": (
        "engines",
        "dep_change_tracker_max_breaking_change_pct",
    ),
    "alert_correlation_opt_enabled": ("engines", "alert_correlation_opt_enabled"),
    "alert_correlation_opt_max_records": ("engines", "alert_correlation_opt_max_records"),
    "alert_correlation_opt_min_correlation_strength": (
        "engines",
        "alert_correlation_opt_min_correlation_strength",
    ),
    "forecast_validator_enabled": ("engines", "forecast_validator_enabled"),
    "forecast_validator_max_records": ("engines", "forecast_validator_max_records"),
    "forecast_validator_max_forecast_error_pct": (
        "engines",
        "forecast_validator_max_forecast_error_pct",
    ),
    "rollback_tracker_enabled": ("engines", "rollback_tracker_enabled"),
    "rollback_tracker_max_records": ("engines", "rollback_tracker_max_records"),
    "rollback_tracker_max_rollback_rate_pct": ("engines", "rollback_tracker_max_rollback_rate_pct"),
    "slo_health_enabled": ("engines", "slo_health_enabled"),
    "slo_health_max_records": ("engines", "slo_health_max_records"),
    "slo_health_min_health_score": ("engines", "slo_health_min_health_score"),
    "runbook_compliance_enabled": ("engines", "runbook_compliance_enabled"),
    "runbook_compliance_max_records": ("engines", "runbook_compliance_max_records"),
    "runbook_compliance_min_compliance_pct": ("engines", "runbook_compliance_min_compliance_pct"),
    "vuln_prioritizer_enabled": ("engines", "vuln_prioritizer_enabled"),
    "vuln_prioritizer_max_records": ("engines", "vuln_prioritizer_max_records"),
    "vuln_prioritizer_critical_cvss_threshold": (
        "engines",
        "vuln_prioritizer_critical_cvss_threshold",
    ),
    "usage_analyzer_enabled": ("engines", "usage_analyzer_enabled"),
    "usage_analyzer_max_records": ("engines", "usage_analyzer_max_records"),
    "usage_analyzer_min_usage_score": ("engines", "usage_analyzer_min_usage_score"),
    "compliance_risk_scorer_enabled": ("engines", "compliance_risk_scorer_enabled"),
    "compliance_risk_scorer_max_records": ("engines", "compliance_risk_scorer_max_records"),
    "compliance_risk_scorer_max_risk_score": ("engines", "compliance_risk_scorer_max_risk_score"),
    "perf_benchmark_enabled": ("engines", "perf_benchmark_enabled"),
    "perf_benchmark_max_records": ("engines", "perf_benchmark_max_records"),
    "perf_benchmark_max_regression_pct": ("engines", "perf_benchmark_max_regression_pct"),
    "evidence_tracker_enabled": ("engines", "evidence_tracker_enabled"),
    "evidence_tracker_max_records": ("engines", "evidence_tracker_max_records"),
    "evidence_tracker_min_completeness_pct": ("engines", "evidence_tracker_min_completeness_pct"),
    "triage_quality_enabled": ("engines", "triage_quality_enabled"),
    "triage_quality_max_records": ("engines", "triage_quality_max_records"),
    "triage_quality_min_triage_quality_pct": ("engines", "triage_quality_min_triage_quality_pct"),
    "health_trend_enabled": ("engines", "health_trend_enabled"),
    "health_trend_max_records": ("engines", "health_trend_max_records"),
    "health_trend_min_health_trend_score": ("engines", "health_trend_min_health_trend_score"),
    "metric_quality_enabled": ("engines", "metric_quality_enabled"),
    "metric_quality_max_records": ("engines", "metric_quality_max_records"),
    "metric_quality_min_metric_quality_pct": ("engines", "metric_quality_min_metric_quality_pct"),
    "invoice_validator_enabled": ("engines", "invoice_validator_enabled"),
    "invoice_validator_max_records": ("engines", "invoice_validator_max_records"),
    "invoice_validator_max_discrepancy_pct": ("engines", "invoice_validator_max_discrepancy_pct"),
    "deploy_stability_enabled": ("engines", "deploy_stability_enabled"),
    "deploy_stability_max_records": ("engines", "deploy_stability_max_records"),
    "deploy_stability_min_stability_score": ("engines", "deploy_stability_min_stability_score"),
    "breach_impact_enabled": ("engines", "breach_impact_enabled"),
    "breach_impact_max_records": ("engines", "breach_impact_max_records"),
    "breach_impact_max_breach_impact_score": ("engines", "breach_impact_max_breach_impact_score"),
    "shift_optimizer_enabled": ("engines", "shift_optimizer_enabled"),
    "shift_optimizer_max_records": ("engines", "shift_optimizer_max_records"),
    "shift_optimizer_max_coverage_gap_pct": ("engines", "shift_optimizer_max_coverage_gap_pct"),
    "lateral_movement_enabled": ("engines", "lateral_movement_enabled"),
    "lateral_movement_max_records": ("engines", "lateral_movement_max_records"),
    "lateral_movement_min_detection_confidence_pct": (
        "engines",
        "lateral_movement_min_detection_confidence_pct",
    ),
    "knowledge_coverage_enabled": ("engines", "knowledge_coverage_enabled"),
    "knowledge_coverage_max_records": ("engines", "knowledge_coverage_max_records"),
    "knowledge_coverage_min_coverage_pct": ("engines", "knowledge_coverage_min_coverage_pct"),
    "regulation_tracker_enabled": ("engines", "regulation_tracker_enabled"),
    "regulation_tracker_max_records": ("engines", "regulation_tracker_max_records"),
    "regulation_tracker_max_impact_score": ("engines", "regulation_tracker_max_impact_score"),
    "workflow_analyzer_enabled": ("engines", "workflow_analyzer_enabled"),
    "workflow_analyzer_max_records": ("engines", "workflow_analyzer_max_records"),
    "workflow_analyzer_min_efficiency_score": ("engines", "workflow_analyzer_min_efficiency_score"),
    "finding_tracker_enabled": ("engines", "finding_tracker_enabled"),
    "finding_tracker_max_records": ("engines", "finding_tracker_max_records"),
    "finding_tracker_max_open_finding_pct": ("engines", "finding_tracker_max_open_finding_pct"),
    "blast_radius_enabled": ("engines", "blast_radius_enabled"),
    "blast_radius_max_records": ("engines", "blast_radius_max_records"),
    "blast_radius_max_blast_radius_score": ("engines", "blast_radius_max_blast_radius_score"),
    "api_gateway_health_enabled": ("engines", "api_gateway_health_enabled"),
    "api_gateway_health_max_records": ("engines", "api_gateway_health_max_records"),
    "api_gateway_health_max_error_rate_pct": ("engines", "api_gateway_health_max_error_rate_pct"),
    "log_quality_enabled": ("engines", "log_quality_enabled"),
    "log_quality_max_records": ("engines", "log_quality_max_records"),
    "log_quality_min_log_quality_pct": ("engines", "log_quality_min_log_quality_pct"),
    "commitment_tracker_enabled": ("engines", "commitment_tracker_enabled"),
    "commitment_tracker_max_records": ("engines", "commitment_tracker_max_records"),
    "commitment_tracker_min_utilization_pct": ("engines", "commitment_tracker_min_utilization_pct"),
    "feature_flag_impact_enabled": ("engines", "feature_flag_impact_enabled"),
    "feature_flag_impact_max_records": ("engines", "feature_flag_impact_max_records"),
    "feature_flag_impact_max_negative_impact_pct": (
        "engines",
        "feature_flag_impact_max_negative_impact_pct",
    ),
    "customer_impact_enabled": ("engines", "customer_impact_enabled"),
    "customer_impact_max_records": ("engines", "customer_impact_max_records"),
    "customer_impact_max_impact_score": ("engines", "customer_impact_max_impact_score"),
    "toil_automator_enabled": ("engines", "toil_automator_enabled"),
    "toil_automator_max_records": ("engines", "toil_automator_max_records"),
    "toil_automator_min_automation_pct": ("engines", "toil_automator_min_automation_pct"),
    "insider_threat_enabled": ("engines", "insider_threat_enabled"),
    "insider_threat_max_records": ("engines", "insider_threat_max_records"),
    "insider_threat_min_threat_confidence_pct": (
        "engines",
        "insider_threat_min_threat_confidence_pct",
    ),
    "expertise_mapper_enabled": ("engines", "expertise_mapper_enabled"),
    "expertise_mapper_max_records": ("engines", "expertise_mapper_max_records"),
    "expertise_mapper_min_expertise_coverage_pct": (
        "engines",
        "expertise_mapper_min_expertise_coverage_pct",
    ),
    "control_effectiveness_enabled": ("engines", "control_effectiveness_enabled"),
    "control_effectiveness_max_records": ("engines", "control_effectiveness_max_records"),
    "control_effectiveness_min_effectiveness_pct": (
        "engines",
        "control_effectiveness_min_effectiveness_pct",
    ),
    "reliability_metrics_enabled": ("engines", "reliability_metrics_enabled"),
    "reliability_metrics_max_records": ("engines", "reliability_metrics_max_records"),
    "reliability_metrics_min_reliability_score": (
        "engines",
        "reliability_metrics_min_reliability_score",
    ),
    "remediation_tracker_enabled": ("engines", "remediation_tracker_enabled"),
    "remediation_tracker_max_records": ("engines", "remediation_tracker_max_records"),
    "remediation_tracker_max_overdue_pct": ("engines", "remediation_tracker_max_overdue_pct"),
    "response_playbook_enabled": ("engines", "response_playbook_enabled"),
    "response_playbook_max_records": ("engines", "response_playbook_max_records"),
    "response_playbook_min_playbook_coverage_pct": (
        "engines",
        "response_playbook_min_playbook_coverage_pct",
    ),
    "service_communication_enabled": ("engines", "service_communication_enabled"),
    "service_communication_max_records": ("engines", "service_communication_max_records"),
    "service_communication_max_anomaly_rate_pct": (
        "engines",
        "service_communication_max_anomaly_rate_pct",
    ),
    "dashboard_effectiveness_enabled": ("engines", "dashboard_effectiveness_enabled"),
    "dashboard_effectiveness_max_records": ("engines", "dashboard_effectiveness_max_records"),
    "dashboard_effectiveness_min_effectiveness_score": (
        "engines",
        "dashboard_effectiveness_min_effectiveness_score",
    ),
    "procurement_optimizer_enabled": ("engines", "procurement_optimizer_enabled"),
    "procurement_optimizer_max_records": ("engines", "procurement_optimizer_max_records"),
    "procurement_optimizer_max_waste_pct": ("engines", "procurement_optimizer_max_waste_pct"),
    "merge_risk_enabled": ("engines", "merge_risk_enabled"),
    "merge_risk_max_records": ("engines", "merge_risk_max_records"),
    "merge_risk_max_risk_score": ("engines", "merge_risk_max_risk_score"),
    "degradation_tracker_enabled": ("engines", "degradation_tracker_enabled"),
    "degradation_tracker_max_records": ("engines", "degradation_tracker_max_records"),
    "degradation_tracker_max_degradation_minutes": (
        "engines",
        "degradation_tracker_max_degradation_minutes",
    ),
    "handover_quality_enabled": ("engines", "handover_quality_enabled"),
    "handover_quality_max_records": ("engines", "handover_quality_max_records"),
    "handover_quality_min_handover_quality_pct": (
        "engines",
        "handover_quality_min_handover_quality_pct",
    ),
    "data_classification_enabled": ("engines", "data_classification_enabled"),
    "data_classification_max_records": ("engines", "data_classification_max_records"),
    "data_classification_min_classification_coverage_pct": (
        "engines",
        "data_classification_min_classification_coverage_pct",
    ),
    "feedback_loop_enabled": ("engines", "feedback_loop_enabled"),
    "feedback_loop_max_records": ("engines", "feedback_loop_max_records"),
    "feedback_loop_min_satisfaction_score": ("engines", "feedback_loop_min_satisfaction_score"),
    "policy_coverage_enabled": ("engines", "policy_coverage_enabled"),
    "policy_coverage_max_records": ("engines", "policy_coverage_max_records"),
    "policy_coverage_min_policy_coverage_pct": (
        "engines",
        "policy_coverage_min_policy_coverage_pct",
    ),
    "alert_response_enabled": ("engines", "alert_response_enabled"),
    "alert_response_max_records": ("engines", "alert_response_max_records"),
    "alert_response_max_response_time_minutes": (
        "engines",
        "alert_response_max_response_time_minutes",
    ),
    "change_audit_enabled": ("engines", "change_audit_enabled"),
    "change_audit_max_records": ("engines", "change_audit_max_records"),
    "change_audit_min_audit_compliance_pct": ("engines", "change_audit_min_audit_compliance_pct"),
    "severity_impact_enabled": ("engines", "severity_impact_enabled"),
    "severity_impact_max_records": ("engines", "severity_impact_max_records"),
    "severity_impact_max_high_impact_pct": ("engines", "severity_impact_max_high_impact_pct"),
    "api_contract_drift_enabled": ("engines", "api_contract_drift_enabled"),
    "api_contract_drift_max_records": ("engines", "api_contract_drift_max_records"),
    "api_contract_drift_max_breaking_drift_pct": (
        "engines",
        "api_contract_drift_max_breaking_drift_pct",
    ),
    "trace_coverage_enabled": ("engines", "trace_coverage_enabled"),
    "trace_coverage_max_records": ("engines", "trace_coverage_max_records"),
    "trace_coverage_min_coverage_pct": ("engines", "trace_coverage_min_coverage_pct"),
    "showback_engine_enabled": ("engines", "showback_engine_enabled"),
    "showback_engine_max_records": ("engines", "showback_engine_max_records"),
    "showback_engine_max_over_budget_pct": ("engines", "showback_engine_max_over_budget_pct"),
    "deploy_canary_health_enabled": ("engines", "deploy_canary_health_enabled"),
    "deploy_canary_health_max_records": ("engines", "deploy_canary_health_max_records"),
    "deploy_canary_health_max_unhealthy_pct": ("engines", "deploy_canary_health_max_unhealthy_pct"),
    "maintenance_impact_enabled": ("engines", "maintenance_impact_enabled"),
    "maintenance_impact_max_records": ("engines", "maintenance_impact_max_records"),
    "maintenance_impact_max_impact_minutes": ("engines", "maintenance_impact_max_impact_minutes"),
    "reservation_optimizer_enabled": ("engines", "reservation_optimizer_enabled"),
    "reservation_optimizer_max_records": ("engines", "reservation_optimizer_max_records"),
    "reservation_optimizer_min_utilization_pct": (
        "engines",
        "reservation_optimizer_min_utilization_pct",
    ),
    "secret_rotation_planner_enabled": ("engines", "secret_rotation_planner_enabled"),
    "secret_rotation_planner_max_records": ("engines", "secret_rotation_planner_max_records"),
    "secret_rotation_planner_max_overdue_pct": (
        "engines",
        "secret_rotation_planner_max_overdue_pct",
    ),
    "taxonomy_manager_enabled": ("engines", "taxonomy_manager_enabled"),
    "taxonomy_manager_max_records": ("engines", "taxonomy_manager_max_records"),
    "taxonomy_manager_min_completeness_score": (
        "engines",
        "taxonomy_manager_min_completeness_score",
    ),
    "audit_evidence_mapper_enabled": ("engines", "audit_evidence_mapper_enabled"),
    "audit_evidence_mapper_max_records": ("engines", "audit_evidence_mapper_max_records"),
    "audit_evidence_mapper_min_mapping_coverage_pct": (
        "engines",
        "audit_evidence_mapper_min_mapping_coverage_pct",
    ),
    "capacity_simulation_enabled": ("engines", "capacity_simulation_enabled"),
    "capacity_simulation_max_records": ("engines", "capacity_simulation_max_records"),
    "capacity_simulation_max_over_capacity_pct": (
        "engines",
        "capacity_simulation_max_over_capacity_pct",
    ),
    "access_review_enabled": ("engines", "access_review_enabled"),
    "access_review_max_records": ("engines", "access_review_max_records"),
    "access_review_min_review_completion_pct": (
        "engines",
        "access_review_min_review_completion_pct",
    ),
    "incident_pattern_enabled": ("engines", "incident_pattern_enabled"),
    "incident_pattern_max_records": ("engines", "incident_pattern_max_records"),
    "incident_pattern_max_critical_pattern_pct": (
        "engines",
        "incident_pattern_max_critical_pattern_pct",
    ),
    "escalation_path_enabled": ("engines", "escalation_path_enabled"),
    "escalation_path_max_records": ("engines", "escalation_path_max_records"),
    "escalation_path_max_resolution_time_minutes": (
        "engines",
        "escalation_path_max_resolution_time_minutes",
    ),
    "dependency_freshness_monitor_enabled": ("engines", "dependency_freshness_monitor_enabled"),
    "dependency_freshness_monitor_max_records": (
        "engines",
        "dependency_freshness_monitor_max_records",
    ),
    "dependency_freshness_monitor_max_stale_pct": (
        "engines",
        "dependency_freshness_monitor_max_stale_pct",
    ),
    "cost_attribution_engine_enabled": ("engines", "cost_attribution_engine_enabled"),
    "cost_attribution_engine_max_records": ("engines", "cost_attribution_engine_max_records"),
    "cost_attribution_engine_max_disputed_pct": (
        "engines",
        "cost_attribution_engine_max_disputed_pct",
    ),
    "deploy_rollback_health_enabled": ("engines", "deploy_rollback_health_enabled"),
    "deploy_rollback_health_max_records": ("engines", "deploy_rollback_health_max_records"),
    "deploy_rollback_health_max_recovery_time_seconds": (
        "engines",
        "deploy_rollback_health_max_recovery_time_seconds",
    ),
    "slo_error_budget_tracker_enabled": ("engines", "slo_error_budget_tracker_enabled"),
    "slo_error_budget_tracker_max_records": ("engines", "slo_error_budget_tracker_max_records"),
    "slo_error_budget_tracker_min_remaining_budget_pct": (
        "engines",
        "slo_error_budget_tracker_min_remaining_budget_pct",
    ),
    "operational_readiness_enabled": ("engines", "operational_readiness_enabled"),
    "operational_readiness_max_records": ("engines", "operational_readiness_max_records"),
    "operational_readiness_min_readiness_score": (
        "engines",
        "operational_readiness_min_readiness_score",
    ),
    "threat_intelligence_enabled": ("engines", "threat_intelligence_enabled"),
    "threat_intelligence_max_records": ("engines", "threat_intelligence_max_records"),
    "threat_intelligence_min_threat_confidence_pct": (
        "engines",
        "threat_intelligence_min_threat_confidence_pct",
    ),
    "knowledge_graph_enabled": ("engines", "knowledge_graph_enabled"),
    "knowledge_graph_max_records": ("engines", "knowledge_graph_max_records"),
    "knowledge_graph_max_orphan_pct": ("engines", "knowledge_graph_max_orphan_pct"),
    "compliance_evidence_chain_enabled": ("engines", "compliance_evidence_chain_enabled"),
    "compliance_evidence_chain_max_records": ("engines", "compliance_evidence_chain_max_records"),
    "compliance_evidence_chain_max_broken_chain_pct": (
        "engines",
        "compliance_evidence_chain_max_broken_chain_pct",
    ),
    "capacity_headroom_enabled": ("engines", "capacity_headroom_enabled"),
    "capacity_headroom_max_records": ("engines", "capacity_headroom_max_records"),
    "capacity_headroom_min_headroom_pct": ("engines", "capacity_headroom_min_headroom_pct"),
    "change_velocity_enabled": ("engines", "change_velocity_enabled"),
    "change_velocity_max_records": ("engines", "change_velocity_max_records"),
    "change_velocity_max_changes_per_day": ("engines", "change_velocity_max_changes_per_day"),
    "incident_debrief_enabled": ("engines", "incident_debrief_enabled"),
    "incident_debrief_max_records": ("engines", "incident_debrief_max_records"),
    "incident_debrief_min_debrief_quality_pct": (
        "engines",
        "incident_debrief_min_debrief_quality_pct",
    ),
    "dependency_circuit_breaker_enabled": ("engines", "dependency_circuit_breaker_enabled"),
    "dependency_circuit_breaker_max_records": ("engines", "dependency_circuit_breaker_max_records"),
    "dependency_circuit_breaker_max_open_circuit_pct": (
        "engines",
        "dependency_circuit_breaker_max_open_circuit_pct",
    ),
    "metric_cardinality_planner_enabled": ("engines", "metric_cardinality_planner_enabled"),
    "metric_cardinality_planner_max_records": ("engines", "metric_cardinality_planner_max_records"),
    "metric_cardinality_planner_max_high_cardinality_pct": (
        "engines",
        "metric_cardinality_planner_max_high_cardinality_pct",
    ),
    "cost_forecast_accuracy_enabled": ("engines", "cost_forecast_accuracy_enabled"),
    "cost_forecast_accuracy_max_records": ("engines", "cost_forecast_accuracy_max_records"),
    "cost_forecast_accuracy_min_accuracy_pct": (
        "engines",
        "cost_forecast_accuracy_min_accuracy_pct",
    ),
    "deploy_gate_tracker_enabled": ("engines", "deploy_gate_tracker_enabled"),
    "deploy_gate_tracker_max_records": ("engines", "deploy_gate_tracker_max_records"),
    "deploy_gate_tracker_max_gate_failure_pct": (
        "engines",
        "deploy_gate_tracker_max_gate_failure_pct",
    ),
    "slo_window_analyzer_enabled": ("engines", "slo_window_analyzer_enabled"),
    "slo_window_analyzer_max_records": ("engines", "slo_window_analyzer_max_records"),
    "slo_window_analyzer_min_compliance_pct": ("engines", "slo_window_analyzer_min_compliance_pct"),
    "runbook_dependency_enabled": ("engines", "runbook_dependency_enabled"),
    "runbook_dependency_max_records": ("engines", "runbook_dependency_max_records"),
    "runbook_dependency_max_broken_dependency_pct": (
        "engines",
        "runbook_dependency_max_broken_dependency_pct",
    ),
    "security_posture_gap_enabled": ("engines", "security_posture_gap_enabled"),
    "security_posture_gap_max_records": ("engines", "security_posture_gap_max_records"),
    "security_posture_gap_max_critical_gap_pct": (
        "engines",
        "security_posture_gap_max_critical_gap_pct",
    ),
    "knowledge_retention_enabled": ("engines", "knowledge_retention_enabled"),
    "knowledge_retention_max_records": ("engines", "knowledge_retention_max_records"),
    "knowledge_retention_min_retention_score": (
        "engines",
        "knowledge_retention_min_retention_score",
    ),
    "audit_finding_tracker_enabled": ("engines", "audit_finding_tracker_enabled"),
    "audit_finding_tracker_max_records": ("engines", "audit_finding_tracker_max_records"),
    "audit_finding_tracker_max_open_finding_pct": (
        "engines",
        "audit_finding_tracker_max_open_finding_pct",
    ),
    "capacity_reservation_planner_enabled": ("engines", "capacity_reservation_planner_enabled"),
    "capacity_reservation_planner_max_records": (
        "engines",
        "capacity_reservation_planner_max_records",
    ),
    "capacity_reservation_planner_min_utilization_pct": (
        "engines",
        "capacity_reservation_planner_min_utilization_pct",
    ),
    "change_approval_flow_enabled": ("engines", "change_approval_flow_enabled"),
    "change_approval_flow_max_records": ("engines", "change_approval_flow_max_records"),
    "change_approval_flow_max_approval_time_hours": (
        "engines",
        "change_approval_flow_max_approval_time_hours",
    ),
    "incident_response_time_enabled": ("engines", "incident_response_time_enabled"),
    "incident_response_time_max_records": ("engines", "incident_response_time_max_records"),
    "incident_response_time_max_response_time_minutes": (
        "engines",
        "incident_response_time_max_response_time_minutes",
    ),
    "topology_change_tracker_enabled": ("engines", "topology_change_tracker_enabled"),
    "topology_change_tracker_max_records": ("engines", "topology_change_tracker_max_records"),
    "topology_change_tracker_max_high_impact_pct": (
        "engines",
        "topology_change_tracker_max_high_impact_pct",
    ),
    "observability_budget_planner_enabled": ("engines", "observability_budget_planner_enabled"),
    "observability_budget_planner_max_records": (
        "engines",
        "observability_budget_planner_max_records",
    ),
    "observability_budget_planner_max_over_budget_pct": (
        "engines",
        "observability_budget_planner_max_over_budget_pct",
    ),
    "cost_variance_analyzer_enabled": ("engines", "cost_variance_analyzer_enabled"),
    "cost_variance_analyzer_max_records": ("engines", "cost_variance_analyzer_max_records"),
    "cost_variance_analyzer_max_variance_pct": (
        "engines",
        "cost_variance_analyzer_max_variance_pct",
    ),
    "deploy_dependency_tracker_enabled": ("engines", "deploy_dependency_tracker_enabled"),
    "deploy_dependency_tracker_max_records": ("engines", "deploy_dependency_tracker_max_records"),
    "deploy_dependency_tracker_max_wait_time_minutes": (
        "engines",
        "deploy_dependency_tracker_max_wait_time_minutes",
    ),
    "slo_breach_analyzer_enabled": ("engines", "slo_breach_analyzer_enabled"),
    "slo_breach_analyzer_max_records": ("engines", "slo_breach_analyzer_max_records"),
    "slo_breach_analyzer_max_breach_duration_minutes": (
        "engines",
        "slo_breach_analyzer_max_breach_duration_minutes",
    ),
    "runbook_effectiveness_scorer_enabled": ("engines", "runbook_effectiveness_scorer_enabled"),
    "runbook_effectiveness_scorer_max_records": (
        "engines",
        "runbook_effectiveness_scorer_max_records",
    ),
    "runbook_effectiveness_scorer_min_effectiveness_score": (
        "engines",
        "runbook_effectiveness_scorer_min_effectiveness_score",
    ),
    "threat_response_tracker_enabled": ("engines", "threat_response_tracker_enabled"),
    "threat_response_tracker_max_records": ("engines", "threat_response_tracker_max_records"),
    "threat_response_tracker_max_response_time_hours": (
        "engines",
        "threat_response_tracker_max_response_time_hours",
    ),
    "knowledge_gap_detector_enabled": ("engines", "knowledge_gap_detector_enabled"),
    "knowledge_gap_detector_max_records": ("engines", "knowledge_gap_detector_max_records"),
    "knowledge_gap_detector_min_coverage_pct": (
        "engines",
        "knowledge_gap_detector_min_coverage_pct",
    ),
    "audit_compliance_mapper_enabled": ("engines", "audit_compliance_mapper_enabled"),
    "audit_compliance_mapper_max_records": ("engines", "audit_compliance_mapper_max_records"),
    "audit_compliance_mapper_min_coverage_score": (
        "engines",
        "audit_compliance_mapper_min_coverage_score",
    ),
    "capacity_scaling_advisor_enabled": ("engines", "capacity_scaling_advisor_enabled"),
    "capacity_scaling_advisor_max_records": ("engines", "capacity_scaling_advisor_max_records"),
    "capacity_scaling_advisor_min_efficiency_score": (
        "engines",
        "capacity_scaling_advisor_min_efficiency_score",
    ),
    "change_risk_classifier_enabled": ("engines", "change_risk_classifier_enabled"),
    "change_risk_classifier_max_records": ("engines", "change_risk_classifier_max_records"),
    "change_risk_classifier_max_high_risk_pct": (
        "engines",
        "change_risk_classifier_max_high_risk_pct",
    ),
    "incident_pattern_analyzer_enabled": ("engines", "incident_pattern_analyzer_enabled"),
    "incident_pattern_analyzer_max_records": ("engines", "incident_pattern_analyzer_max_records"),
    "incident_pattern_analyzer_max_recurring_pct": (
        "engines",
        "incident_pattern_analyzer_max_recurring_pct",
    ),
    "service_dependency_scorer_enabled": ("engines", "service_dependency_scorer_enabled"),
    "service_dependency_scorer_max_records": ("engines", "service_dependency_scorer_max_records"),
    "service_dependency_scorer_min_health_score": (
        "engines",
        "service_dependency_scorer_min_health_score",
    ),
    "alert_noise_profiler_enabled": ("engines", "alert_noise_profiler_enabled"),
    "alert_noise_profiler_max_records": ("engines", "alert_noise_profiler_max_records"),
    "alert_noise_profiler_max_noise_ratio": ("engines", "alert_noise_profiler_max_noise_ratio"),
    "cost_optimization_tracker_enabled": ("engines", "cost_optimization_tracker_enabled"),
    "cost_optimization_tracker_max_records": ("engines", "cost_optimization_tracker_max_records"),
    "cost_optimization_tracker_min_savings_pct": (
        "engines",
        "cost_optimization_tracker_min_savings_pct",
    ),
    "deploy_verification_tracker_enabled": ("engines", "deploy_verification_tracker_enabled"),
    "deploy_verification_tracker_max_records": (
        "engines",
        "deploy_verification_tracker_max_records",
    ),
    "deploy_verification_tracker_min_coverage_pct": (
        "engines",
        "deploy_verification_tracker_min_coverage_pct",
    ),
    "slo_compliance_monitor_enabled": ("engines", "slo_compliance_monitor_enabled"),
    "slo_compliance_monitor_max_records": ("engines", "slo_compliance_monitor_max_records"),
    "slo_compliance_monitor_min_compliance_pct": (
        "engines",
        "slo_compliance_monitor_min_compliance_pct",
    ),
    "runbook_quality_scorer_enabled": ("engines", "runbook_quality_scorer_enabled"),
    "runbook_quality_scorer_max_records": ("engines", "runbook_quality_scorer_max_records"),
    "runbook_quality_scorer_min_quality_score": (
        "engines",
        "runbook_quality_scorer_min_quality_score",
    ),
    "vulnerability_response_tracker_enabled": ("engines", "vulnerability_response_tracker_enabled"),
    "vulnerability_response_tracker_max_records": (
        "engines",
        "vulnerability_response_tracker_max_records",
    ),
    "vulnerability_response_tracker_max_remediation_days": (
        "engines",
        "vulnerability_response_tracker_max_remediation_days",
    ),
    "knowledge_freshness_scorer_enabled": ("engines", "knowledge_freshness_scorer_enabled"),
    "knowledge_freshness_scorer_max_records": ("engines", "knowledge_freshness_scorer_max_records"),
    "knowledge_freshness_scorer_min_freshness_score": (
        "engines",
        "knowledge_freshness_scorer_min_freshness_score",
    ),
    "audit_control_assessor_enabled": ("engines", "audit_control_assessor_enabled"),
    "audit_control_assessor_max_records": ("engines", "audit_control_assessor_max_records"),
    "audit_control_assessor_min_effectiveness_score": (
        "engines",
        "audit_control_assessor_min_effectiveness_score",
    ),
    "capacity_utilization_tracker_enabled": ("engines", "capacity_utilization_tracker_enabled"),
    "capacity_utilization_tracker_max_records": (
        "engines",
        "capacity_utilization_tracker_max_records",
    ),
    "capacity_utilization_tracker_min_utilization_pct": (
        "engines",
        "capacity_utilization_tracker_min_utilization_pct",
    ),
    "change_impact_predictor_enabled": ("engines", "change_impact_predictor_enabled"),
    "change_impact_predictor_max_records": ("engines", "change_impact_predictor_max_records"),
    "change_impact_predictor_max_high_impact_pct": (
        "engines",
        "change_impact_predictor_max_high_impact_pct",
    ),
    "incident_escalation_scorer_enabled": ("engines", "incident_escalation_scorer_enabled"),
    "incident_escalation_scorer_max_records": ("engines", "incident_escalation_scorer_max_records"),
    "incident_escalation_scorer_min_quality_score": (
        "engines",
        "incident_escalation_scorer_min_quality_score",
    ),
    "topology_drift_detector_enabled": ("engines", "topology_drift_detector_enabled"),
    "topology_drift_detector_max_records": ("engines", "topology_drift_detector_max_records"),
    "topology_drift_detector_max_critical_drift_pct": (
        "engines",
        "topology_drift_detector_max_critical_drift_pct",
    ),
    "alert_correlation_profiler_enabled": ("engines", "alert_correlation_profiler_enabled"),
    "alert_correlation_profiler_max_records": ("engines", "alert_correlation_profiler_max_records"),
    "alert_correlation_profiler_min_correlation_score": (
        "engines",
        "alert_correlation_profiler_min_correlation_score",
    ),
    "cost_allocation_validator_enabled": ("engines", "cost_allocation_validator_enabled"),
    "cost_allocation_validator_max_records": ("engines", "cost_allocation_validator_max_records"),
    "cost_allocation_validator_min_accuracy_pct": (
        "engines",
        "cost_allocation_validator_min_accuracy_pct",
    ),
    "deploy_canary_analyzer_enabled": ("engines", "deploy_canary_analyzer_enabled"),
    "deploy_canary_analyzer_max_records": ("engines", "deploy_canary_analyzer_max_records"),
    "deploy_canary_analyzer_min_success_rate": (
        "engines",
        "deploy_canary_analyzer_min_success_rate",
    ),
    "slo_error_budget_forecaster_enabled": ("engines", "slo_error_budget_forecaster_enabled"),
    "slo_error_budget_forecaster_max_records": (
        "engines",
        "slo_error_budget_forecaster_max_records",
    ),
    "slo_error_budget_forecaster_min_remaining_pct": (
        "engines",
        "slo_error_budget_forecaster_min_remaining_pct",
    ),
    "runbook_automation_scorer_enabled": ("engines", "runbook_automation_scorer_enabled"),
    "runbook_automation_scorer_max_records": ("engines", "runbook_automation_scorer_max_records"),
    "runbook_automation_scorer_min_automation_score": (
        "engines",
        "runbook_automation_scorer_min_automation_score",
    ),
    "threat_surface_analyzer_enabled": ("engines", "threat_surface_analyzer_enabled"),
    "threat_surface_analyzer_max_records": ("engines", "threat_surface_analyzer_max_records"),
    "threat_surface_analyzer_max_exposure_score": (
        "engines",
        "threat_surface_analyzer_max_exposure_score",
    ),
    "knowledge_quality_assessor_enabled": ("engines", "knowledge_quality_assessor_enabled"),
    "knowledge_quality_assessor_max_records": ("engines", "knowledge_quality_assessor_max_records"),
    "knowledge_quality_assessor_min_quality_score": (
        "engines",
        "knowledge_quality_assessor_min_quality_score",
    ),
    "audit_remediation_tracker_enabled": ("engines", "audit_remediation_tracker_enabled"),
    "audit_remediation_tracker_max_records": ("engines", "audit_remediation_tracker_max_records"),
    "audit_remediation_tracker_max_remediation_days": (
        "engines",
        "audit_remediation_tracker_max_remediation_days",
    ),
    "capacity_forecast_validator_enabled": ("engines", "capacity_forecast_validator_enabled"),
    "capacity_forecast_validator_max_records": (
        "engines",
        "capacity_forecast_validator_max_records",
    ),
    "capacity_forecast_validator_min_accuracy_pct": (
        "engines",
        "capacity_forecast_validator_min_accuracy_pct",
    ),
    "change_window_analyzer_enabled": ("engines", "change_window_analyzer_enabled"),
    "change_window_analyzer_max_records": ("engines", "change_window_analyzer_max_records"),
    "change_window_analyzer_min_compliance_pct": (
        "engines",
        "change_window_analyzer_min_compliance_pct",
    ),
    "incident_mitigation_enabled": ("engines", "incident_mitigation_enabled"),
    "incident_mitigation_max_records": ("engines", "incident_mitigation_max_records"),
    "incident_mitigation_effectiveness_threshold": (
        "engines",
        "incident_mitigation_effectiveness_threshold",
    ),
    "service_routing_opt_enabled": ("engines", "service_routing_opt_enabled"),
    "service_routing_opt_max_records": ("engines", "service_routing_opt_max_records"),
    "service_routing_opt_latency_threshold_ms": (
        "engines",
        "service_routing_opt_latency_threshold_ms",
    ),
    "metric_anomaly_cls_enabled": ("engines", "metric_anomaly_cls_enabled"),
    "metric_anomaly_cls_max_records": ("engines", "metric_anomaly_cls_max_records"),
    "metric_anomaly_cls_confidence_threshold": (
        "engines",
        "metric_anomaly_cls_confidence_threshold",
    ),
    "cost_governance_enabled": ("engines", "cost_governance_enabled"),
    "cost_governance_max_records": ("engines", "cost_governance_max_records"),
    "cost_governance_max_violation_rate": ("engines", "cost_governance_max_violation_rate"),
    "change_rollout_enabled": ("engines", "change_rollout_enabled"),
    "change_rollout_max_records": ("engines", "change_rollout_max_records"),
    "change_rollout_risk_tolerance_threshold": (
        "engines",
        "change_rollout_risk_tolerance_threshold",
    ),
    "slo_threshold_opt_enabled": ("engines", "slo_threshold_opt_enabled"),
    "slo_threshold_opt_max_records": ("engines", "slo_threshold_opt_max_records"),
    "slo_threshold_opt_adjustment_sensitivity": (
        "engines",
        "slo_threshold_opt_adjustment_sensitivity",
    ),
    "operational_hygiene_enabled": ("engines", "operational_hygiene_enabled"),
    "operational_hygiene_max_records": ("engines", "operational_hygiene_max_records"),
    "operational_hygiene_min_hygiene_score": ("engines", "operational_hygiene_min_hygiene_score"),
    "security_signal_corr_enabled": ("engines", "security_signal_corr_enabled"),
    "security_signal_corr_max_records": ("engines", "security_signal_corr_max_records"),
    "security_signal_corr_correlation_confidence_threshold": (
        "engines",
        "security_signal_corr_correlation_confidence_threshold",
    ),
    "knowledge_reuse_enabled": ("engines", "knowledge_reuse_enabled"),
    "knowledge_reuse_max_records": ("engines", "knowledge_reuse_max_records"),
    "knowledge_reuse_min_reuse_score": ("engines", "knowledge_reuse_min_reuse_score"),
    "audit_workflow_opt_enabled": ("engines", "audit_workflow_opt_enabled"),
    "audit_workflow_opt_max_records": ("engines", "audit_workflow_opt_max_records"),
    "audit_workflow_opt_cycle_time_threshold": (
        "engines",
        "audit_workflow_opt_cycle_time_threshold",
    ),
    "perf_baseline_tracker_enabled": ("engines", "perf_baseline_tracker_enabled"),
    "perf_baseline_tracker_max_records": ("engines", "perf_baseline_tracker_max_records"),
    "perf_baseline_tracker_deviation_threshold": (
        "engines",
        "perf_baseline_tracker_deviation_threshold",
    ),
    "compliance_control_map_enabled": ("engines", "compliance_control_map_enabled"),
    "compliance_control_map_max_records": ("engines", "compliance_control_map_max_records"),
    "compliance_control_map_coverage_gap_threshold": (
        "engines",
        "compliance_control_map_coverage_gap_threshold",
    ),
    "stakeholder_impact_tracker_enabled": ("engines", "stakeholder_impact_tracker_enabled"),
    "stakeholder_impact_tracker_max_records": ("engines", "stakeholder_impact_tracker_max_records"),
    "stakeholder_impact_tracker_impact_score_threshold": (
        "engines",
        "stakeholder_impact_tracker_impact_score_threshold",
    ),
    "service_health_predictor_enabled": ("engines", "service_health_predictor_enabled"),
    "service_health_predictor_max_records": ("engines", "service_health_predictor_max_records"),
    "service_health_predictor_prediction_confidence_threshold": (
        "engines",
        "service_health_predictor_prediction_confidence_threshold",
    ),
    "metric_collection_optimizer_enabled": ("engines", "metric_collection_optimizer_enabled"),
    "metric_collection_optimizer_max_records": (
        "engines",
        "metric_collection_optimizer_max_records",
    ),
    "metric_collection_optimizer_collection_efficiency_threshold": (
        "engines",
        "metric_collection_optimizer_collection_efficiency_threshold",
    ),
    "cost_forecast_precision_enabled": ("engines", "cost_forecast_precision_enabled"),
    "cost_forecast_precision_max_records": ("engines", "cost_forecast_precision_max_records"),
    "cost_forecast_precision_precision_accuracy_threshold": (
        "engines",
        "cost_forecast_precision_precision_accuracy_threshold",
    ),
    "change_coordination_planner_enabled": ("engines", "change_coordination_planner_enabled"),
    "change_coordination_planner_max_records": (
        "engines",
        "change_coordination_planner_max_records",
    ),
    "change_coordination_planner_coordination_risk_threshold": (
        "engines",
        "change_coordination_planner_coordination_risk_threshold",
    ),
    "slo_cross_correlation_enabled": ("engines", "slo_cross_correlation_enabled"),
    "slo_cross_correlation_max_records": ("engines", "slo_cross_correlation_max_records"),
    "slo_cross_correlation_correlation_strength_threshold": (
        "engines",
        "slo_cross_correlation_correlation_strength_threshold",
    ),
    "team_capacity_planner_enabled": ("engines", "team_capacity_planner_enabled"),
    "team_capacity_planner_max_records": ("engines", "team_capacity_planner_max_records"),
    "team_capacity_planner_capacity_utilization_threshold": (
        "engines",
        "team_capacity_planner_capacity_utilization_threshold",
    ),
    "security_compliance_scorer_enabled": ("engines", "security_compliance_scorer_enabled"),
    "security_compliance_scorer_max_records": ("engines", "security_compliance_scorer_max_records"),
    "security_compliance_scorer_compliance_gap_threshold": (
        "engines",
        "security_compliance_scorer_compliance_gap_threshold",
    ),
    "knowledge_impact_analyzer_enabled": ("engines", "knowledge_impact_analyzer_enabled"),
    "knowledge_impact_analyzer_max_records": ("engines", "knowledge_impact_analyzer_max_records"),
    "knowledge_impact_analyzer_impact_relevance_threshold": (
        "engines",
        "knowledge_impact_analyzer_impact_relevance_threshold",
    ),
    "audit_scope_optimizer_enabled": ("engines", "audit_scope_optimizer_enabled"),
    "audit_scope_optimizer_max_records": ("engines", "audit_scope_optimizer_max_records"),
    "audit_scope_optimizer_scope_efficiency_threshold": (
        "engines",
        "audit_scope_optimizer_scope_efficiency_threshold",
    ),
    "data_quality_scorer_enabled": ("engines", "data_quality_scorer_enabled"),
    "data_quality_scorer_max_records": ("engines", "data_quality_scorer_max_records"),
    "data_quality_scorer_quality_score_threshold": (
        "engines",
        "data_quality_scorer_quality_score_threshold",
    ),
    "regulatory_impact_tracker_enabled": ("engines", "regulatory_impact_tracker_enabled"),
    "regulatory_impact_tracker_max_records": ("engines", "regulatory_impact_tracker_max_records"),
    "regulatory_impact_tracker_impact_severity_threshold": (
        "engines",
        "regulatory_impact_tracker_impact_severity_threshold",
    ),
    "mitre_attack_mapper_enabled": ("engines", "mitre_attack_mapper_enabled"),
    "mitre_attack_mapper_max_records": ("engines", "mitre_attack_mapper_max_records"),
    "mitre_attack_mapper_coverage_gap_threshold": (
        "engines",
        "mitre_attack_mapper_coverage_gap_threshold",
    ),
    "threat_intel_aggregator_enabled": ("engines", "threat_intel_aggregator_enabled"),
    "threat_intel_aggregator_max_records": ("engines", "threat_intel_aggregator_max_records"),
    "threat_intel_aggregator_ioc_confidence_threshold": (
        "engines",
        "threat_intel_aggregator_ioc_confidence_threshold",
    ),
    "soar_playbook_engine_enabled": ("engines", "soar_playbook_engine_enabled"),
    "soar_playbook_engine_max_records": ("engines", "soar_playbook_engine_max_records"),
    "soar_playbook_engine_effectiveness_threshold": (
        "engines",
        "soar_playbook_engine_effectiveness_threshold",
    ),
    "attack_chain_reconstructor_enabled": ("engines", "attack_chain_reconstructor_enabled"),
    "attack_chain_reconstructor_max_records": ("engines", "attack_chain_reconstructor_max_records"),
    "attack_chain_reconstructor_completeness_threshold": (
        "engines",
        "attack_chain_reconstructor_completeness_threshold",
    ),
    "soc_metrics_dashboard_enabled": ("engines", "soc_metrics_dashboard_enabled"),
    "soc_metrics_dashboard_max_records": ("engines", "soc_metrics_dashboard_max_records"),
    "soc_metrics_dashboard_metric_target_threshold": (
        "engines",
        "soc_metrics_dashboard_metric_target_threshold",
    ),
    "adversary_simulation_engine_enabled": ("engines", "adversary_simulation_engine_enabled"),
    "adversary_simulation_engine_max_records": (
        "engines",
        "adversary_simulation_engine_max_records",
    ),
    "adversary_simulation_engine_detection_threshold": (
        "engines",
        "adversary_simulation_engine_detection_threshold",
    ),
    "risk_quantification_engine_enabled": ("engines", "risk_quantification_engine_enabled"),
    "risk_quantification_engine_max_records": ("engines", "risk_quantification_engine_max_records"),
    "risk_quantification_engine_risk_tolerance_threshold": (
        "engines",
        "risk_quantification_engine_risk_tolerance_threshold",
    ),
    "alert_triage_scorer_enabled": ("engines", "alert_triage_scorer_enabled"),
    "alert_triage_scorer_max_records": ("engines", "alert_triage_scorer_max_records"),
    "alert_triage_scorer_triage_score_threshold": (
        "engines",
        "alert_triage_scorer_triage_score_threshold",
    ),
    "compliance_evidence_automator_v2_enabled": (
        "engines",
        "compliance_evidence_automator_v2_enabled",
    ),
    "compliance_evidence_automator_v2_max_records": (
        "engines",
        "compliance_evidence_automator_v2_max_records",
    ),
    "compliance_evidence_automator_v2_completeness_threshold": (
        "engines",
        "compliance_evidence_automator_v2_completeness_threshold",
    ),
    "incident_containment_tracker_enabled": ("engines", "incident_containment_tracker_enabled"),
    "incident_containment_tracker_max_records": (
        "engines",
        "incident_containment_tracker_max_records",
    ),
    "incident_containment_tracker_effectiveness_threshold": (
        "engines",
        "incident_containment_tracker_effectiveness_threshold",
    ),
    "incident_forensics_tracker_enabled": ("engines", "incident_forensics_tracker_enabled"),
    "incident_forensics_tracker_max_records": ("engines", "incident_forensics_tracker_max_records"),
    "incident_forensics_tracker_integrity_threshold": (
        "engines",
        "incident_forensics_tracker_integrity_threshold",
    ),
    "deception_tech_manager_enabled": ("engines", "deception_tech_manager_enabled"),
    "deception_tech_manager_max_records": ("engines", "deception_tech_manager_max_records"),
    "deception_tech_manager_detection_threshold": (
        "engines",
        "deception_tech_manager_detection_threshold",
    ),
    "soc_analyst_agent_enabled": ("engines", "soc_analyst_agent_enabled"),
    "alert_enrichment_engine_enabled": ("engines", "alert_enrichment_engine_enabled"),
    "alert_enrichment_engine_max_records": ("engines", "alert_enrichment_engine_max_records"),
    "alert_enrichment_engine_enrichment_quality_threshold": (
        "engines",
        "alert_enrichment_engine_enrichment_quality_threshold",
    ),
    "detection_rule_effectiveness_enabled": ("engines", "detection_rule_effectiveness_enabled"),
    "detection_rule_effectiveness_max_records": (
        "engines",
        "detection_rule_effectiveness_max_records",
    ),
    "detection_rule_effectiveness_rule_effectiveness_threshold": (
        "engines",
        "detection_rule_effectiveness_rule_effectiveness_threshold",
    ),
    "analyst_workload_balancer_enabled": ("engines", "analyst_workload_balancer_enabled"),
    "analyst_workload_balancer_max_records": ("engines", "analyst_workload_balancer_max_records"),
    "analyst_workload_balancer_utilization_threshold": (
        "engines",
        "analyst_workload_balancer_utilization_threshold",
    ),
    "alert_escalation_intelligence_enabled": ("engines", "alert_escalation_intelligence_enabled"),
    "alert_escalation_intelligence_max_records": (
        "engines",
        "alert_escalation_intelligence_max_records",
    ),
    "alert_escalation_intelligence_escalation_effectiveness_threshold": (
        "engines",
        "alert_escalation_intelligence_escalation_effectiveness_threshold",
    ),
    "ioc_sweep_engine_enabled": ("engines", "ioc_sweep_engine_enabled"),
    "ioc_sweep_engine_max_records": ("engines", "ioc_sweep_engine_max_records"),
    "ioc_sweep_engine_match_score_threshold": ("engines", "ioc_sweep_engine_match_score_threshold"),
    "security_alert_dedup_engine_enabled": ("engines", "security_alert_dedup_engine_enabled"),
    "security_alert_dedup_engine_max_records": (
        "engines",
        "security_alert_dedup_engine_max_records",
    ),
    "security_alert_dedup_engine_dedup_effectiveness_threshold": (
        "engines",
        "security_alert_dedup_engine_dedup_effectiveness_threshold",
    ),
    "threat_hunter_agent_enabled": ("engines", "threat_hunter_agent_enabled"),
    "hunt_hypothesis_generator_enabled": ("engines", "hunt_hypothesis_generator_enabled"),
    "hunt_hypothesis_generator_max_records": ("engines", "hunt_hypothesis_generator_max_records"),
    "hunt_hypothesis_generator_hypothesis_quality_threshold": (
        "engines",
        "hunt_hypothesis_generator_hypothesis_quality_threshold",
    ),
    "behavioral_baseline_engine_enabled": ("engines", "behavioral_baseline_engine_enabled"),
    "behavioral_baseline_engine_max_records": ("engines", "behavioral_baseline_engine_max_records"),
    "behavioral_baseline_engine_deviation_threshold": (
        "engines",
        "behavioral_baseline_engine_deviation_threshold",
    ),
    "hunt_effectiveness_tracker_enabled": ("engines", "hunt_effectiveness_tracker_enabled"),
    "hunt_effectiveness_tracker_max_records": ("engines", "hunt_effectiveness_tracker_max_records"),
    "hunt_effectiveness_tracker_hunt_effectiveness_threshold": (
        "engines",
        "hunt_effectiveness_tracker_hunt_effectiveness_threshold",
    ),
    "threat_campaign_tracker_enabled": ("engines", "threat_campaign_tracker_enabled"),
    "threat_campaign_tracker_max_records": ("engines", "threat_campaign_tracker_max_records"),
    "threat_campaign_tracker_threat_score_threshold": (
        "engines",
        "threat_campaign_tracker_threat_score_threshold",
    ),
    "anomalous_access_detector_enabled": ("engines", "anomalous_access_detector_enabled"),
    "anomalous_access_detector_max_records": ("engines", "anomalous_access_detector_max_records"),
    "anomalous_access_detector_anomaly_score_threshold": (
        "engines",
        "anomalous_access_detector_anomaly_score_threshold",
    ),
    "network_flow_analyzer_enabled": ("engines", "network_flow_analyzer_enabled"),
    "network_flow_analyzer_max_records": ("engines", "network_flow_analyzer_max_records"),
    "network_flow_analyzer_suspicion_score_threshold": (
        "engines",
        "network_flow_analyzer_suspicion_score_threshold",
    ),
    "forensics_agent_enabled": ("engines", "forensics_agent_enabled"),
    "deception_agent_enabled": ("engines", "deception_agent_enabled"),
    "evidence_integrity_verifier_enabled": ("engines", "evidence_integrity_verifier_enabled"),
    "evidence_integrity_verifier_max_records": (
        "engines",
        "evidence_integrity_verifier_max_records",
    ),
    "evidence_integrity_verifier_integrity_confidence_threshold": (
        "engines",
        "evidence_integrity_verifier_integrity_confidence_threshold",
    ),
    "forensic_timeline_builder_enabled": ("engines", "forensic_timeline_builder_enabled"),
    "forensic_timeline_builder_max_records": ("engines", "forensic_timeline_builder_max_records"),
    "forensic_timeline_builder_accuracy_threshold": (
        "engines",
        "forensic_timeline_builder_accuracy_threshold",
    ),
    "honeypot_interaction_analyzer_enabled": ("engines", "honeypot_interaction_analyzer_enabled"),
    "honeypot_interaction_analyzer_max_records": (
        "engines",
        "honeypot_interaction_analyzer_max_records",
    ),
    "honeypot_interaction_analyzer_threat_score_threshold": (
        "engines",
        "honeypot_interaction_analyzer_threat_score_threshold",
    ),
    "attacker_profile_builder_enabled": ("engines", "attacker_profile_builder_enabled"),
    "attacker_profile_builder_max_records": ("engines", "attacker_profile_builder_max_records"),
    "attacker_profile_builder_profile_confidence_threshold": (
        "engines",
        "attacker_profile_builder_profile_confidence_threshold",
    ),
    "zero_day_detection_engine_enabled": ("engines", "zero_day_detection_engine_enabled"),
    "zero_day_detection_engine_max_records": ("engines", "zero_day_detection_engine_max_records"),
    "zero_day_detection_engine_detection_confidence_threshold": (
        "engines",
        "zero_day_detection_engine_detection_confidence_threshold",
    ),
    "supply_chain_attack_detector_enabled": ("engines", "supply_chain_attack_detector_enabled"),
    "supply_chain_attack_detector_max_records": (
        "engines",
        "supply_chain_attack_detector_max_records",
    ),
    "supply_chain_attack_detector_supply_chain_risk_threshold": (
        "engines",
        "supply_chain_attack_detector_supply_chain_risk_threshold",
    ),
    "apt_detection_engine_enabled": ("engines", "apt_detection_engine_enabled"),
    "apt_detection_engine_max_records": ("engines", "apt_detection_engine_max_records"),
    "apt_detection_engine_apt_threat_threshold": (
        "engines",
        "apt_detection_engine_apt_threat_threshold",
    ),
    "ransomware_defense_engine_enabled": ("engines", "ransomware_defense_engine_enabled"),
    "ransomware_defense_engine_max_records": ("engines", "ransomware_defense_engine_max_records"),
    "ransomware_defense_engine_readiness_threshold": (
        "engines",
        "ransomware_defense_engine_readiness_threshold",
    ),
    "dlp_scorer_enabled": ("engines", "dlp_scorer_enabled"),
    "dlp_scorer_max_records": ("engines", "dlp_scorer_max_records"),
    "dlp_scorer_protection_threshold": ("engines", "dlp_scorer_protection_threshold"),
    "insider_threat_ai_scorer_enabled": ("engines", "insider_threat_ai_scorer_enabled"),
    "insider_threat_ai_scorer_max_records": ("engines", "insider_threat_ai_scorer_max_records"),
    "insider_threat_ai_scorer_insider_threat_threshold": (
        "engines",
        "insider_threat_ai_scorer_insider_threat_threshold",
    ),
    "cloud_security_posture_scorer_enabled": ("engines", "cloud_security_posture_scorer_enabled"),
    "cloud_security_posture_scorer_max_records": (
        "engines",
        "cloud_security_posture_scorer_max_records",
    ),
    "cloud_security_posture_scorer_posture_threshold": (
        "engines",
        "cloud_security_posture_scorer_posture_threshold",
    ),
    "container_runtime_security_enabled": ("engines", "container_runtime_security_enabled"),
    "container_runtime_security_max_records": ("engines", "container_runtime_security_max_records"),
    "container_runtime_security_runtime_security_threshold": (
        "engines",
        "container_runtime_security_runtime_security_threshold",
    ),
    "identity_threat_detection_enabled": ("engines", "identity_threat_detection_enabled"),
    "identity_threat_detection_max_records": ("engines", "identity_threat_detection_max_records"),
    "identity_threat_detection_identity_threat_threshold": (
        "engines",
        "identity_threat_detection_identity_threat_threshold",
    ),
    "threat_intel_correlation_enabled": ("engines", "threat_intel_correlation_enabled"),
    "threat_intel_correlation_max_records": ("engines", "threat_intel_correlation_max_records"),
    "threat_intel_correlation_correlation_confidence_threshold": (
        "engines",
        "threat_intel_correlation_correlation_confidence_threshold",
    ),
    "security_automation_coverage_enabled": ("engines", "security_automation_coverage_enabled"),
    "security_automation_coverage_max_records": (
        "engines",
        "security_automation_coverage_max_records",
    ),
    "security_automation_coverage_automation_coverage_threshold": (
        "engines",
        "security_automation_coverage_automation_coverage_threshold",
    ),
    "purple_team_exercise_tracker_enabled": ("engines", "purple_team_exercise_tracker_enabled"),
    "purple_team_exercise_tracker_max_records": (
        "engines",
        "purple_team_exercise_tracker_max_records",
    ),
    "purple_team_exercise_tracker_exercise_effectiveness_threshold": (
        "engines",
        "purple_team_exercise_tracker_exercise_effectiveness_threshold",
    ),
    "fair_risk_modeler_enabled": ("engines", "fair_risk_modeler_enabled"),
    "fair_risk_modeler_max_records": ("engines", "fair_risk_modeler_max_records"),
    "fair_risk_modeler_risk_estimate_threshold": (
        "engines",
        "fair_risk_modeler_risk_estimate_threshold",
    ),
    "continuous_compliance_monitor_enabled": ("engines", "continuous_compliance_monitor_enabled"),
    "continuous_compliance_monitor_max_records": (
        "engines",
        "continuous_compliance_monitor_max_records",
    ),
    "continuous_compliance_monitor_compliance_drift_threshold": (
        "engines",
        "continuous_compliance_monitor_compliance_drift_threshold",
    ),
    "regulatory_change_impact_enabled": ("engines", "regulatory_change_impact_enabled"),
    "regulatory_change_impact_max_records": ("engines", "regulatory_change_impact_max_records"),
    "regulatory_change_impact_regulatory_impact_threshold": (
        "engines",
        "regulatory_change_impact_regulatory_impact_threshold",
    ),
    "risk_prediction_engine_enabled": ("engines", "risk_prediction_engine_enabled"),
    "risk_prediction_engine_max_records": ("engines", "risk_prediction_engine_max_records"),
    "risk_prediction_engine_forecast_confidence_threshold": (
        "engines",
        "risk_prediction_engine_forecast_confidence_threshold",
    ),
    "control_effectiveness_scorer_enabled": ("engines", "control_effectiveness_scorer_enabled"),
    "control_effectiveness_scorer_max_records": (
        "engines",
        "control_effectiveness_scorer_max_records",
    ),
    "control_effectiveness_scorer_control_effectiveness_threshold": (
        "engines",
        "control_effectiveness_scorer_control_effectiveness_threshold",
    ),
    "vendor_risk_intelligence_enabled": ("engines", "vendor_risk_intelligence_enabled"),
    "vendor_risk_intelligence_max_records": ("engines", "vendor_risk_intelligence_max_records"),
    "vendor_risk_intelligence_vendor_risk_threshold": (
        "engines",
        "vendor_risk_intelligence_vendor_risk_threshold",
    ),
    "compliance_gap_prioritizer_enabled": ("engines", "compliance_gap_prioritizer_enabled"),
    "compliance_gap_prioritizer_max_records": ("engines", "compliance_gap_prioritizer_max_records"),
    "compliance_gap_prioritizer_gap_priority_threshold": (
        "engines",
        "compliance_gap_prioritizer_gap_priority_threshold",
    ),
    "audit_readiness_scorer_enabled": ("engines", "audit_readiness_scorer_enabled"),
    "audit_readiness_scorer_max_records": ("engines", "audit_readiness_scorer_max_records"),
    "audit_readiness_scorer_readiness_threshold": (
        "engines",
        "audit_readiness_scorer_readiness_threshold",
    ),
    "risk_treatment_tracker_enabled": ("engines", "risk_treatment_tracker_enabled"),
    "risk_treatment_tracker_max_records": ("engines", "risk_treatment_tracker_max_records"),
    "risk_treatment_tracker_residual_risk_threshold": (
        "engines",
        "risk_treatment_tracker_residual_risk_threshold",
    ),
    "compliance_automation_scorer_enabled": ("engines", "compliance_automation_scorer_enabled"),
    "compliance_automation_scorer_max_records": (
        "engines",
        "compliance_automation_scorer_max_records",
    ),
    "compliance_automation_scorer_automation_threshold": (
        "engines",
        "compliance_automation_scorer_automation_threshold",
    ),
    "data_privacy_impact_assessor_enabled": ("engines", "data_privacy_impact_assessor_enabled"),
    "data_privacy_impact_assessor_max_records": (
        "engines",
        "data_privacy_impact_assessor_max_records",
    ),
    "data_privacy_impact_assessor_privacy_impact_threshold": (
        "engines",
        "data_privacy_impact_assessor_privacy_impact_threshold",
    ),
    "security_maturity_model_enabled": ("engines", "security_maturity_model_enabled"),
    "security_maturity_model_max_records": ("engines", "security_maturity_model_max_records"),
    "security_maturity_model_maturity_threshold": (
        "engines",
        "security_maturity_model_maturity_threshold",
    ),
    "incident_response_agent_enabled": ("engines", "incident_response_agent_enabled"),
    "incident_response_containment_timeout_seconds": (
        "engines",
        "incident_response_containment_timeout_seconds",
    ),
    "incident_response_max_concurrent_responses": (
        "engines",
        "incident_response_max_concurrent_responses",
    ),
    "attack_surface_agent_enabled": ("engines", "attack_surface_agent_enabled"),
    "attack_surface_scan_timeout_seconds": ("engines", "attack_surface_scan_timeout_seconds"),
    "attack_surface_max_concurrent_scans": ("engines", "attack_surface_max_concurrent_scans"),
    "ml_governance_agent_enabled": ("engines", "ml_governance_agent_enabled"),
    "ml_governance_evaluation_timeout_seconds": (
        "engines",
        "ml_governance_evaluation_timeout_seconds",
    ),
    "ml_governance_max_concurrent_evaluations": (
        "engines",
        "ml_governance_max_concurrent_evaluations",
    ),
    "finops_intelligence_agent_enabled": ("engines", "finops_intelligence_agent_enabled"),
    "finops_analysis_timeout_seconds": ("engines", "finops_analysis_timeout_seconds"),
    "finops_max_concurrent_analyses": ("engines", "finops_max_concurrent_analyses"),
    "zero_trust_agent_enabled": ("engines", "zero_trust_agent_enabled"),
    "zero_trust_assessment_timeout_seconds": ("engines", "zero_trust_assessment_timeout_seconds"),
    "zero_trust_max_concurrent_assessments": ("engines", "zero_trust_max_concurrent_assessments"),
    "threat_automation_agent_enabled": ("engines", "threat_automation_agent_enabled"),
    "threat_automation_hunt_timeout_seconds": ("engines", "threat_automation_hunt_timeout_seconds"),
    "threat_automation_max_concurrent_hunts": ("engines", "threat_automation_max_concurrent_hunts"),
    "soar_orchestration_agent_enabled": ("engines", "soar_orchestration_agent_enabled"),
    "soar_orchestration_timeout_seconds": ("engines", "soar_orchestration_timeout_seconds"),
    "soar_orchestration_max_concurrent": ("engines", "soar_orchestration_max_concurrent"),
    "itdr_agent_enabled": ("engines", "itdr_agent_enabled"),
    "itdr_detection_timeout_seconds": ("engines", "itdr_detection_timeout_seconds"),
    "itdr_max_concurrent_detections": ("engines", "itdr_max_concurrent_detections"),
    "auto_remediation_agent_enabled": ("engines", "auto_remediation_agent_enabled"),
    "auto_remediation_timeout_seconds": ("engines", "auto_remediation_timeout_seconds"),
    "auto_remediation_max_concurrent": ("engines", "auto_remediation_max_concurrent"),
    "observability_intelligence_agent_enabled": (
        "engines",
        "observability_intelligence_agent_enabled",
    ),
    "observability_intelligence_timeout_seconds": (
        "engines",
        "observability_intelligence_timeout_seconds",
    ),
    "observability_intelligence_max_concurrent": (
        "engines",
        "observability_intelligence_max_concurrent",
    ),
    "xdr_agent_enabled": ("engines", "xdr_agent_enabled"),
    "xdr_timeout_seconds": ("engines", "xdr_timeout_seconds"),
    "xdr_max_concurrent": ("engines", "xdr_max_concurrent"),
    "intelligent_automation_agent_enabled": ("engines", "intelligent_automation_agent_enabled"),
    "intelligent_automation_timeout_seconds": ("engines", "intelligent_automation_timeout_seconds"),
    "intelligent_automation_max_concurrent": ("engines", "intelligent_automation_max_concurrent"),
    "platform_intelligence_agent_enabled": ("engines", "platform_intelligence_agent_enabled"),
    "platform_intelligence_timeout_seconds": ("engines", "platform_intelligence_timeout_seconds"),
    "platform_intelligence_max_concurrent": ("engines", "platform_intelligence_max_concurrent"),
    "security_convergence_agent_enabled": ("engines", "security_convergence_agent_enabled"),
    "security_convergence_timeout_seconds": ("engines", "security_convergence_timeout_seconds"),
    "security_convergence_max_concurrent": ("engines", "security_convergence_max_concurrent"),
    "autonomous_defense_agent_enabled": ("engines", "autonomous_defense_agent_enabled"),
    "autonomous_defense_timeout_seconds": ("engines", "autonomous_defense_timeout_seconds"),
    "autonomous_defense_max_concurrent": ("engines", "autonomous_defense_max_concurrent"),
    "crowdstrike_client_id": ("connectors", "crowdstrike_client_id"),
    "crowdstrike_client_secret": ("connectors", "crowdstrike_client_secret"),
    "crowdstrike_base_url": ("connectors", "crowdstrike_base_url"),
    "defender_tenant_id": ("connectors", "defender_tenant_id"),
    "defender_client_id": ("connectors", "defender_client_id"),
    "defender_client_secret": ("connectors", "defender_client_secret"),
    "wiz_client_id": ("connectors", "wiz_client_id"),
    "wiz_client_secret": ("connectors", "wiz_client_secret"),
    "wiz_api_endpoint": ("connectors", "wiz_api_endpoint"),
    "splunk_hec_url": ("connectors", "splunk_hec_url"),
    "splunk_hec_token": ("connectors", "splunk_hec_token"),
    "elastic_cloud_id": ("connectors", "elastic_cloud_id"),
    "newrelic_region": ("connectors", "newrelic_region"),
    "servicenow_instance_url": ("connectors", "servicenow_instance_url"),
    "servicenow_username": ("connectors", "servicenow_username"),
    "servicenow_password": ("connectors", "servicenow_password"),
    "jira_base_url": ("connectors", "jira_base_url"),
    "jira_email": ("connectors", "jira_email"),
    "jira_api_token": ("connectors", "jira_api_token"),
    "opsgenie_api_key": ("connectors", "opsgenie_api_key"),
}


class Settings(BaseSettings):
    """ShieldOps configuration loaded from environment variables."""

    app: AppConfig = AppConfig()
    api: ApiConfig = ApiConfig()
    database: DatabaseConfig = DatabaseConfig()
    redis: RedisConfig = RedisConfig()
    rate_limiting: RateLimitConfig = RateLimitConfig()
    kafka: KafkaConfig = KafkaConfig()
    llm: LlmConfig = LlmConfig()
    agents: AgentConfig = AgentConfig()
    auth: AuthConfig = AuthConfig()
    observability: ObservabilityConfig = ObservabilityConfig()
    connectors: ConnectorsConfig = ConnectorsConfig()
    notifications: NotificationsConfig = NotificationsConfig()
    billing: BillingConfig = BillingConfig()
    scanners: ScannersConfig = ScannersConfig()
    security: SecurityConfig = SecurityConfig()
    engines: EnginesConfig = EnginesConfig()

    @model_validator(mode="before")
    @classmethod
    def _route_flat_to_nested(cls, values: dict) -> dict:  # type: ignore[type-arg]
        """Route flat env vars (e.g. SHIELDOPS_APP_NAME) into nested sub-configs.

        Because the sub-configs are plain ``BaseModel`` (not ``BaseSettings``),
        ``SHIELDOPS_DATABASE_URL`` and friends do NOT reach pydantic-settings
        field mapping — they get dropped by ``extra="ignore"`` before this
        validator runs. Pull them in explicitly from the process environment
        using the same ``SHIELDOPS_`` prefix that ``BaseSettings`` expects.
        """
        if not isinstance(values, dict):
            return values
        for flat_name, (sub, field) in _FLAT_TO_NESTED.items():
            if flat_name not in values:
                env_key = f"SHIELDOPS_{flat_name.upper()}"
                if env_key in os.environ:
                    values[flat_name] = os.environ[env_key]
            if flat_name in values:
                values.setdefault(sub, {})
                if isinstance(values[sub], dict):
                    values[sub][field] = values.pop(flat_name)
        return values

    def __getattr__(self, name: str) -> Any:  # type: ignore[override]
        """Backward-compatible flat attribute access (e.g. settings.anthropic_api_key)."""
        if name in _FLAT_TO_NESTED:
            sub_attr, field_name = _FLAT_TO_NESTED[name]
            return getattr(getattr(self, sub_attr), field_name)
        raise AttributeError(f"Settings has no attribute '{name}'")

    def __setattr__(self, name: str, value: object) -> None:
        """Allow setting flat attributes for backward compatibility (e.g. mock.patch)."""
        if name in _FLAT_TO_NESTED:
            sub_attr, field_name = _FLAT_TO_NESTED[name]
            setattr(getattr(self, sub_attr), field_name, value)
            return
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        """Allow deleting flat attributes for backward compatibility (e.g. mock.patch cleanup)."""
        if name in _FLAT_TO_NESTED:
            # Reset to default - mock.patch calls delattr on cleanup
            sub_attr, field_name = _FLAT_TO_NESTED[name]
            sub_model = getattr(self, sub_attr)
            default_model = type(sub_model)()
            setattr(sub_model, field_name, getattr(default_model, field_name))
            return
        super().__delattr__(name)

    model_config = {
        "env_prefix": "SHIELDOPS_",
        "env_file": ".env",
        "extra": "ignore",
    }


settings = Settings()
