"""Unit tests for observability and ITSM connectors."""

from __future__ import annotations

from shieldops.connectors.datadog.connector import DatadogConnector
from shieldops.connectors.jira.connector import JiraConnector
from shieldops.connectors.newrelic.connector import NewRelicConnector
from shieldops.connectors.opsgenie.connector import OpsGenieConnector
from shieldops.connectors.pagerduty.connector import PagerDutyConnector
from shieldops.connectors.servicenow.connector import ServiceNowConnector

# 7 ABC methods from InfraConnector
INFRA_METHODS = [
    "get_health",
    "list_resources",
    "get_events",
    "execute_action",
    "create_snapshot",
    "rollback",
    "validate_health",
]


# ── Datadog ──────────────────────────────────────────────────────────────────


class TestDatadogConnector:
    """Tests for the Datadog observability connector."""

    def test_instantiation(self) -> None:
        conn = DatadogConnector(api_key="dd-api-key", app_key="dd-app-key")
        assert conn is not None
        assert conn.provider == "datadog"

    def test_has_all_infra_methods(self) -> None:
        conn = DatadogConnector(api_key="k")
        for method in INFRA_METHODS:
            assert hasattr(conn, method), f"Missing InfraConnector method: {method}"

    def test_has_platform_methods(self) -> None:
        conn = DatadogConnector(api_key="k")
        platform_methods = [
            "query_metrics",
            "search_logs",
            "get_monitors",
            "create_monitor",
            "get_incidents",
            "submit_metrics",
        ]
        for method in platform_methods:
            assert hasattr(conn, method), f"Missing platform method: {method}"

    def test_default_site(self) -> None:
        conn = DatadogConnector(api_key="k")
        assert conn._site == "datadoghq.com"

    def test_custom_site(self) -> None:
        conn = DatadogConnector(api_key="k", site="datadoghq.eu")
        assert conn._site == "datadoghq.eu"
        assert "datadoghq.eu" in conn._base_url

    def test_snapshot_store(self) -> None:
        conn = DatadogConnector(api_key="k")
        assert isinstance(conn._snapshots, dict)
        assert len(conn._snapshots) == 0

    def test_provider_attribute(self) -> None:
        conn = DatadogConnector(api_key="k")
        assert conn.provider == "datadog"

    def test_auth_headers_configured(self) -> None:
        conn = DatadogConnector(api_key="test-api", app_key="test-app")
        assert conn._api_key == "test-api"
        assert conn._app_key == "test-app"


# ── New Relic ────────────────────────────────────────────────────────────────


class TestNewRelicConnector:
    """Tests for the New Relic observability connector."""

    def test_instantiation(self) -> None:
        conn = NewRelicConnector(api_key="nr-key", account_id="12345")
        assert conn is not None

    def test_provider(self) -> None:
        conn = NewRelicConnector(api_key="k")
        assert conn.provider == "newrelic"

    def test_infra_methods(self) -> None:
        conn = NewRelicConnector(api_key="k")
        for method in INFRA_METHODS:
            assert hasattr(conn, method), f"Missing: {method}"

    def test_platform_methods(self) -> None:
        conn = NewRelicConnector(api_key="k")
        platform_methods = [
            "run_nrql",
            "get_entities",
            "get_alert_policies",
            "create_alert_condition",
            "get_sli_compliance",
            "get_incidents",
        ]
        for method in platform_methods:
            assert hasattr(conn, method), f"Missing: {method}"

    def test_graphql_endpoint(self) -> None:
        us = NewRelicConnector(api_key="k", region="US")
        eu = NewRelicConnector(api_key="k", region="EU")
        assert "api.newrelic.com" in us._graphql_endpoint
        assert "api.eu.newrelic.com" in eu._graphql_endpoint

    def test_default_region(self) -> None:
        conn = NewRelicConnector(api_key="k")
        assert conn._region == "US"

    def test_account_id_stored(self) -> None:
        conn = NewRelicConnector(api_key="k", account_id="99999")
        assert conn._account_id == "99999"


# ── PagerDuty ────────────────────────────────────────────────────────────────


class TestPagerDutyConnector:
    """Tests for the PagerDuty incident management connector."""

    def test_instantiation(self) -> None:
        conn = PagerDutyConnector(api_key="pd-key")
        assert conn is not None

    def test_provider(self) -> None:
        conn = PagerDutyConnector(api_key="k")
        assert conn.provider == "pagerduty"

    def test_infra_methods(self) -> None:
        conn = PagerDutyConnector(api_key="k")
        for method in INFRA_METHODS:
            assert hasattr(conn, method), f"Missing: {method}"

    def test_platform_methods(self) -> None:
        conn = PagerDutyConnector(api_key="k")
        platform_methods = [
            "get_incidents",
            "create_incident",
            "get_services",
            "get_oncall",
            "trigger_event",
            "get_escalation_policies",
        ]
        for method in platform_methods:
            assert hasattr(conn, method), f"Missing: {method}"

    def test_routing_key_stored(self) -> None:
        conn = PagerDutyConnector(api_key="k", routing_key="rk-123")
        assert conn._routing_key == "rk-123"

    def test_base_url(self) -> None:
        conn = PagerDutyConnector(api_key="k")
        headers = conn._auth_headers()
        assert "Token token=" in headers["Authorization"]

    def test_snapshot_store(self) -> None:
        conn = PagerDutyConnector(api_key="k")
        assert isinstance(conn._snapshots, dict)


# ── ServiceNow ───────────────────────────────────────────────────────────────


class TestServiceNowConnector:
    """Tests for the ServiceNow ITSM connector."""

    def test_instantiation(self) -> None:
        conn = ServiceNowConnector(instance_url="https://dev12345.service-now.com")
        assert conn is not None

    def test_provider(self) -> None:
        conn = ServiceNowConnector(instance_url="https://x.service-now.com")
        assert conn.provider == "servicenow"

    def test_infra_methods(self) -> None:
        conn = ServiceNowConnector(instance_url="https://x.service-now.com")
        for method in INFRA_METHODS:
            assert hasattr(conn, method), f"Missing: {method}"

    def test_platform_methods(self) -> None:
        conn = ServiceNowConnector(instance_url="https://x.service-now.com")
        platform_methods = [
            "get_incidents",
            "create_incident",
            "get_change_requests",
            "create_change_request",
            "query_cmdb",
            "update_record",
        ]
        for method in platform_methods:
            assert hasattr(conn, method), f"Missing: {method}"

    def test_instance_url_stored(self) -> None:
        conn = ServiceNowConnector(instance_url="https://dev12345.service-now.com/")
        assert conn._instance_url == "https://dev12345.service-now.com"

    def test_auth_stored(self) -> None:
        conn = ServiceNowConnector(
            instance_url="https://x.service-now.com",
            username="admin",
            password="secret",
        )
        assert conn._username == "admin"
        assert conn._password == "secret"

    def test_snapshot_store(self) -> None:
        conn = ServiceNowConnector(instance_url="https://x.service-now.com")
        assert isinstance(conn._snapshots, dict)


# ── Jira ─────────────────────────────────────────────────────────────────────


class TestJiraConnector:
    """Tests for the Jira issue tracking connector."""

    def test_instantiation(self) -> None:
        conn = JiraConnector(base_url="https://myorg.atlassian.net")
        assert conn is not None

    def test_provider(self) -> None:
        conn = JiraConnector(base_url="https://x.atlassian.net")
        assert conn.provider == "jira"

    def test_infra_methods(self) -> None:
        conn = JiraConnector(base_url="https://x.atlassian.net")
        for method in INFRA_METHODS:
            assert hasattr(conn, method), f"Missing: {method}"

    def test_platform_methods(self) -> None:
        conn = JiraConnector(base_url="https://x.atlassian.net")
        platform_methods = [
            "search_jql",
            "create_issue",
            "transition_issue",
            "add_comment",
            "get_projects",
            "get_transitions",
        ]
        for method in platform_methods:
            assert hasattr(conn, method), f"Missing: {method}"

    def test_base_url_stored(self) -> None:
        conn = JiraConnector(base_url="https://myorg.atlassian.net/")
        assert conn._base_url == "https://myorg.atlassian.net"

    def test_auth_stored(self) -> None:
        conn = JiraConnector(
            base_url="https://x.atlassian.net",
            email="user@example.com",
            api_token="tok-123",
        )
        assert conn._email == "user@example.com"
        assert conn._api_token == "tok-123"

    def test_snapshot_store(self) -> None:
        conn = JiraConnector(base_url="https://x.atlassian.net")
        assert isinstance(conn._snapshots, dict)


# ── OpsGenie ─────────────────────────────────────────────────────────────────


class TestOpsGenieConnector:
    """Tests for the OpsGenie alert management connector."""

    def test_instantiation(self) -> None:
        conn = OpsGenieConnector(api_key="og-key")
        assert conn is not None

    def test_provider(self) -> None:
        conn = OpsGenieConnector(api_key="k")
        assert conn.provider == "opsgenie"

    def test_infra_methods(self) -> None:
        conn = OpsGenieConnector(api_key="k")
        for method in INFRA_METHODS:
            assert hasattr(conn, method), f"Missing: {method}"

    def test_platform_methods(self) -> None:
        conn = OpsGenieConnector(api_key="k")
        platform_methods = [
            "get_alerts",
            "create_alert",
            "acknowledge_alert",
            "close_alert",
            "get_teams",
            "get_schedules",
            "get_oncall",
        ]
        for method in platform_methods:
            assert hasattr(conn, method), f"Missing: {method}"

    def test_api_key_stored(self) -> None:
        conn = OpsGenieConnector(api_key="my-genie-key")
        assert conn._api_key == "my-genie-key"

    def test_default_base_url(self) -> None:
        conn = OpsGenieConnector(api_key="k")
        assert conn._base_url == "https://api.opsgenie.com"

    def test_snapshot_store(self) -> None:
        conn = OpsGenieConnector(api_key="k")
        assert isinstance(conn._snapshots, dict)
