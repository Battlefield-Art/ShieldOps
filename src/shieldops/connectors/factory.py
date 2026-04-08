"""Factory for creating a ConnectorRouter with registered infrastructure connectors."""

import structlog

from shieldops.config import Settings
from shieldops.connectors.base import ConnectorRouter
from shieldops.connectors.kubernetes.connector import KubernetesConnector

logger = structlog.get_logger()


def create_connector_router(settings: Settings) -> ConnectorRouter:
    """Create a ConnectorRouter with all configured infrastructure connectors.

    Kubernetes is always registered (falls back to in-cluster config).
    AWS/GCP/Azure connectors will be added when those modules are implemented.

    Args:
        settings: Application settings (used for future cloud connector config).

    Returns:
        A ConnectorRouter with registered connectors.
    """
    router = ConnectorRouter()

    # Kubernetes is always available — falls back to in-cluster config
    k8s = KubernetesConnector()
    router.register(k8s)
    logger.info("connector_registered", provider="kubernetes")

    # AWS — registered when aws_region is configured
    if settings.aws_region:
        from shieldops.connectors.aws.connector import AWSConnector

        aws = AWSConnector(region=settings.aws_region)
        router.register(aws)
        logger.info("connector_registered", provider="aws")

    # Linux SSH — registered when linux_host is configured
    if settings.linux_host:
        from shieldops.connectors.linux.connector import LinuxConnector

        linux = LinuxConnector(
            host=settings.linux_host,
            username=settings.linux_username,
            private_key_path=settings.linux_private_key_path or None,
        )
        router.register(linux)
        logger.info("connector_registered", provider="linux")

    # GCP — registered when gcp_project_id is configured
    if settings.gcp_project_id:
        from shieldops.connectors.gcp.connector import GCPConnector

        gcp = GCPConnector(
            project_id=settings.gcp_project_id,
            region=settings.gcp_region,
        )
        router.register(gcp)
        logger.info("connector_registered", provider="gcp")

    # Azure — registered when azure_subscription_id is configured
    if settings.azure_subscription_id:
        from shieldops.connectors.azure.connector import AzureConnector

        azure = AzureConnector(
            subscription_id=settings.azure_subscription_id,
            resource_group=settings.azure_resource_group,
            location=settings.azure_location,
        )
        router.register(azure)
        logger.info("connector_registered", provider="azure")

    # Windows WinRM — registered when windows_host is configured
    if settings.windows_host:
        from shieldops.connectors.windows.connector import WindowsConnector

        windows = WindowsConnector(
            host=settings.windows_host,
            username=settings.windows_username,
            password=settings.windows_password,
            use_ssl=settings.windows_use_ssl,
            port=settings.windows_port,
        )
        router.register(windows)
        logger.info("connector_registered", provider="windows")

    # CrowdStrike — registered when crowdstrike_client_id is configured
    if settings.crowdstrike_client_id:
        from shieldops.connectors.crowdstrike.connector import CrowdStrikeConnector

        crowdstrike = CrowdStrikeConnector(
            client_id=settings.crowdstrike_client_id,
            client_secret=settings.crowdstrike_client_secret,
            base_url=settings.crowdstrike_base_url,
        )
        router.register(crowdstrike)
        logger.info("connector_registered", provider="crowdstrike")

    # Microsoft Defender — registered when defender_tenant_id is configured
    if settings.defender_tenant_id:
        from shieldops.connectors.defender.connector import DefenderConnector

        defender = DefenderConnector(
            tenant_id=settings.defender_tenant_id,
            client_id=settings.defender_client_id,
            client_secret=settings.defender_client_secret,
        )
        router.register(defender)
        logger.info("connector_registered", provider="defender")

    # Wiz — registered when wiz_client_id is configured
    if settings.wiz_client_id:
        from shieldops.connectors.wiz.connector import WizConnector

        wiz = WizConnector(
            client_id=settings.wiz_client_id,
            client_secret=settings.wiz_client_secret,
            api_url=settings.wiz_api_endpoint,
        )
        router.register(wiz)
        logger.info("connector_registered", provider="wiz")

    # Splunk — registered when splunk_url is configured
    if settings.splunk_url:
        from shieldops.connectors.splunk.connector import SplunkConnector

        splunk = SplunkConnector(
            base_url=settings.splunk_url,
            token=settings.splunk_token,
            hec_url=settings.splunk_hec_url,
            hec_token=settings.splunk_hec_token,
        )
        router.register(splunk)
        logger.info("connector_registered", provider="splunk")

    # Elastic — registered when elastic_url is configured
    if settings.elastic_url:
        from shieldops.connectors.elastic.connector import ElasticConnector

        elastic = ElasticConnector(
            url=settings.elastic_url,
            api_key=settings.elastic_api_key,
            cloud_id=settings.elastic_cloud_id,
        )
        router.register(elastic)
        logger.info("connector_registered", provider="elastic")

    # Datadog — registered when datadog_api_key is configured
    if settings.datadog_api_key:
        from shieldops.connectors.datadog.connector import DatadogConnector

        dd = DatadogConnector(
            api_key=settings.datadog_api_key,
            app_key=settings.datadog_app_key,
            site=settings.datadog_site,
        )
        router.register(dd)
        logger.info("connector_registered", provider="datadog")

    # New Relic — registered when newrelic_api_key is configured
    if settings.newrelic_api_key:
        from shieldops.connectors.newrelic.connector import NewRelicConnector

        nr = NewRelicConnector(
            api_key=settings.newrelic_api_key,
            account_id=settings.newrelic_account_id,
            region=settings.newrelic_region,
        )
        router.register(nr)
        logger.info("connector_registered", provider="newrelic")

    # PagerDuty — registered when pagerduty_api_key is configured
    if settings.pagerduty_api_key:
        from shieldops.connectors.pagerduty.connector import PagerDutyConnector

        pd_conn = PagerDutyConnector(
            api_key=settings.pagerduty_api_key,
            routing_key=getattr(settings, "pagerduty_routing_key", ""),
        )
        router.register(pd_conn)
        logger.info("connector_registered", provider="pagerduty")

    # ServiceNow — registered when servicenow_instance_url is configured
    if settings.servicenow_instance_url:
        from shieldops.connectors.servicenow.connector import ServiceNowConnector

        snow = ServiceNowConnector(
            instance_url=settings.servicenow_instance_url,
            username=settings.servicenow_username,
            password=settings.servicenow_password,
        )
        router.register(snow)
        logger.info("connector_registered", provider="servicenow")

    # Jira — registered when jira_base_url is configured
    if settings.jira_base_url:
        from shieldops.connectors.jira.connector import JiraConnector

        jira = JiraConnector(
            base_url=settings.jira_base_url,
            email=settings.jira_email,
            api_token=settings.jira_api_token,
        )
        router.register(jira)
        logger.info("connector_registered", provider="jira")

    # OpsGenie — registered when opsgenie_api_key is configured
    if settings.opsgenie_api_key:
        from shieldops.connectors.opsgenie.connector import OpsGenieConnector

        og = OpsGenieConnector(api_key=settings.opsgenie_api_key)
        router.register(og)
        logger.info("connector_registered", provider="opsgenie")

    logger.info("connector_router_ready", providers=router.providers)
    return router
