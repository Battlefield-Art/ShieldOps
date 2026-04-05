"""Connector configuration."""

from pydantic import BaseModel


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
