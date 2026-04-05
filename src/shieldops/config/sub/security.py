"""Security configuration."""

from pydantic import BaseModel


class SecurityConfig(BaseModel):
    """Vault, secret management, and security settings."""

    vault_addr: str = ""
    vault_token: str = ""
    vault_mount_point: str = "secret"
    vault_namespace: str = ""
    gcp_secret_manager_enabled: bool = False
    azure_keyvault_url: str = ""
    github_advisory_token: str = ""
