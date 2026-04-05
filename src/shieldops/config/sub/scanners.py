"""Scanner configuration."""

from pydantic import BaseModel


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
