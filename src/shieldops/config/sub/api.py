"""API configuration."""

from pydantic import BaseModel


class ApiConfig(BaseModel):
    """API server settings."""

    api_host: str = "0.0.0.0"  # noqa: S104  # nosec B104
    api_port: int = 8000
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = ["http://localhost:3000"]
