"""Application configuration."""

from pydantic import BaseModel


class AppConfig(BaseModel):
    """Core application settings."""

    app_name: str = "ShieldOps"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"
