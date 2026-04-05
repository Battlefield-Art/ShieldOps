"""Rate limiting configuration."""

from pydantic import BaseModel


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
