"""Redis configuration."""

from pydantic import BaseModel


class RedisConfig(BaseModel):
    """Redis connection settings."""

    redis_url: str = "redis://localhost:6379/0"
