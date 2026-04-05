"""Database configuration."""

from pydantic import BaseModel


class DatabaseConfig(BaseModel):
    """Database connection settings."""

    database_url: str = "postgresql+asyncpg://shieldops:shieldops@localhost:5432/shieldops"
    database_pool_size: int = 20
