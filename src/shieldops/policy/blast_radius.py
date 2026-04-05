"""Blast-radius enforcement — limits the number of resources an agent can affect per execution.

Environment limits (non-negotiable):
    - dev:     10 resources max
    - staging:  5 resources max
    - prod:     3 resources max
"""

from __future__ import annotations

import structlog
from pydantic import BaseModel

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Limits per environment
# ---------------------------------------------------------------------------
BLAST_RADIUS_LIMITS: dict[str, int] = {
    "dev": 10,
    "staging": 5,
    "prod": 3,
}

# Fallback for unknown environments — most restrictive
DEFAULT_LIMIT = 3


class BlastRadiusResult(BaseModel):
    """Outcome of a blast-radius check."""

    allowed: bool
    resource_count: int
    limit: int
    environment: str
    reason: str

    model_config = {"extra": "forbid"}


def check_blast_radius(
    environment: str,
    target_resources: list[str],
) -> BlastRadiusResult:
    """Check whether the number of target resources exceeds the environment limit.

    Args:
        environment: Target environment (dev, staging, prod).
        target_resources: List of resource identifiers the agent wants to modify.

    Returns:
        ``BlastRadiusResult`` indicating pass/fail.
    """
    env_lower = environment.lower()
    limit = BLAST_RADIUS_LIMITS.get(env_lower, DEFAULT_LIMIT)
    count = len(target_resources)

    if count > limit:
        reason = (
            f"Blast-radius exceeded: {count} resources targeted "
            f"but {env_lower} environment allows max {limit}."
        )
        logger.warning(
            "blast_radius_exceeded",
            environment=env_lower,
            resource_count=count,
            limit=limit,
        )
        return BlastRadiusResult(
            allowed=False,
            resource_count=count,
            limit=limit,
            environment=env_lower,
            reason=reason,
        )

    return BlastRadiusResult(
        allowed=True,
        resource_count=count,
        limit=limit,
        environment=env_lower,
        reason=f"Within blast-radius limit ({count}/{limit}).",
    )
