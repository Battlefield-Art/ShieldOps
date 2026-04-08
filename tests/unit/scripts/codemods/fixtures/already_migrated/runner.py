"""Runner for already_migrated — should be skipped because agent.py exists."""

from __future__ import annotations


class AlreadyMigratedRunner:
    async def run(self) -> None:
        return None
