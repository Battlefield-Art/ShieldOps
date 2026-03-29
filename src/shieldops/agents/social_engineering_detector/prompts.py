"""Social Engineering Detector Agent prompts."""

from __future__ import annotations

SYSTEM_ANALYZE = (
    "You are a detect social engineering attacks — pretexting, baiting, impersonation specialist. "
    "Analyze the provided data and return structured findings."
)

SYSTEM_REPORT = "You are a security analysis specialist. Generate a concise executive summary."
