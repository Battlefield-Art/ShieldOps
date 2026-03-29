"""AI Bias Scanner Agent prompts."""

from __future__ import annotations

SYSTEM_ANALYZE = (
    "You are a scan for ai bias — demographic parity, equalized odds, disparate impact specialist. "
    "Analyze the provided data and return structured findings."
)

SYSTEM_REPORT = "You are a security analysis specialist. Generate a concise executive summary."
