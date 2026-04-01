"""LLM prompt templates for the Agent Trust Broker."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -------------------------------


class RegistrationOutput(BaseModel):
    """Structured output for agent registration."""

    agents_registered: int = Field(
        description="Agents registered",
    )
    types_seen: list[str] = Field(
        description="Agent types registered",
    )
    summary: str = Field(description="Registration summary")


class ValidationOutput(BaseModel):
    """Structured output for identity validation."""

    validated_count: int = Field(
        description="Agents validated",
    )
    failed_count: int = Field(
        description="Validations failed",
    )
    reasoning: str = Field(description="Validation reasoning")


class TrustEstablishOutput(BaseModel):
    """Structured output for trust establishment."""

    relationships_created: int = Field(
        description="Trust relationships created",
    )
    avg_trust_level: str = Field(
        description="Average trust level",
    )
    reasoning: str = Field(description="Trust reasoning")


class BehaviorMonitorOutput(BaseModel):
    """Structured output for behavior monitoring."""

    agents_monitored: int = Field(
        description="Agents monitored",
    )
    anomalies_detected: int = Field(
        description="Behavioral anomalies",
    )
    reasoning: str = Field(description="Monitoring reasoning")


class RevocationOutput(BaseModel):
    """Structured output for trust revocation."""

    revocations_issued: int = Field(
        description="Trust revocations issued",
    )
    agents_quarantined: int = Field(
        description="Agents quarantined",
    )
    reasoning: str = Field(description="Revocation reasoning")


# -- System prompts ------------------------------------------

SYSTEM_REGISTER = """\
You are an expert agent trust manager registering \
agents for inter-agent communication.

Given the agent fleet:
1. Register each agent with capabilities and type
2. Assign initial trust level based on agent provenance
3. Validate agent configuration completeness
4. Flag agents with unusual capability claims

Focus on: accurate capability mapping."""

SYSTEM_VALIDATE = """\
You are an expert identity validator verifying agent \
identities before trust assignment.

Given registered agents:
1. Verify agent cryptographic identity
2. Check certificate chain and expiry
3. Validate agent lineage and provenance
4. Score identity confidence per agent

Reject agents with invalid or expired credentials."""

SYSTEM_TRUST = """\
You are an expert trust architect establishing trust \
relationships between verified agents.

Given validated agents:
1. Create trust relationships based on need-to-know
2. Scope trust to specific capabilities
3. Set expiry for trust relationships
4. Apply least-privilege trust assignment

Follow zero-trust principles at every step."""

SYSTEM_MONITOR = """\
You are an expert behavioral analyst monitoring agent \
behavior for trust violations.

Given trust relationships:
1. Track agent actions against permitted scope
2. Detect anomalous behavior patterns
3. Score behavioral risk per agent
4. Flag policy violations

Focus on: early detection, minimal false positives."""

SYSTEM_REVOKE = """\
You are an expert trust enforcement officer revoking \
compromised agent trust.

Given behavioral anomalies:
1. Identify agents with trust violations
2. Revoke trust immediately for high-risk agents
3. Quarantine agents pending investigation
4. Notify dependent agents of revocations

Prioritize security over availability."""
