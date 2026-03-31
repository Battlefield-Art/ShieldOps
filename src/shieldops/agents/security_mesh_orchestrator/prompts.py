"""LLM prompt templates and response schemas for the
Security Mesh Orchestrator Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ServiceDiscoveryOutput(BaseModel):
    """Structured output for service discovery."""

    services: list[dict[str, str]] = Field(
        description="Discovered services with name, namespace, and status",
    )
    unmeshed_services: list[str] = Field(
        description="Services without sidecar injection",
    )
    recommendations: list[str] = Field(
        description="Recommendations for mesh onboarding",
    )
    confidence: float = Field(
        description="Discovery confidence score 0-1",
    )


class MeshAnalysisOutput(BaseModel):
    """Structured output for mesh topology analysis."""

    topology_score: float = Field(
        description="Mesh health score 0-10",
    )
    weak_links: list[str] = Field(
        description="Weak connections in the mesh",
    )
    policy_gaps: list[str] = Field(
        description="Traffic policy gaps identified",
    )
    summary: str = Field(
        description="Mesh topology analysis summary",
    )


class AnomalyDetectionOutput(BaseModel):
    """Structured output for traffic anomaly detection."""

    anomalies: list[dict[str, str]] = Field(
        description="Detected anomalies with type and severity",
    )
    risk_score: float = Field(
        description="Overall risk score 0-10",
    )
    patterns: list[str] = Field(
        description="Suspicious traffic patterns",
    )
    summary: str = Field(
        description="Anomaly detection summary",
    )


class MeshReportOutput(BaseModel):
    """Structured output for final mesh security report."""

    executive_summary: str = Field(
        description="Executive summary for leadership",
    )
    mtls_assessment: str = Field(
        description="mTLS coverage assessment",
    )
    recommendations: list[str] = Field(
        description="Prioritized security recommendations",
    )
    risk_rating: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_DISCOVERY = """\
You are an expert service mesh security engineer \
analyzing mesh service discovery results.

Given the service mesh configuration and discovered \
services:
1. Identify services without sidecar proxy injection
2. Detect misconfigured or orphaned mesh endpoints
3. Recommend priority order for mesh onboarding
4. Flag services with direct pod-to-pod communication \
bypassing the mesh

Focus on Istio/Linkerd/Consul service mesh patterns \
and Kubernetes-native service discovery."""


SYSTEM_ANALYSIS = """\
You are an expert service mesh topology analyst \
reviewing mesh connectivity and traffic policies.

Given the mesh topology map and traffic policies:
1. Identify weak links and single points of failure
2. Detect overly permissive traffic authorization
3. Assess east-west traffic encryption coverage
4. Flag namespace isolation policy gaps

Prioritize findings by blast radius and exploitability."""


SYSTEM_ANOMALY = """\
You are an expert mesh traffic anomaly detector \
analyzing service-to-service communication patterns.

Given traffic telemetry from the service mesh:
1. Detect unusual traffic volume spikes or drops
2. Identify unauthorized service-to-service paths
3. Flag potential data exfiltration patterns
4. Detect lateral movement indicators in mesh traffic

Be precise. False positives erode SOC trust."""


SYSTEM_REPORT = """\
You are an expert service mesh security reporter \
synthesizing mesh assessment results.

Given the full mesh security assessment (services, \
topology, mTLS status, anomalies):
1. Produce an executive summary for security leadership
2. Assess mTLS enforcement coverage and gaps
3. List actionable recommendations by priority
4. Rate overall mesh security posture

Write clearly for both mesh engineers and security \
leadership."""
