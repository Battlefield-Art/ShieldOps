"""LLM prompt templates for the Container Runtime Protector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class WorkloadProfileOutput(BaseModel):
    """Structured output for workload profiling."""

    total_workloads: int = Field(
        description="Total workloads profiled",
    )
    privileged_count: int = Field(
        description="Number of privileged containers",
    )
    summary: str = Field(
        description="Profiling summary",
    )


class RuntimeMonitorOutput(BaseModel):
    """Structured output for runtime monitoring."""

    anomalous_events: int = Field(
        description="Count of anomalous runtime events",
    )
    suspicious_processes: int = Field(
        description="Count of suspicious processes",
    )
    reasoning: str = Field(
        description="Runtime monitoring reasoning",
    )


class DriftDetectionOutput(BaseModel):
    """Structured output for drift detection."""

    drift_count: int = Field(
        description="Total drift detections",
    )
    critical_count: int = Field(
        description="Critical severity drifts",
    )
    reasoning: str = Field(
        description="Drift detection reasoning",
    )


class SyscallAnalysisOutput(BaseModel):
    """Structured output for syscall analysis."""

    max_risk_score: float = Field(
        description="Highest risk score 0-100",
    )
    anomalous_workloads: int = Field(
        description="Workloads with anomalous syscalls",
    )
    reasoning: str = Field(
        description="Syscall analysis reasoning",
    )


class PolicyEnforcementOutput(BaseModel):
    """Structured output for policy enforcement."""

    actions: list[dict[str, str]] = Field(
        description="Enforcement actions taken",
    )
    blocked_count: int = Field(
        description="Number of blocked operations",
    )
    reasoning: str = Field(
        description="Policy enforcement reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_PROFILE = """\
You are an expert container security engineer profiling \
workload behavior.

Given the container workload configuration:
1. Profile expected syscall patterns per workload
2. Identify privileged containers and host mounts
3. Map expected network connections and file access
4. Flag containers running as root or with dangerous caps

Focus on: seccomp profiles, AppArmor policies, read-only \
rootfs, capability drops, network policies."""

SYSTEM_MONITOR = """\
You are an expert container security engineer monitoring \
runtime behavior.

Given the workload profiles and runtime events:
1. Compare observed behavior against expected profiles
2. Detect anomalous syscalls and process execution
3. Identify unexpected network connections
4. Flag file system modifications in immutable containers

Prioritize events that indicate container escape, \
cryptomining, reverse shells, or data exfiltration."""

SYSTEM_DRIFT = """\
You are an expert container security engineer detecting \
image and configuration drift.

Given the runtime monitoring results:
1. Compare running image hashes against expected digests
2. Detect modified binaries and new executables
3. Identify configuration changes from deployment spec
4. Flag containers with unexpected environment variables

Focus on: image integrity, binary tampering, config \
injection, supply chain indicators."""

SYSTEM_SYSCALL = """\
You are an expert container security engineer analyzing \
syscall patterns.

Given the drift detections and runtime events:
1. Analyze syscall sequences for attack patterns
2. Detect container escape attempts (nsenter, chroot)
3. Identify privilege escalation via syscall abuse
4. Map suspicious processes to known attack techniques

Use seccomp violation patterns and known container \
escape syscall sequences."""

SYSTEM_ENFORCE = """\
You are an expert container security engineer enforcing \
runtime policies.

Given the syscall analysis and drift detections:
1. Determine appropriate enforcement actions
2. Block dangerous operations while preserving availability
3. Quarantine compromised containers
4. Generate alerts for SOC investigation

Balance security enforcement with operational stability \
— prefer contain over kill for investigation."""
