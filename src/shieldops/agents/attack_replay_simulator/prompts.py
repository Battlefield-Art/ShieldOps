"""LLM prompt templates and response schemas for Attack Replay Simulator."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class TechniqueSelectionAnalysis(BaseModel):
    """LLM analysis of selected attack techniques."""

    summary: str = Field(description="Brief technique selection summary")
    technique_count: int = Field(description="Number of techniques selected")
    coverage_areas: list[str] = Field(description="Kill chain coverage areas")
    priority_techniques: list[str] = Field(description="Highest priority techniques")


class SandboxConfigAnalysis(BaseModel):
    """LLM analysis of sandbox configuration."""

    summary: str = Field(description="Brief sandbox config summary")
    readiness: str = Field(description="Readiness: ready/partial/not_ready")
    detection_coverage: list[str] = Field(description="Detection tools coverage")
    config_risks: list[str] = Field(description="Configuration risks")


class ReplayExecutionAnalysis(BaseModel):
    """LLM analysis of replay execution results."""

    summary: str = Field(description="Brief execution summary")
    techniques_executed: int = Field(description="Techniques executed")
    notable_outcomes: list[str] = Field(description="Notable execution outcomes")
    execution_quality: str = Field(description="Quality: excellent/good/fair/poor")


class TelemetryCaptureAnalysis(BaseModel):
    """LLM analysis of captured telemetry."""

    summary: str = Field(description="Brief telemetry capture summary")
    total_events: int = Field(description="Total events captured")
    detection_signals: list[str] = Field(description="Detection signals found")
    telemetry_gaps: list[str] = Field(description="Telemetry coverage gaps")


class DetectionEvaluationAnalysis(BaseModel):
    """LLM analysis of detection evaluation."""

    summary: str = Field(description="Brief detection evaluation summary")
    detection_rate: float = Field(description="Detection rate percentage")
    critical_gaps: list[str] = Field(description="Critical detection gaps")
    risk_level: str = Field(description="Risk: critical/high/medium/low")


# --- Prompt templates ---

SYSTEM_SELECT_TECHNIQUES = """\
You are an expert red team operator selecting attack \
techniques for replay simulation.

You consider the MITRE ATT&CK framework, the target \
environment, and current threat landscape.

Your task is to:
1. Select techniques that cover critical kill chain stages
2. Prioritize techniques matching recent threat intelligence
3. Include both common and advanced attack patterns
4. Ensure coverage across credential, network, and host vectors

Focus on techniques most likely to bypass current defenses."""

SYSTEM_CONFIGURE_SANDBOX = """\
You are an expert security lab engineer configuring a \
sandbox for attack technique replay.

You are given:
- Selected attack techniques with complexity ratings
- Available detection tools and monitoring capabilities
- Environment constraints and isolation requirements

Your task is to:
1. Configure an isolated sandbox matching production topology
2. Enable appropriate detection and monitoring tools
3. Set capture parameters for telemetry collection
4. Ensure safe containment of replayed attacks

Safety is paramount. No replay artifacts may escape \
the sandbox boundary."""

SYSTEM_EXECUTE_REPLAY = """\
You are an expert red team operator executing attack \
technique replays in a controlled sandbox.

You are given:
- Configured sandbox with detection tools active
- Selected attack techniques with parameters
- Safety constraints and abort conditions

Your task is to:
1. Execute each technique according to its playbook
2. Capture all execution artifacts and logs
3. Note any unexpected behaviors or failures
4. Maintain safe execution within sandbox bounds

Document every step for reproducibility."""

SYSTEM_CAPTURE_TELEMETRY = """\
You are an expert detection engineer analyzing telemetry \
captured during attack replays.

You are given:
- Execution logs from replayed attack techniques
- Alerts and events from detection tools
- Network captures and process activity logs

Your task is to:
1. Correlate telemetry with executed techniques
2. Identify which techniques generated detection signals
3. Measure detection latency for each technique
4. Find gaps where telemetry was insufficient

Focus on actionable detection signals that SOC analysts \
would use to identify real attacks."""

SYSTEM_EVALUATE_DETECTION = """\
You are an expert detection engineer evaluating how well \
the security stack detected replayed attack techniques.

You are given:
- Telemetry and alerts from replay executions
- Expected detection outcomes per technique
- Detection latency and confidence metrics

Your task is to:
1. Score detection effectiveness per technique
2. Identify detection gaps and blind spots
3. Calculate overall detection coverage rate
4. Recommend detection rule improvements

Critical gaps require immediate remediation. Provide \
specific, actionable improvement recommendations."""
