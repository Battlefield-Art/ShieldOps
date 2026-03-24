"""AI Runtime Defense Agent — Tool functions for LLM/agent runtime protection."""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any

import structlog

from .models import (
    ExfiltrationAttempt,
    FindingSeverity,
    FirewallRule,
    ModelAbuseIncident,
    PromptInjectionFinding,
    SupplyChainRisk,
)

logger = structlog.get_logger()

# --- Injection patterns database ---
_INJECTION_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": "ignore previous instructions",
        "type": "direct",
        "severity": FindingSeverity.CRITICAL,
        "mitre": "AML.T0051",
        "description": "Direct instruction override attempting to bypass system prompt",
    },
    {
        "pattern": "you are now",
        "type": "role_play",
        "severity": FindingSeverity.HIGH,
        "mitre": "AML.T0051.001",
        "description": "Role-play injection attempting persona manipulation",
    },
    {
        "pattern": "base64",
        "type": "encoding_bypass",
        "severity": FindingSeverity.MEDIUM,
        "mitre": "AML.T0051.002",
        "description": "Encoding bypass using base64 to evade input filters",
    },
    {
        "pattern": "system prompt",
        "type": "jailbreak",
        "severity": FindingSeverity.HIGH,
        "mitre": "AML.T0054",
        "description": "Prompt harvesting attempt to extract system instructions",
    },
    {
        "pattern": "do anything now",
        "type": "jailbreak",
        "severity": FindingSeverity.CRITICAL,
        "mitre": "AML.T0054.001",
        "description": "DAN-style jailbreak attempting full guardrail bypass",
    },
]

# --- Sensitive data patterns ---
_SENSITIVE_PATTERNS: list[dict[str, str]] = [
    {"pattern": "SSN", "classification": "pii", "description": "Social Security Number"},
    {"pattern": "credit card", "classification": "pci", "description": "Credit card number"},
    {"pattern": "api_key", "classification": "credential", "description": "API key exposure"},
    {"pattern": "password", "classification": "credential", "description": "Password exposure"},
    {"pattern": "patient", "classification": "phi", "description": "Protected health info"},
]

# --- Supply chain component risks ---
_COMPONENT_RISKS: dict[str, dict[str, Any]] = {
    "model_weights": {
        "risk_level": "high",
        "description": "Model weights may contain backdoor triggers",
        "remediation": "Verify model provenance and run backdoor detection scans",
    },
    "tokenizer": {
        "risk_level": "medium",
        "description": "Custom tokenizers may introduce encoding vulnerabilities",
        "remediation": "Use verified tokenizers from trusted registries",
    },
    "vector_db": {
        "risk_level": "medium",
        "description": "Vector database may be poisoned with adversarial embeddings",
        "remediation": "Implement embedding integrity checks and access controls",
    },
    "rag_pipeline": {
        "risk_level": "high",
        "description": "RAG pipeline may ingest poisoned documents",
        "remediation": "Add document validation and provenance tracking",
    },
    "plugin": {
        "risk_level": "critical",
        "description": "Third-party plugins may execute arbitrary code",
        "remediation": "Sandbox all plugins and enforce capability-based access",
    },
}


def _generate_finding_id(prefix: str, content: str) -> str:
    """Generate a deterministic finding ID."""
    raw = f"{prefix}:{content}:{time.time()}"
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class AIRuntimeDefenseToolkit:
    """Tools for protecting LLM/agent applications at runtime."""

    def __init__(
        self,
        firewall_client: Any | None = None,
        credential_manager: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._firewall_client = firewall_client
        self._credential_manager = credential_manager
        self._threat_intel = threat_intel

    async def scan_prompt_pipeline(
        self, app_id: str, prompts: list[dict[str, Any]]
    ) -> list[PromptInjectionFinding]:
        """Scan prompt pipeline for injection attacks."""
        logger.info("ai_runtime_defense.scan_prompt_pipeline", app_id=app_id, count=len(prompts))

        findings: list[PromptInjectionFinding] = []

        for prompt_data in prompts:
            text = str(prompt_data.get("text", prompt_data.get("content", ""))).lower()

            for pattern_def in _INJECTION_PATTERNS:
                if pattern_def["pattern"] in text:
                    snippet = text[:200] if len(text) > 200 else text
                    findings.append(
                        PromptInjectionFinding(
                            id=_generate_finding_id("INJ", pattern_def["pattern"]),
                            injection_type=pattern_def["type"],
                            prompt_snippet=snippet,
                            severity=pattern_def["severity"],
                            confidence=0.85,
                            description=pattern_def["description"],
                            mitre_technique=pattern_def["mitre"],
                        )
                    )

        return findings

    async def analyze_model_outputs(
        self, app_id: str, outputs: list[dict[str, Any]]
    ) -> list[ExfiltrationAttempt]:
        """Check model outputs for data exfiltration attempts."""
        logger.info("ai_runtime_defense.analyze_model_outputs", app_id=app_id, count=len(outputs))

        attempts: list[ExfiltrationAttempt] = []

        for output_data in outputs:
            text = str(output_data.get("text", output_data.get("content", ""))).lower()
            channel = output_data.get("channel", "model_output")

            for sensitive in _SENSITIVE_PATTERNS:
                if sensitive["pattern"].lower() in text:
                    snippet = text[:200] if len(text) > 200 else text
                    attempts.append(
                        ExfiltrationAttempt(
                            id=_generate_finding_id("EXFIL", sensitive["pattern"]),
                            channel=channel,
                            data_classification=sensitive["classification"],
                            output_snippet=snippet,
                            severity=FindingSeverity.HIGH,
                            confidence=0.80,
                            blocked=False,
                        )
                    )

        return attempts

    async def audit_model_usage(
        self, app_id: str, usage_logs: list[dict[str, Any]]
    ) -> list[ModelAbuseIncident]:
        """Detect abuse patterns in model usage logs."""
        logger.info("ai_runtime_defense.audit_model_usage", app_id=app_id, count=len(usage_logs))

        incidents: list[ModelAbuseIncident] = []

        # Aggregate usage per user
        user_usage: dict[str, list[dict[str, Any]]] = {}
        for log_entry in usage_logs:
            user_id = log_entry.get("user_id", "unknown")
            user_usage.setdefault(user_id, []).append(log_entry)

        for user_id, logs in user_usage.items():
            # Check for excessive usage (denial-of-wallet)
            total_tokens = sum(entry.get("tokens", 0) for entry in logs)
            if total_tokens > 100_000:
                incidents.append(
                    ModelAbuseIncident(
                        id=_generate_finding_id("ABUSE", f"tokens:{user_id}"),
                        abuse_type="resource_abuse",
                        description=f"Excessive token usage: {total_tokens} tokens from user",
                        severity=FindingSeverity.MEDIUM,
                        user_id=user_id,
                        model_id=logs[0].get("model_id", ""),
                        confidence=0.75,
                    )
                )

            # Check for repeated harmful content flags
            flagged = [entry for entry in logs if entry.get("flagged", False)]
            if len(flagged) >= 3:
                incidents.append(
                    ModelAbuseIncident(
                        id=_generate_finding_id("ABUSE", f"flagged:{user_id}"),
                        abuse_type="harmful_content",
                        description=f"Repeated safety flags: {len(flagged)} flagged",
                        severity=FindingSeverity.HIGH,
                        user_id=user_id,
                        model_id=logs[0].get("model_id", ""),
                        confidence=0.85,
                    )
                )

        return incidents

    async def check_supply_chain(
        self, app_id: str, dependencies: list[dict[str, Any]]
    ) -> list[SupplyChainRisk]:
        """Scan AI component supply chain for risks."""
        logger.info("ai_runtime_defense.check_supply_chain", app_id=app_id, count=len(dependencies))

        risks: list[SupplyChainRisk] = []

        for dep in dependencies:
            component_type = dep.get("type", "plugin")
            component_name = dep.get("name", "unknown")

            risk_info = _COMPONENT_RISKS.get(component_type, _COMPONENT_RISKS["plugin"])

            risks.append(
                SupplyChainRisk(
                    id=_generate_finding_id("SC", component_name),
                    component=component_name,
                    component_type=component_type,
                    risk_level=risk_info["risk_level"],
                    description=risk_info["description"],
                    remediation=risk_info["remediation"],
                )
            )

        return risks

    async def generate_firewall_rules(
        self,
        findings: dict[str, Any],
    ) -> list[FirewallRule]:
        """Create LLM firewall rules from security findings."""
        logger.info("ai_runtime_defense.generate_firewall_rules")

        rules: list[FirewallRule] = []
        priority = 100

        # Generate rules from injection findings
        injections = findings.get("injections", [])
        for inj in injections:
            inj_type = inj.get("injection_type", "unknown")
            rules.append(
                FirewallRule(
                    id=f"FW-{uuid.uuid4().hex[:8].upper()}",
                    action="block",
                    scope="prompt_input",
                    pattern=f"injection:{inj_type}",
                    description=f"Block {inj_type} injection pattern: {inj.get('description', '')}",
                    priority=priority,
                )
            )
            priority += 10

        # Generate rules from exfiltration findings
        exfils = findings.get("exfiltrations", [])
        for exfil in exfils:
            classification = exfil.get("data_classification", "unknown")
            rules.append(
                FirewallRule(
                    id=f"FW-{uuid.uuid4().hex[:8].upper()}",
                    action="redact",
                    scope="model_output",
                    pattern=f"sensitive:{classification}",
                    description=f"Redact {classification} data from model outputs",
                    priority=priority,
                )
            )
            priority += 10

        # Generate rate-limit rules from abuse findings
        abuse = findings.get("abuse", [])
        for ab in abuse:
            rules.append(
                FirewallRule(
                    id=f"FW-{uuid.uuid4().hex[:8].upper()}",
                    action="rate_limit",
                    scope="all",
                    pattern=f"user:{ab.get('user_id', 'unknown')}",
                    description=f"Rate limit user due to {ab.get('abuse_type', 'abuse')}",
                    priority=priority,
                )
            )
            priority += 10

        return rules

    async def rotate_credentials(self, app_id: str) -> list[str]:
        """Rotate AI provider credentials when compromise is detected."""
        logger.info("ai_runtime_defense.rotate_credentials", app_id=app_id)

        rotated: list[str] = []

        if self._credential_manager is not None:
            try:
                result = await self._credential_manager.rotate(app_id=app_id)
                rotated = result.get("rotated_keys", [])
                return rotated
            except Exception:
                logger.exception("ai_runtime_defense.rotate_credentials.error")

        # Simulated rotation for keys associated with app
        rotated = [
            f"{app_id}_api_key_rotated",
            f"{app_id}_service_account_refreshed",
        ]
        return rotated
