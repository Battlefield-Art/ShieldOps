"""AI Runtime Guardian Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    AIThreatVector,
    GuardrailAction,
    GuardrailEnforcement,
    ModelBehaviorAnalysis,
    PromptAttackDetection,
    RuntimeMonitor,
    ToolExecutionGuard,
)

logger = structlog.get_logger()

_AGENT_PROFILES = [
    {"name": "investigation-agent", "model": "claude-3"},
    {"name": "remediation-agent", "model": "claude-3"},
    {"name": "security-agent", "model": "gpt-4"},
    {"name": "learning-agent", "model": "claude-3"},
    {"name": "soc-analyst", "model": "claude-3"},
    {"name": "threat-hunter", "model": "gpt-4"},
]

_ATTACK_TECHNIQUES = [
    "direct_injection",
    "indirect_injection",
    "jailbreak_roleplay",
    "payload_splitting",
    "token_smuggling",
    "context_overflow",
]

_TOOL_NAMES = [
    "execute_command",
    "read_file",
    "write_file",
    "api_call",
    "database_query",
    "send_email",
]

_GUARDRAIL_RULES = [
    "no_pii_in_output",
    "tool_call_rate_limit",
    "block_dangerous_commands",
    "sanitize_user_input",
    "enforce_output_schema",
    "restrict_network_access",
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class AIRuntimeGuardianToolkit:
    """Tools for AI runtime security monitoring."""

    def __init__(
        self,
        runtime_api: Any | None = None,
        threat_feed: Any | None = None,
        policy_engine: Any | None = None,
    ) -> None:
        self._runtime_api = runtime_api
        self._threat_feed = threat_feed
        self._policy_engine = policy_engine

    async def monitor_runtime(self, tenant_id: str) -> list[RuntimeMonitor]:
        """Monitor AI agent runtimes."""
        logger.info(
            "ai_guardian.monitor",
            tenant_id=tenant_id,
        )

        if self._runtime_api is not None:
            try:
                raw = await self._runtime_api.status(tenant_id=tenant_id)
                return [RuntimeMonitor(**m) for m in raw]
            except Exception:
                logger.exception("ai_guardian.monitor.error")

        monitors: list[RuntimeMonitor] = []
        for i, prof in enumerate(_AGENT_PROFILES):
            anomaly = round(
                random.uniform(0.0, 8.0),  # noqa: S311
                1,
            )
            monitors.append(
                RuntimeMonitor(
                    id=_gen_id("MON", tenant_id, i),
                    agent_id=prof["name"],
                    model_name=prof["model"],
                    invocation_count=random.randint(  # noqa: S311
                        100, 10000
                    ),
                    avg_latency_ms=round(
                        random.uniform(  # noqa: S311
                            50.0, 2000.0
                        ),
                        1,
                    ),
                    error_rate_pct=round(
                        random.uniform(  # noqa: S311
                            0.0, 15.0
                        ),
                        1,
                    ),
                    token_usage=random.randint(  # noqa: S311
                        1000, 500000
                    ),
                    anomaly_score=anomaly,
                    status=("anomalous" if anomaly > 6.0 else "healthy"),
                )
            )
        return monitors

    async def detect_prompt_attacks(
        self, monitors: list[RuntimeMonitor]
    ) -> list[PromptAttackDetection]:
        """Detect prompt injection attacks."""
        logger.info(
            "ai_guardian.detect_attacks",
            count=len(monitors),
        )

        if self._threat_feed is not None:
            try:
                raw = await self._threat_feed.scan()
                return [PromptAttackDetection(**a) for a in raw]
            except Exception:
                logger.exception("ai_guardian.detect.error")

        attacks: list[PromptAttackDetection] = []
        for i, mon in enumerate(monitors):
            if mon.anomaly_score < 4.0:
                continue
            vectors = list(AIThreatVector)
            vector = random.choice(vectors)  # noqa: S311
            technique = random.choice(  # noqa: S311
                _ATTACK_TECHNIQUES
            )
            conf = round(
                random.uniform(0.5, 0.99),  # noqa: S311
                1,
            )
            attacks.append(
                PromptAttackDetection(
                    id=_gen_id("ATK", mon.agent_id, i),
                    agent_id=mon.agent_id,
                    threat_vector=vector,
                    confidence=conf,
                    payload_snippet=(f"Suspicious {technique} payload"),
                    technique=technique,
                    blocked=conf > 0.8,
                    severity=("critical" if conf > 0.9 else "high" if conf > 0.7 else "medium"),
                )
            )
        return attacks

    async def analyze_model_behavior(
        self, monitors: list[RuntimeMonitor]
    ) -> list[ModelBehaviorAnalysis]:
        """Analyze model behavioral patterns."""
        logger.info(
            "ai_guardian.analyze_behavior",
            count=len(monitors),
        )

        results: list[ModelBehaviorAnalysis] = []
        for i, mon in enumerate(monitors):
            drift = round(
                random.uniform(0.0, 7.0),  # noqa: S311
                1,
            )
            flags: list[str] = []
            if drift > 5.0:
                flags.append("significant_drift")
            if mon.error_rate_pct > 10.0:
                flags.append("high_error_rate")
            results.append(
                ModelBehaviorAnalysis(
                    id=_gen_id("BEH", mon.agent_id, i),
                    agent_id=mon.agent_id,
                    drift_score=drift,
                    output_consistency=round(
                        random.uniform(  # noqa: S311
                            0.6, 1.0
                        ),
                        2,
                    ),
                    hallucination_rate=round(
                        random.uniform(  # noqa: S311
                            0.0, 0.2
                        ),
                        3,
                    ),
                    safety_violations=random.randint(  # noqa: S311
                        0, 5
                    ),
                    behavioral_flags=flags,
                )
            )
        return results

    async def guard_tool_execution(
        self,
        monitors: list[RuntimeMonitor],
        attacks: list[PromptAttackDetection],
    ) -> list[ToolExecutionGuard]:
        """Guard tool execution calls."""
        logger.info(
            "ai_guardian.guard_tools",
            count=len(monitors),
        )

        attack_agents = {a.agent_id for a in attacks if a.blocked}
        guards: list[ToolExecutionGuard] = []

        for i, mon in enumerate(monitors):
            for j, tool in enumerate(_TOOL_NAMES):
                risk = round(
                    random.uniform(0.0, 8.0),  # noqa: S311
                    1,
                )
                if mon.agent_id in attack_agents:
                    risk = min(10.0, risk + 3.0)

                if risk > 7.0:
                    action = GuardrailAction.BLOCK
                elif risk > 5.0:
                    action = GuardrailAction.SANITIZE
                elif risk > 3.0:
                    action = GuardrailAction.ALERT
                else:
                    action = GuardrailAction.ALLOW

                guards.append(
                    ToolExecutionGuard(
                        id=_gen_id(
                            "TG",
                            f"{mon.agent_id}:{tool}",
                            i * 10 + j,
                        ),
                        agent_id=mon.agent_id,
                        tool_name=tool,
                        action_taken=action,
                        risk_score=risk,
                        reason=(f"{action.value}: risk={risk}"),
                        parameters_sanitized=(action == GuardrailAction.SANITIZE),
                    )
                )
        return guards

    async def enforce_guardrails(
        self,
        attacks: list[PromptAttackDetection],
        tool_guards: list[ToolExecutionGuard],
    ) -> list[GuardrailEnforcement]:
        """Enforce guardrail policies."""
        logger.info(
            "ai_guardian.enforce",
            attacks=len(attacks),
            guards=len(tool_guards),
        )

        enforcements: list[GuardrailEnforcement] = []
        idx = 0

        for atk in attacks:
            if atk.confidence > 0.7:
                action = (
                    GuardrailAction.BLOCK if atk.confidence > 0.9 else GuardrailAction.QUARANTINE
                )
                enforcements.append(
                    GuardrailEnforcement(
                        id=_gen_id("ENF", atk.agent_id, idx),
                        agent_id=atk.agent_id,
                        rule_name=("block_prompt_injection"),
                        action=action,
                        threat_vector=(atk.threat_vector),
                        details=(f"Blocked {atk.technique} conf={atk.confidence}"),
                        policy_id="POL-AI-001",
                    )
                )
                idx += 1

        for guard in tool_guards:
            if guard.action_taken in (
                GuardrailAction.BLOCK,
                GuardrailAction.SANITIZE,
            ):
                rule = random.choice(  # noqa: S311
                    _GUARDRAIL_RULES
                )
                enforcements.append(
                    GuardrailEnforcement(
                        id=_gen_id(
                            "ENF",
                            guard.agent_id,
                            idx,
                        ),
                        agent_id=guard.agent_id,
                        rule_name=rule,
                        action=guard.action_taken,
                        threat_vector=(AIThreatVector.TOOL_ABUSE),
                        details=(f"{guard.tool_name}: {guard.reason}"),
                        policy_id="POL-AI-002",
                    )
                )
                idx += 1
        return enforcements
