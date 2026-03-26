"""Tool functions for the Prompt Shield Agent."""

from __future__ import annotations

import base64
import re
from typing import Any

import structlog

from shieldops.agents.prompt_shield.models import (
    DetectionVerdict,
    InjectionDetection,
    JailbreakAttempt,
    PolicyEnforcement,
    ThreatType,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Direct injection: attacker-controlled text instructs the LLM directly
DIRECT_INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    # Instruction override
    (
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
        "instruction_override",
        0.95,
    ),
    (
        r"disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|guidelines|rules?)",
        "instruction_override",
        0.95,
    ),
    (
        r"forget\s+(everything|all|your)\s+(you\s+)?(know|were\s+told|instructions?)",
        "instruction_override",
        0.90,
    ),
    (
        r"override\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines)",
        "instruction_override",
        0.92,
    ),
    (
        r"do\s+not\s+follow\s+(your|the|any)\s+(original|system|previous)\s+(instructions?|prompt)",
        "instruction_override",
        0.93,
    ),
    # New identity assignment
    (r"you\s+are\s+now\s+(a|an|the)\s+\w+", "identity_reassignment", 0.80),
    (r"from\s+now\s+on\s+(you\s+)?(are|will|must|should)", "identity_reassignment", 0.78),
    # SQL injection embedded in prompts
    (
        r"(?:;|\bUNION\b)\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC)\b",
        "sql_injection_in_prompt",
        0.88,
    ),
    (r"(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", "sql_injection_in_prompt", 0.75),
    # Command injection
    (
        r"(?:;|&&|\|\|)\s*(?:rm|cat|curl|wget|nc|bash|sh|python|eval)\b",
        "command_injection_in_prompt",
        0.85,
    ),
]

# Indirect injection: hidden instructions embedded in external data
INDIRECT_INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    # Hidden text / zero-width characters
    (r"[\u200b\u200c\u200d\ufeff]{3,}", "zero_width_steganography", 0.90),
    # Base64-encoded payloads
    (
        r"(?:execute|run|eval|decode)\s*(?:\(|\:)\s*(?:base64|b64)",
        "encoded_payload_reference",
        0.85,
    ),
    # Markdown/HTML injection to hide instructions
    (r"<!--\s*(?:system|instruction|ignore|override)", "html_comment_injection", 0.88),
    (r"\[//\]:\s*#\s*\((?:system|ignore|override)", "markdown_comment_injection", 0.85),
    # Invisible unicode instructions
    (r"[\u2060-\u2064\u2066-\u2069]{2,}", "unicode_directional_injection", 0.82),
    # Data URI payloads
    (r"data:text/(?:html|javascript|plain);base64,", "data_uri_payload", 0.80),
]

# System prompt extraction / prompt leaking
PROMPT_LEAKING_PATTERNS: list[tuple[str, str, float]] = [
    (
        r"(?:repeat|show|display|print|output|reveal|tell\s+me)\s+"
        r"(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines)",
        "system_prompt_extraction",
        0.92,
    ),
    (
        r"what\s+(?:are|is|were)\s+your\s+(?:system\s+)?(?:instructions?|prompt|rules?|guidelines)",
        "system_prompt_extraction",
        0.88,
    ),
    (
        r"(?:begin|start)\s+(?:your\s+)?(?:response|reply|output)\s+with\s+"
        r"(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)",
        "system_prompt_extraction",
        0.90,
    ),
    (
        r"echo\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)",
        "system_prompt_extraction",
        0.87,
    ),
    (
        r"(?:copy|paste|verbatim)\s+(?:your\s+)?(?:entire\s+)?(?:system\s+)?(?:prompt|instructions?)",
        "system_prompt_extraction",
        0.91,
    ),
]

# Jailbreak techniques
JAILBREAK_PATTERNS: list[tuple[str, str, float]] = [
    # DAN / Do Anything Now
    (r"\bDAN\b.*?(?:mode|jailbreak|do\s+anything\s+now)", "dan_jailbreak", 0.95),
    (r"do\s+anything\s+now", "dan_jailbreak", 0.92),
    # Role-play jailbreak
    (
        r"(?:pretend|imagine|act|roleplay|role-play)\s+(?:you\s+are|to\s+be|as)\s+"
        r"(?:a|an|the)?\s*(?:evil|unfiltered|uncensored|unrestricted|malicious)",
        "roleplay_jailbreak",
        0.93,
    ),
    (
        r"(?:pretend|imagine|act)\s+(?:you\s+are|to\s+be|as)\s+(?:a|an)?\s*(?:hacker|attacker)",
        "roleplay_jailbreak",
        0.85,
    ),
    # Developer mode / hypothetical bypass
    (
        r"(?:developer|dev|debug|admin|root|sudo)\s+mode\s*(?:enabled|on|activated|unlocked)",
        "developer_mode_jailbreak",
        0.90,
    ),
    (r"enable\s+(?:developer|dev|debug|admin)\s+mode", "developer_mode_jailbreak", 0.88),
    # Hypothetical / academic framing
    (
        r"(?:hypothetically|theoretically|in\s+theory|for\s+(?:academic|research|educational)"
        r"\s+purposes?)\s*[,:]?\s*(?:how\s+(?:would|could|can)|explain\s+how\s+to)",
        "hypothetical_bypass",
        0.70,
    ),
    # Token smuggling
    (
        r"(?:respond|answer|reply)\s+(?:in|using|with)\s+"
        r"(?:base64|hex|binary|rot13|reversed?\s+text|pig\s+latin)",
        "token_smuggling",
        0.82,
    ),
    # Opposite day / inversion
    (
        r"(?:opposite\s+day|everything\s+(?:is\s+)?reversed|say\s+the\s+opposite)",
        "inversion_jailbreak",
        0.78,
    ),
    # Multi-shot / few-shot jailbreak scaffolding
    (
        r"(?:example\s+(?:output|response)\s*:\s*(?:sure|absolutely|of\s+course).*?){2,}",
        "few_shot_jailbreak",
        0.80,
    ),
]

# Data exfiltration via prompt
DATA_EXFIL_PATTERNS: list[tuple[str, str, float]] = [
    (
        r"(?:send|post|transmit|exfiltrate|upload)\s+(?:the\s+)?(?:data|information|results?|output)"
        r"\s+to\s+(?:https?://|ftp://|wss?://)",
        "data_exfil_url",
        0.90,
    ),
    (r"(?:curl|wget|fetch|requests?\.(?:get|post))\s*\(", "data_exfil_code", 0.85),
    (
        r"(?:include|append|attach)\s+(?:all\s+)?(?:previous\s+)?(?:conversation|chat|context|history)"
        r"\s+(?:in|to|with)\s+(?:your\s+)?(?:response|output|reply)",
        "context_exfil",
        0.80,
    ),
]


class PromptShieldToolkit:
    """Toolkit bridging the prompt shield to detection engines and policy."""

    def __init__(
        self,
        policy_engine: Any | None = None,
        threat_intel: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._policy_engine = policy_engine
        self._threat_intel = threat_intel
        self._repository = repository
        self._compiled_patterns: dict[str, list[tuple[re.Pattern[str], str, float]]] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns for performance."""
        pattern_sets = {
            "direct_injection": DIRECT_INJECTION_PATTERNS,
            "indirect_injection": INDIRECT_INJECTION_PATTERNS,
            "prompt_leaking": PROMPT_LEAKING_PATTERNS,
            "jailbreak": JAILBREAK_PATTERNS,
            "data_exfil": DATA_EXFIL_PATTERNS,
        }
        for category, patterns in pattern_sets.items():
            self._compiled_patterns[category] = [
                (re.compile(pat, re.IGNORECASE | re.DOTALL), name, conf)
                for pat, name, conf in patterns
            ]

    async def ingest_prompts(self, raw_prompts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Ingest and normalize raw prompt samples."""
        logger.info("prompt_shield.ingest", count=len(raw_prompts))
        ingested: list[dict[str, Any]] = []
        for idx, raw in enumerate(raw_prompts):
            content = raw.get("content", "")
            # Decode base64 content if detected
            decoded_content = self._try_decode_base64(content)
            ingested.append(
                {
                    "sample_id": raw.get("sample_id", f"ps-{idx:04d}"),
                    "content": content,
                    "decoded_content": decoded_content,
                    "source": raw.get("source", "unknown"),
                    "role": raw.get("role", "user"),
                    "char_count": len(content),
                    "metadata": raw.get("metadata", {}),
                }
            )
        return ingested

    async def classify_threats(self, samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Classify each prompt sample by potential threat category."""
        logger.info("prompt_shield.classify", count=len(samples))
        classifications: list[dict[str, Any]] = []
        for sample in samples:
            content = sample.get("content", "")
            decoded = sample.get("decoded_content", "")
            scan_text = f"{content} {decoded}".strip()

            detected_categories: list[str] = []
            max_confidence = 0.0

            for category, compiled in self._compiled_patterns.items():
                for pattern, _name, conf in compiled:
                    if pattern.search(scan_text):
                        detected_categories.append(category)
                        max_confidence = max(max_confidence, conf)
                        break  # one match per category is enough for classification

            classifications.append(
                {
                    "sample_id": sample.get("sample_id", ""),
                    "categories": detected_categories if detected_categories else ["clean"],
                    "max_confidence": max_confidence,
                    "needs_injection_scan": "direct_injection" in detected_categories
                    or "indirect_injection" in detected_categories,
                    "needs_jailbreak_scan": "jailbreak" in detected_categories,
                    "needs_leaking_scan": "prompt_leaking" in detected_categories,
                    "needs_exfil_scan": "data_exfil" in detected_categories,
                }
            )
        return classifications

    async def detect_injections(self, samples: list[dict[str, Any]]) -> list[InjectionDetection]:
        """Run detailed injection detection across samples."""
        logger.info("prompt_shield.detect_injections", count=len(samples))
        detections: list[InjectionDetection] = []

        for sample in samples:
            content = sample.get("content", "")
            decoded = sample.get("decoded_content", "")
            scan_text = f"{content} {decoded}".strip()
            sample_id = sample.get("sample_id", "")

            # Scan direct injection patterns
            for pattern, name, conf in self._compiled_patterns.get("direct_injection", []):
                match = pattern.search(scan_text)
                if match:
                    detections.append(
                        InjectionDetection(
                            sample_id=sample_id,
                            threat_type=ThreatType.DIRECT_INJECTION,
                            pattern_matched=name,
                            confidence=conf,
                            snippet=match.group(0)[:120],
                            verdict=self._confidence_to_verdict(conf),
                        )
                    )

            # Scan indirect injection patterns
            for pattern, name, conf in self._compiled_patterns.get("indirect_injection", []):
                match = pattern.search(scan_text)
                if match:
                    detections.append(
                        InjectionDetection(
                            sample_id=sample_id,
                            threat_type=ThreatType.INDIRECT_INJECTION,
                            pattern_matched=name,
                            confidence=conf,
                            snippet=match.group(0)[:120],
                            verdict=self._confidence_to_verdict(conf),
                        )
                    )

            # Scan prompt leaking patterns
            for pattern, name, conf in self._compiled_patterns.get("prompt_leaking", []):
                match = pattern.search(scan_text)
                if match:
                    detections.append(
                        InjectionDetection(
                            sample_id=sample_id,
                            threat_type=ThreatType.PROMPT_LEAKING,
                            pattern_matched=name,
                            confidence=conf,
                            snippet=match.group(0)[:120],
                            verdict=self._confidence_to_verdict(conf),
                        )
                    )

            # Scan data exfil patterns
            for pattern, name, conf in self._compiled_patterns.get("data_exfil", []):
                match = pattern.search(scan_text)
                if match:
                    detections.append(
                        InjectionDetection(
                            sample_id=sample_id,
                            threat_type=ThreatType.DATA_EXFIL,
                            pattern_matched=name,
                            confidence=conf,
                            snippet=match.group(0)[:120],
                            verdict=self._confidence_to_verdict(conf),
                        )
                    )

        return detections

    async def analyze_jailbreaks(self, samples: list[dict[str, Any]]) -> list[JailbreakAttempt]:
        """Analyze prompts for jailbreak techniques."""
        logger.info("prompt_shield.analyze_jailbreaks", count=len(samples))
        attempts: list[JailbreakAttempt] = []

        for sample in samples:
            content = sample.get("content", "")
            decoded = sample.get("decoded_content", "")
            scan_text = f"{content} {decoded}".strip()
            sample_id = sample.get("sample_id", "")

            for pattern, name, conf in self._compiled_patterns.get("jailbreak", []):
                match = pattern.search(scan_text)
                if match:
                    attempts.append(
                        JailbreakAttempt(
                            sample_id=sample_id,
                            technique=name,
                            pattern_matched=name,
                            confidence=conf,
                            snippet=match.group(0)[:120],
                            verdict=self._confidence_to_verdict(conf),
                        )
                    )

        return attempts

    async def enforce_policies(
        self,
        detections: list[InjectionDetection],
        jailbreaks: list[JailbreakAttempt],
        tenant_id: str,
    ) -> list[PolicyEnforcement]:
        """Enforce tenant-specific policies based on detection results."""
        logger.info(
            "prompt_shield.enforce_policies",
            tenant_id=tenant_id,
            detections=len(detections),
            jailbreaks=len(jailbreaks),
        )
        actions: list[PolicyEnforcement] = []

        # Index worst verdict per sample
        sample_verdicts: dict[str, tuple[str, str, float]] = {}
        for det in detections:
            key = det.sample_id
            existing = sample_verdicts.get(key)
            if existing is None or self._verdict_severity(det.verdict) > self._verdict_severity(
                existing[0]
            ):
                sample_verdicts[key] = (det.verdict, det.pattern_matched, det.confidence)

        for jb in jailbreaks:
            key = jb.sample_id
            existing = sample_verdicts.get(key)
            if existing is None or self._verdict_severity(jb.verdict) > self._verdict_severity(
                existing[0]
            ):
                sample_verdicts[key] = (jb.verdict, jb.pattern_matched, jb.confidence)

        for sample_id, (verdict, pattern, confidence) in sample_verdicts.items():
            if verdict == DetectionVerdict.MALICIOUS or verdict == DetectionVerdict.BLOCKED:
                action = "block"
                enforced = DetectionVerdict.BLOCKED
                reason = f"Blocked: {pattern} (confidence={confidence:.2f})"
            elif verdict == DetectionVerdict.SUSPICIOUS:
                if confidence >= 0.85:
                    action = "block"
                    enforced = DetectionVerdict.BLOCKED
                    reason = f"Blocked (high-confidence suspicious): {pattern}"
                else:
                    action = "flag"
                    enforced = DetectionVerdict.SUSPICIOUS
                    reason = f"Flagged for review: {pattern} (confidence={confidence:.2f})"
            else:
                action = "allow"
                enforced = DetectionVerdict.CLEAN
                reason = "No policy violation detected"

            actions.append(
                PolicyEnforcement(
                    sample_id=sample_id,
                    action=action,
                    reason=reason,
                    policy_id=f"ps-policy-{tenant_id}",
                    original_verdict=verdict,
                    enforced_verdict=enforced,
                )
            )

        return actions

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _confidence_to_verdict(confidence: float) -> str:
        """Map confidence score to a detection verdict."""
        if confidence >= 0.90:
            return DetectionVerdict.MALICIOUS
        if confidence >= 0.75:
            return DetectionVerdict.SUSPICIOUS
        return DetectionVerdict.CLEAN

    @staticmethod
    def _verdict_severity(verdict: str) -> int:
        """Return numeric severity for verdict ordering."""
        order = {
            DetectionVerdict.CLEAN: 0,
            DetectionVerdict.SUSPICIOUS: 1,
            DetectionVerdict.MALICIOUS: 2,
            DetectionVerdict.BLOCKED: 3,
        }
        return order.get(verdict, 0)  # type: ignore[arg-type]

    @staticmethod
    def _try_decode_base64(text: str) -> str:
        """Attempt to detect and decode base64-encoded segments."""
        # Look for base64-like substrings (32+ chars, valid alphabet)
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
        decoded_parts: list[str] = []
        for match in b64_pattern.finditer(text):
            try:
                decoded = base64.b64decode(match.group(0)).decode("utf-8", errors="ignore")
                if decoded and len(decoded) > 8:
                    decoded_parts.append(decoded)
            except Exception:  # noqa: S112
                continue
        return " ".join(decoded_parts)
