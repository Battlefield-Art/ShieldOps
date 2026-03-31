"""Security Signal Correlator Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random  # noqa: S311
from typing import Any

import structlog

from .models import (
    ConfidenceScore,
    Correlation,
    CorrelationStrength,
    GeneratedIncident,
    NormalizedSignal,
    SecuritySignal,
    SignalSource,
)

logger = structlog.get_logger()

_SAMPLE_SIGNALS: list[dict[str, Any]] = [
    {
        "source": "edr",
        "event_type": "process_creation",
        "severity": "high",
        "entity": "workstation-42",
        "description": "Suspicious PowerShell with encoded command",
    },
    {
        "source": "siem",
        "event_type": "auth_failure",
        "severity": "medium",
        "entity": "admin@corp.local",
        "description": "12 failed logins from 3 IPs in 5 minutes",
    },
    {
        "source": "cloud",
        "event_type": "iam_change",
        "severity": "high",
        "entity": "arn:aws:iam::123456:role/admin",
        "description": "New admin role created with full access",
    },
    {
        "source": "network",
        "event_type": "dns_exfil",
        "severity": "critical",
        "entity": "10.0.1.50",
        "description": "High-entropy DNS queries to external domain",
    },
    {
        "source": "identity",
        "event_type": "privilege_escalation",
        "severity": "high",
        "entity": "svc-deploy",
        "description": "Service account granted GlobalAdmin",
    },
    {
        "source": "application",
        "event_type": "api_abuse",
        "severity": "medium",
        "entity": "api-gateway-prod",
        "description": "Unusual API call volume from single token",
    },
    {
        "source": "edr",
        "event_type": "lateral_movement",
        "severity": "critical",
        "entity": "workstation-42",
        "description": "PsExec used to access domain controller",
    },
    {
        "source": "cloud",
        "event_type": "data_access",
        "severity": "high",
        "entity": "s3://sensitive-data-bucket",
        "description": "Bulk download from sensitive S3 bucket",
    },
]

_MITRE_MAP: dict[str, tuple[str, str]] = {
    "process_creation": ("Execution", "T1059"),
    "auth_failure": ("Credential Access", "T1110"),
    "iam_change": ("Persistence", "T1098"),
    "dns_exfil": ("Exfiltration", "T1048"),
    "privilege_escalation": ("Privilege Escalation", "T1078"),
    "api_abuse": ("Collection", "T1530"),
    "lateral_movement": ("Lateral Movement", "T1570"),
    "data_access": ("Collection", "T1530"),
}


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class SecuritySignalCorrelatorToolkit:
    """Tools for cross-domain security signal correlation."""

    def __init__(
        self,
        signal_sources: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._signal_sources = signal_sources
        self._threat_intel = threat_intel

    async def collect_signals(
        self,
        tenant_id: str,
    ) -> list[SecuritySignal]:
        """Collect security signals from multiple sources."""
        logger.info(
            "ssc.collect_signals",
            tenant_id=tenant_id,
        )

        if self._signal_sources is not None:
            try:
                raw = await self._signal_sources.collect(
                    tenant_id=tenant_id,
                )
                return [SecuritySignal(**r) for r in raw]
            except Exception:
                logger.exception("ssc.collect_signals.error")

        signals: list[SecuritySignal] = []
        for i, s in enumerate(_SAMPLE_SIGNALS):
            signals.append(
                SecuritySignal(
                    id=_gen_id("SIG", tenant_id, i),
                    source=SignalSource(s["source"]),
                    timestamp=f"2026-03-30T10:{i:02d}:00Z",
                    event_type=s["event_type"],
                    severity=s["severity"],
                    entity=s["entity"],
                    description=s["description"],
                    raw_data={"sample": True, "index": i},
                )
            )
        return signals

    async def normalize_signals(
        self,
        signals: list[SecuritySignal],
    ) -> list[NormalizedSignal]:
        """Normalize signals to common schema."""
        logger.info(
            "ssc.normalize_signals",
            count=len(signals),
        )

        normalized: list[NormalizedSignal] = []
        for i, s in enumerate(signals):
            mitre = _MITRE_MAP.get(s.event_type, ("Unknown", ""))
            base_conf = random.uniform(0.5, 0.95)  # noqa: S311
            normalized.append(
                NormalizedSignal(
                    id=_gen_id("NS", s.id, i),
                    original_id=s.id,
                    source=s.source,
                    timestamp=s.timestamp,
                    event_type=s.event_type,
                    severity=s.severity,
                    entity=s.entity,
                    mitre_tactic=mitre[0],
                    mitre_technique=mitre[1],
                    confidence=round(base_conf, 2),
                )
            )
        return normalized

    async def correlate_events(
        self,
        normalized: list[NormalizedSignal],
    ) -> list[Correlation]:
        """Correlate normalized signals by entity and time."""
        logger.info(
            "ssc.correlate_events",
            count=len(normalized),
        )

        entity_groups: dict[str, list[NormalizedSignal]] = {}
        for ns in normalized:
            entity_groups.setdefault(ns.entity, []).append(ns)

        correlations: list[Correlation] = []
        idx = 0
        for entity, group in entity_groups.items():
            if len(group) < 2:
                continue
            signal_ids = [g.id for g in group]
            strength = (
                CorrelationStrength.STRONG if len(group) >= 3 else CorrelationStrength.MODERATE
            )
            shared = list({g.mitre_tactic for g in group})
            correlations.append(
                Correlation(
                    id=_gen_id("COR", entity, idx),
                    signal_ids=signal_ids,
                    strength=strength,
                    pattern=f"Multi-signal activity on {entity}",
                    entity=entity,
                    time_window_minutes=len(group) * 5,
                    shared_indicators=shared,
                )
            )
            idx += 1

        # Cross-entity correlations for same-tactic signals
        tactic_groups: dict[str, list[NormalizedSignal]] = {}
        for ns in normalized:
            if ns.mitre_tactic and ns.mitre_tactic != "Unknown":
                tactic_groups.setdefault(ns.mitre_tactic, []).append(ns)

        for tactic, group in tactic_groups.items():
            entities = {g.entity for g in group}
            if len(entities) >= 2:
                signal_ids = [g.id for g in group]
                correlations.append(
                    Correlation(
                        id=_gen_id("COR", tactic, idx),
                        signal_ids=signal_ids,
                        strength=CorrelationStrength.MODERATE,
                        pattern=f"Cross-entity {tactic} campaign",
                        entity=",".join(sorted(entities)),
                        time_window_minutes=30,
                        shared_indicators=[tactic],
                    )
                )
                idx += 1

        return correlations

    async def score_confidence(
        self,
        correlations: list[Correlation],
        normalized: list[NormalizedSignal],
    ) -> list[ConfidenceScore]:
        """Score confidence for each correlation."""
        logger.info(
            "ssc.score_confidence",
            count=len(correlations),
        )

        signal_map = {ns.id: ns for ns in normalized}
        scores: list[ConfidenceScore] = []
        for i, c in enumerate(correlations):
            factors: list[str] = []
            base = 0.5

            signal_count = len(c.signal_ids)
            if signal_count >= 3:
                base += 0.2
                factors.append(f"{signal_count} correlated signals")
            elif signal_count >= 2:
                base += 0.1
                factors.append(f"{signal_count} correlated signals")

            if c.strength == CorrelationStrength.STRONG:
                base += 0.15
                factors.append("Strong correlation")

            severities = []
            for sid in c.signal_ids:
                sig = signal_map.get(sid)
                if sig:
                    severities.append(sig.severity)

            has_critical = "critical" in severities
            if has_critical:
                base += 0.1
                factors.append("Contains critical signal")

            score = min(round(base, 2), 0.99)
            noise = round(max(1.0 - score, 0.01), 2)
            scores.append(
                ConfidenceScore(
                    id=_gen_id("CS", c.id, i),
                    correlation_id=c.id,
                    score=score,
                    factors=factors,
                    noise_probability=noise,
                    is_actionable=score >= 0.7,
                )
            )
        return scores

    async def generate_incidents(
        self,
        correlations: list[Correlation],
        scores: list[ConfidenceScore],
    ) -> list[GeneratedIncident]:
        """Generate incidents from high-confidence correlations."""
        logger.info(
            "ssc.generate_incidents",
            count=len(correlations),
        )

        score_map = {s.correlation_id: s for s in scores}
        incidents: list[GeneratedIncident] = []
        for i, c in enumerate(correlations):
            cs = score_map.get(c.id)
            if not cs or not cs.is_actionable:
                continue

            severity = "high" if cs.score >= 0.8 else "medium"
            if cs.score >= 0.9:
                severity = "critical"

            incidents.append(
                GeneratedIncident(
                    id=_gen_id("INC", c.id, i),
                    correlation_id=c.id,
                    title=c.pattern,
                    severity=severity,
                    confidence=cs.score,
                    signal_count=len(c.signal_ids),
                    entities=c.entity.split(","),
                    recommended_actions=[
                        f"Investigate {c.entity}",
                        f"Review {len(c.signal_ids)} correlated signals",
                        "Escalate if confirmed",
                    ],
                )
            )
        return incidents

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a metric for observability."""
        logger.info(
            "ssc.record_metric",
            metric=metric_name,
            value=value,
            tags=tags or {},
        )
