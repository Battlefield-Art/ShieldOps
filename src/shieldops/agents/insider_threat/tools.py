"""Insider Threat Detection Agent — Tool functions for signal fusion and analytics."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    BehavioralBaseline,
    BehaviorDeviation,
    InsiderInvestigation,
    InsiderRiskScore,
    RiskCategory,
    ThreatIndicator,
    UserSignal,
)

logger = structlog.get_logger()

# Detection thresholds
_OFF_HOURS_START = 22  # 10 PM
_OFF_HOURS_END = 6  # 6 AM
_HIGH_DATA_VOLUME_MULTIPLIER = 3.0
_BULK_DOWNLOAD_THRESHOLD = 50  # files in one session
_HIGH_RISK_SCORE_THRESHOLD = 0.75
_INVESTIGATION_THRESHOLD = 0.80
_AUTO_RESPOND_THRESHOLD = 0.90


class InsiderThreatToolkit:
    """Tools for insider threat detection via signal fusion."""

    def __init__(
        self,
        identity_provider: Any | None = None,
        hr_system: Any | None = None,
        dlp_engine: Any | None = None,
        code_repo_connector: Any | None = None,
        ai_tool_monitor: Any | None = None,
        access_log_store: Any | None = None,
    ) -> None:
        self._identity_provider = identity_provider
        self._hr_system = hr_system
        self._dlp_engine = dlp_engine
        self._code_repo = code_repo_connector
        self._ai_tool_monitor = ai_tool_monitor
        self._access_log_store = access_log_store
        self._signal_cache: dict[str, list[UserSignal]] = {}
        self._baseline_cache: dict[str, BehavioralBaseline] = {}

    async def collect_user_signals(
        self,
        tenant_id: str,
        time_window_hours: int = 24,
    ) -> list[UserSignal]:
        """Collect signals from identity, HR, DLP, code, AI tools.

        Fuses data from identity providers, HR systems, DLP
        engines, code repositories, and AI tool usage monitors
        within the specified time window.
        """
        logger.info(
            "insider_threat.collect_signals",
            tenant_id=tenant_id,
            time_window_hours=time_window_hours,
        )
        now = time.time()
        cutoff = now - (time_window_hours * 3600)
        signals: list[UserSignal] = []

        sources = [
            ("identity_provider", self._identity_provider),
            ("hr_system", self._hr_system),
            ("dlp_engine", self._dlp_engine),
            ("code_repo", self._code_repo),
            ("ai_tool_monitor", self._ai_tool_monitor),
            ("access_log_store", self._access_log_store),
        ]

        for source_name, connector in sources:
            if connector is None:
                continue
            try:
                if hasattr(connector, "get_user_events"):
                    raw = await connector.get_user_events(
                        tenant_id=tenant_id,
                        since=cutoff,
                    )
                    for evt in raw:
                        sig = UserSignal(
                            id=evt.get(
                                "id",
                                hashlib.sha256(f"{source_name}:{evt}".encode()).hexdigest()[:16],
                            ),
                            user_id=evt.get("user_id", ""),
                            user_email=evt.get("user_email", ""),
                            source=source_name,
                            signal_type=evt.get("signal_type", ""),
                            action=evt.get("action", ""),
                            resource=evt.get("resource", ""),
                            timestamp=evt.get("timestamp", now),
                            geo_location=evt.get("geo_location", ""),
                            device_id=evt.get("device_id", ""),
                            risk_indicators=evt.get("risk_indicators", []),
                            metadata=evt.get("metadata", {}),
                        )
                        signals.append(sig)
            except Exception:
                logger.warning(
                    "insider_threat.collect.source_error",
                    source=source_name,
                )

        # Synthetic signals when no connectors available
        if not any(c for _, c in sources if c is not None):
            signals = self._generate_synthetic_signals(tenant_id, cutoff, now)

        self._signal_cache[tenant_id] = signals
        return signals

    async def build_baselines(
        self,
        signals: list[UserSignal],
    ) -> list[BehavioralBaseline]:
        """Build behavioral baselines from user signals.

        Computes normal login patterns, working hours,
        typical geolocations, data access volumes, and
        tool usage for each user.
        """
        logger.info(
            "insider_threat.build_baselines",
            signal_count=len(signals),
        )
        user_groups: dict[str, list[UserSignal]] = {}
        for sig in signals:
            user_groups.setdefault(sig.user_id, []).append(sig)

        baselines: list[BehavioralBaseline] = []
        for user_id, user_sigs in user_groups.items():
            baseline = self._compute_baseline(user_id, user_sigs)
            self._baseline_cache[user_id] = baseline
            baselines.append(baseline)

        return baselines

    async def detect_deviations(
        self,
        signals: list[UserSignal],
        baselines: list[BehavioralBaseline],
    ) -> list[BehaviorDeviation]:
        """Detect behavioral deviations from baselines.

        Checks for: off-hours access, data hoarding, bulk
        downloads, privilege abuse, unauthorized tool use,
        and resignation risk indicators.
        """
        logger.info(
            "insider_threat.detect_deviations",
            signal_count=len(signals),
            baseline_count=len(baselines),
        )
        baseline_map = {b.user_id: b for b in baselines}
        deviations: list[BehaviorDeviation] = []

        user_groups: dict[str, list[UserSignal]] = {}
        for sig in signals:
            user_groups.setdefault(sig.user_id, []).append(sig)

        for user_id, user_sigs in user_groups.items():
            baseline = baseline_map.get(user_id)
            if not baseline:
                continue

            deviations.extend(self._check_off_hours(user_id, user_sigs, baseline))
            deviations.extend(self._check_data_hoarding(user_id, user_sigs, baseline))
            deviations.extend(self._check_bulk_download(user_id, user_sigs))
            deviations.extend(self._check_privilege_abuse(user_id, user_sigs, baseline))
            deviations.extend(self._check_unauthorized_tools(user_id, user_sigs, baseline))
            deviations.extend(self._check_resignation_risk(user_id, user_sigs))

        return deviations

    async def assess_risk_scores(
        self,
        deviations: list[BehaviorDeviation],
    ) -> list[InsiderRiskScore]:
        """Compute composite risk scores per user.

        Aggregates deviation severities, classifies risk
        category (flight_risk, data_theft, sabotage,
        espionage, negligence), and recommends actions.
        """
        logger.info(
            "insider_threat.assess_risk",
            deviation_count=len(deviations),
        )
        user_devs: dict[str, list[BehaviorDeviation]] = {}
        for dev in deviations:
            user_devs.setdefault(dev.user_id, []).append(dev)

        scores: list[InsiderRiskScore] = []
        for user_id, devs in user_devs.items():
            score = self._compute_risk_score(user_id, devs)
            scores.append(score)

        return scores

    async def open_investigations(
        self,
        risk_scores: list[InsiderRiskScore],
        deviations: list[BehaviorDeviation],
    ) -> list[InsiderInvestigation]:
        """Open investigations for high-risk users.

        Creates investigation records with evidence
        timeline for users above the investigation
        threshold.
        """
        logger.info(
            "insider_threat.open_investigations",
            score_count=len(risk_scores),
        )
        dev_map: dict[str, list[BehaviorDeviation]] = {}
        for dev in deviations:
            dev_map.setdefault(dev.user_id, []).append(dev)

        investigations: list[InsiderInvestigation] = []
        for score in risk_scores:
            if score.overall_score < _INVESTIGATION_THRESHOLD:
                continue

            user_devs = dev_map.get(score.user_id, [])
            dev_dicts = [d.model_dump() for d in user_devs]
            timeline = sorted(
                [
                    {
                        "timestamp": d.timestamp,
                        "indicator": d.indicator.value,
                        "description": d.description,
                        "severity": d.severity,
                    }
                    for d in user_devs
                ],
                key=lambda x: x.get("timestamp", 0),
            )
            evidence = [d.description for d in user_devs if d.severity >= 0.7]

            inv = InsiderInvestigation(
                id=hashlib.sha256(f"inv:{score.user_id}".encode()).hexdigest()[:16],
                user_id=score.user_id,
                risk_score=score.overall_score,
                category=score.category,
                deviations=dev_dicts,
                timeline=timeline,
                evidence=evidence,
                status="open",
            )
            investigations.append(inv)

        return investigations

    # -- Detection helpers --

    def _compute_baseline(
        self,
        user_id: str,
        signals: list[UserSignal],
    ) -> BehavioralBaseline:
        """Compute behavioral baseline from signals."""
        geos: set[str] = set()
        resources: set[str] = set()
        tools: set[str] = set()
        data_volume = 0.0

        for sig in signals:
            if sig.geo_location:
                geos.add(sig.geo_location)
            if sig.resource:
                resources.add(sig.resource)
            if sig.source == "ai_tool_monitor":
                tools.add(sig.action)
            vol = sig.metadata.get("data_volume_mb", 0)
            data_volume += float(vol)

        days = max(len(signals) / 10, 1)
        dept = ""
        priv = "standard"
        for sig in signals:
            if sig.metadata.get("department"):
                dept = sig.metadata["department"]
            if sig.metadata.get("privilege_level"):
                priv = sig.metadata["privilege_level"]

        return BehavioralBaseline(
            user_id=user_id,
            baseline_period_days=30,
            avg_daily_logins=len(signals) / days,
            typical_hours_start=8,
            typical_hours_end=18,
            typical_geos=list(geos)[:10],
            typical_resources=list(resources)[:20],
            avg_daily_data_volume_mb=data_volume / days,
            typical_tools=list(tools)[:10],
            privilege_level=priv,
            department=dept,
            last_updated=time.time(),
        )

    def _check_off_hours(
        self,
        user_id: str,
        signals: list[UserSignal],
        baseline: BehavioralBaseline,
    ) -> list[BehaviorDeviation]:
        """Detect access during off-hours."""
        deviations: list[BehaviorDeviation] = []
        for sig in signals:
            import datetime

            dt = datetime.datetime.fromtimestamp(
                sig.timestamp,
                tz=datetime.UTC,
            )
            hour = dt.hour
            if hour >= _OFF_HOURS_START or hour < _OFF_HOURS_END:
                dev = BehaviorDeviation(
                    id=hashlib.sha256(f"off_hours:{sig.id}".encode()).hexdigest()[:16],
                    user_id=user_id,
                    indicator=ThreatIndicator.OFF_HOURS_ACCESS,
                    description=(
                        f"Access at {hour}:00 UTC "
                        f"outside normal hours "
                        f"({baseline.typical_hours_start}"
                        f"-{baseline.typical_hours_end})"
                    ),
                    severity=0.6,
                    baseline_value=(f"{baseline.typical_hours_start}-{baseline.typical_hours_end}"),
                    observed_value=f"{hour}:00 UTC",
                    timestamp=sig.timestamp,
                    confidence=0.7,
                    mitre_technique="T1078",
                )
                deviations.append(dev)
        return deviations

    def _check_data_hoarding(
        self,
        user_id: str,
        signals: list[UserSignal],
        baseline: BehavioralBaseline,
    ) -> list[BehaviorDeviation]:
        """Detect data hoarding (excessive data access)."""
        deviations: list[BehaviorDeviation] = []
        total_volume = sum(float(s.metadata.get("data_volume_mb", 0)) for s in signals)
        threshold = max(
            baseline.avg_daily_data_volume_mb * _HIGH_DATA_VOLUME_MULTIPLIER,
            100,
        )

        if total_volume > threshold:
            dev = BehaviorDeviation(
                id=hashlib.sha256(f"hoarding:{user_id}".encode()).hexdigest()[:16],
                user_id=user_id,
                indicator=ThreatIndicator.DATA_HOARDING,
                description=(
                    f"Data volume {total_volume:.0f}MB exceeds {threshold:.0f}MB threshold"
                ),
                severity=min(
                    0.5 + (total_volume / threshold) * 0.2,
                    1.0,
                ),
                baseline_value=f"{threshold:.0f}MB",
                observed_value=f"{total_volume:.0f}MB",
                timestamp=time.time(),
                confidence=0.75,
                mitre_technique="T1119",
            )
            deviations.append(dev)
        return deviations

    def _check_bulk_download(
        self,
        user_id: str,
        signals: list[UserSignal],
    ) -> list[BehaviorDeviation]:
        """Detect bulk file downloads."""
        deviations: list[BehaviorDeviation] = []
        download_sigs = [
            s
            for s in signals
            if s.action
            in (
                "download",
                "export",
                "bulk_export",
                "file_copy",
            )
        ]

        if len(download_sigs) >= _BULK_DOWNLOAD_THRESHOLD:
            dev = BehaviorDeviation(
                id=hashlib.sha256(f"bulk_dl:{user_id}".encode()).hexdigest()[:16],
                user_id=user_id,
                indicator=ThreatIndicator.BULK_DOWNLOAD,
                description=(
                    f"{len(download_sigs)} downloads "
                    f"detected (threshold: "
                    f"{_BULK_DOWNLOAD_THRESHOLD})"
                ),
                severity=min(
                    0.6 + (len(download_sigs) / _BULK_DOWNLOAD_THRESHOLD) * 0.15,
                    1.0,
                ),
                baseline_value=str(_BULK_DOWNLOAD_THRESHOLD),
                observed_value=str(len(download_sigs)),
                timestamp=time.time(),
                confidence=0.85,
                mitre_technique="T1530",
            )
            deviations.append(dev)
        return deviations

    def _check_privilege_abuse(
        self,
        user_id: str,
        signals: list[UserSignal],
        baseline: BehavioralBaseline,
    ) -> list[BehaviorDeviation]:
        """Detect privilege abuse (accessing resources beyond role)."""
        deviations: list[BehaviorDeviation] = []
        typical = set(baseline.typical_resources)
        priv_actions = {
            "admin_access",
            "elevate_privilege",
            "modify_permissions",
            "create_admin_user",
            "access_secrets",
            "modify_iam",
        }

        for sig in signals:
            if sig.action in priv_actions and (sig.resource not in typical):
                dev = BehaviorDeviation(
                    id=hashlib.sha256(f"priv:{sig.id}".encode()).hexdigest()[:16],
                    user_id=user_id,
                    indicator=(ThreatIndicator.PRIVILEGE_ABUSE),
                    description=(
                        f"Privilege action '{sig.action}' on atypical resource '{sig.resource}'"
                    ),
                    severity=0.8,
                    baseline_value="standard_access",
                    observed_value=sig.action,
                    timestamp=sig.timestamp,
                    confidence=0.8,
                    mitre_technique="T1078.004",
                )
                deviations.append(dev)
        return deviations

    def _check_unauthorized_tools(
        self,
        user_id: str,
        signals: list[UserSignal],
        baseline: BehavioralBaseline,
    ) -> list[BehaviorDeviation]:
        """Detect unauthorized AI tool or shadow IT usage."""
        deviations: list[BehaviorDeviation] = []
        typical_tools = set(baseline.typical_tools)

        ai_sigs = [s for s in signals if s.source == "ai_tool_monitor"]
        for sig in ai_sigs:
            if sig.action not in typical_tools and sig.action:
                dev = BehaviorDeviation(
                    id=hashlib.sha256(f"tool:{sig.id}".encode()).hexdigest()[:16],
                    user_id=user_id,
                    indicator=(ThreatIndicator.UNAUTHORIZED_TOOL_USE),
                    description=(f"Unauthorized AI tool usage: '{sig.action}' on '{sig.resource}'"),
                    severity=0.65,
                    baseline_value=(",".join(list(typical_tools)[:5]) or "none"),
                    observed_value=sig.action,
                    timestamp=sig.timestamp,
                    confidence=0.7,
                    mitre_technique="T1204",
                )
                deviations.append(dev)
        return deviations

    def _check_resignation_risk(
        self,
        user_id: str,
        signals: list[UserSignal],
    ) -> list[BehaviorDeviation]:
        """Detect resignation risk indicators from HR signals."""
        deviations: list[BehaviorDeviation] = []
        hr_risk_actions = {
            "resignation_submitted",
            "pto_request_bulk",
            "performance_review_negative",
            "job_search_detected",
            "exit_interview_scheduled",
            "badge_usage_decline",
        }

        for sig in signals:
            if sig.action in hr_risk_actions:
                dev = BehaviorDeviation(
                    id=hashlib.sha256(f"resign:{sig.id}".encode()).hexdigest()[:16],
                    user_id=user_id,
                    indicator=(ThreatIndicator.RESIGNATION_RISK),
                    description=(f"HR risk signal: '{sig.action}'"),
                    severity=0.7,
                    baseline_value="normal_engagement",
                    observed_value=sig.action,
                    timestamp=sig.timestamp,
                    confidence=0.75,
                    mitre_technique="T1078",
                )
                deviations.append(dev)
        return deviations

    # -- Risk scoring --

    def _compute_risk_score(
        self,
        user_id: str,
        deviations: list[BehaviorDeviation],
    ) -> InsiderRiskScore:
        """Compute composite risk score from deviations."""
        indicator_scores: dict[str, float] = {}
        for dev in deviations:
            key = dev.indicator.value
            current = indicator_scores.get(key, 0.0)
            indicator_scores[key] = min(
                current + dev.severity * dev.confidence,
                1.0,
            )

        if not deviations:
            overall = 0.0
        else:
            overall = min(
                sum(indicator_scores.values()) / max(len(indicator_scores), 1),
                1.0,
            )

        category = self._classify_category(indicator_scores)
        high_sev = sum(1 for d in deviations if d.severity >= 0.7)
        actions = self._recommend_actions(overall, category, high_sev)
        avg_conf = sum(d.confidence for d in deviations) / len(deviations) if deviations else 0.0

        return InsiderRiskScore(
            user_id=user_id,
            overall_score=round(overall, 3),
            category=category,
            indicator_scores=indicator_scores,
            deviation_count=len(deviations),
            high_severity_count=high_sev,
            recommended_actions=actions,
            confidence=round(avg_conf, 3),
        )

    def _classify_category(
        self,
        scores: dict[str, float],
    ) -> RiskCategory:
        """Classify risk category from indicator scores."""
        resign = scores.get(ThreatIndicator.RESIGNATION_RISK.value, 0)
        hoard = scores.get(ThreatIndicator.DATA_HOARDING.value, 0)
        bulk = scores.get(ThreatIndicator.BULK_DOWNLOAD.value, 0)
        priv = scores.get(ThreatIndicator.PRIVILEGE_ABUSE.value, 0)
        tool = scores.get(
            ThreatIndicator.UNAUTHORIZED_TOOL_USE.value,
            0,
        )

        if resign > 0.5 and (hoard > 0.3 or bulk > 0.3):
            return RiskCategory.FLIGHT_RISK
        if hoard > 0.5 or bulk > 0.5:
            return RiskCategory.DATA_THEFT
        if priv > 0.6:
            return RiskCategory.SABOTAGE
        if tool > 0.5 and priv > 0.3:
            return RiskCategory.ESPIONAGE
        return RiskCategory.NEGLIGENCE

    def _recommend_actions(
        self,
        score: float,
        category: RiskCategory,
        high_sev: int,
    ) -> list[str]:
        """Recommend actions based on risk profile."""
        actions: list[str] = []

        if score >= _AUTO_RESPOND_THRESHOLD:
            actions.append("Immediately restrict data access")
            actions.append("Escalate to security incident team")
        elif score >= _INVESTIGATION_THRESHOLD:
            actions.append("Open formal investigation")
            actions.append("Enable enhanced monitoring")
        elif score >= _HIGH_RISK_SCORE_THRESHOLD:
            actions.append("Flag for manager review")
            actions.append("Increase logging verbosity")

        if category == RiskCategory.FLIGHT_RISK:
            actions.append("Coordinate with HR on retention")
            actions.append("Audit data access permissions")
        elif category == RiskCategory.DATA_THEFT:
            actions.append("Enable DLP blocking rules")
            actions.append("Review recent file transfers")
        elif category == RiskCategory.SABOTAGE:
            actions.append("Restrict admin privileges")
            actions.append("Enable change approval gates")
        elif category == RiskCategory.ESPIONAGE:
            actions.append("Audit AI tool data submissions")
            actions.append("Review code repository access")

        if high_sev >= 3:
            actions.append("Priority: multiple high-severity indicators detected")

        return actions

    # -- Synthetic data --

    def _generate_synthetic_signals(
        self,
        tenant_id: str,
        cutoff: float,
        now: float,
    ) -> list[UserSignal]:
        """Generate synthetic signals for analysis."""
        mid = (cutoff + now) / 2
        return [
            UserSignal(
                id=f"syn-{tenant_id}-1",
                user_id=f"user-{tenant_id}-alice",
                user_email="alice@corp.example",
                source="identity_provider",
                signal_type="login",
                action="login",
                resource="aws-console",
                timestamp=mid,
                geo_location="us-east-1",
                risk_indicators=["off_hours"],
                metadata={"data_volume_mb": 250},
            ),
            UserSignal(
                id=f"syn-{tenant_id}-2",
                user_id=f"user-{tenant_id}-alice",
                user_email="alice@corp.example",
                source="dlp_engine",
                signal_type="data_transfer",
                action="bulk_export",
                resource="s3://corp-data/financials",
                timestamp=mid + 300,
                geo_location="us-east-1",
                risk_indicators=["bulk_transfer"],
                metadata={"data_volume_mb": 500},
            ),
            UserSignal(
                id=f"syn-{tenant_id}-3",
                user_id=f"user-{tenant_id}-alice",
                user_email="alice@corp.example",
                source="hr_system",
                signal_type="hr_event",
                action="resignation_submitted",
                resource="hr-portal",
                timestamp=mid + 600,
                geo_location="us-east-1",
                risk_indicators=["resignation"],
            ),
            UserSignal(
                id=f"syn-{tenant_id}-4",
                user_id=f"user-{tenant_id}-bob",
                user_email="bob@corp.example",
                source="ai_tool_monitor",
                signal_type="ai_usage",
                action="chatgpt_code_paste",
                resource="chatgpt.com",
                timestamp=mid + 120,
                geo_location="eu-west-1",
                risk_indicators=[
                    "unauthorized_tool",
                    "code_paste",
                ],
            ),
            UserSignal(
                id=f"syn-{tenant_id}-5",
                user_id=f"user-{tenant_id}-bob",
                user_email="bob@corp.example",
                source="code_repo",
                signal_type="code_access",
                action="admin_access",
                resource="infra/secrets-manager",
                timestamp=mid + 180,
                geo_location="eu-west-1",
                risk_indicators=["privilege_escalation"],
            ),
        ]
