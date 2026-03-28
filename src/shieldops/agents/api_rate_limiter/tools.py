"""API Rate Limiter — Tool functions for abuse detection and enforcement."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from typing import Any

import structlog

from .models import (
    AbuseDetection,
    AbusePattern,
    ActionType,
    ClientProfile,
    ClientRequest,
    EnforcementAction,
    RateLimitRule,
)

logger = structlog.get_logger()

_DEFAULT_RPM = 60
_AUTH_FAILURE_THRESHOLD = 10
_SCRAPING_ENDPOINT_THRESHOLD = 20
_BRUTE_FORCE_THRESHOLD = 5
_DISTRIBUTED_IP_THRESHOLD = 10


class APIRateLimiterToolkit:
    """Tools for intelligent API rate limiting and abuse detection."""

    def __init__(
        self,
        redis_client: Any | None = None,
        alert_sink: Any | None = None,
        geo_service: Any | None = None,
    ) -> None:
        self._redis = redis_client
        self._alert_sink = alert_sink
        self._geo_service = geo_service
        self._request_log: dict[str, list[ClientRequest]] = defaultdict(list)
        self._rules: dict[str, RateLimitRule] = {}
        self._blocked: set[str] = set()
        self._throttled: set[str] = set()

    async def ingest_requests(
        self,
        raw_requests: list[dict[str, Any]],
    ) -> list[ClientRequest]:
        """Ingest raw API requests and normalize them."""
        logger.info(
            "api_rate_limiter.ingest",
            count=len(raw_requests),
        )
        ingested: list[ClientRequest] = []
        for raw in raw_requests:
            req = ClientRequest(
                client_id=raw.get("client_id", "unknown"),
                ip_address=raw.get(
                    "ip_address",
                    "0.0.0.0",  # noqa: S104  # nosec B104
                ),
                endpoint=raw.get("endpoint", "/"),
                method=raw.get("method", "GET"),
                status_code=raw.get("status_code", 200),
                timestamp=raw.get("timestamp", time.time()),
                user_agent=raw.get("user_agent", ""),
                response_time_ms=raw.get("response_time_ms", 0.0),
                payload_size_bytes=raw.get("payload_size_bytes", 0),
                auth_token_hash=raw.get("auth_token_hash", ""),
                geo_country=raw.get("geo_country", ""),
            )
            self._request_log[req.client_id].append(req)
            ingested.append(req)
        # Ring buffer per client
        for cid in self._request_log:
            if len(self._request_log[cid]) > 50000:
                self._request_log[cid] = self._request_log[cid][-50000:]
        return ingested

    async def build_client_profiles(
        self,
        window_minutes: int = 5,
    ) -> list[ClientProfile]:
        """Build behavioral profiles for all active clients."""
        logger.info(
            "api_rate_limiter.build_profiles",
            window_minutes=window_minutes,
        )
        cutoff = time.time() - (window_minutes * 60)
        profiles: list[ClientProfile] = []

        for client_id, requests in self._request_log.items():
            recent = [r for r in requests if r.timestamp >= cutoff]
            if not recent:
                continue

            endpoints = {r.endpoint for r in recent}
            ips = {r.ip_address for r in recent}
            countries = list({r.geo_country for r in recent if r.geo_country})
            auth_failures = sum(1 for r in recent if r.status_code in (401, 403))
            errors = sum(1 for r in recent if r.status_code >= 400)
            error_rate = errors / len(recent) if recent else 0.0
            avg_rt = sum(r.response_time_ms for r in recent) / len(recent) if recent else 0.0
            rpm = len(recent) / max(window_minutes, 1)

            # Risk scoring
            risk = 0.0
            if rpm > _DEFAULT_RPM:
                risk += min((rpm - _DEFAULT_RPM) / _DEFAULT_RPM, 0.3)
            if auth_failures > _AUTH_FAILURE_THRESHOLD:
                risk += 0.3
            if len(endpoints) > _SCRAPING_ENDPOINT_THRESHOLD:
                risk += 0.2
            if len(ips) > _DISTRIBUTED_IP_THRESHOLD:
                risk += 0.2
            risk = min(risk, 1.0)

            profiles.append(
                ClientProfile(
                    client_id=client_id,
                    total_requests=len(recent),
                    requests_per_minute=round(rpm, 2),
                    unique_endpoints=len(endpoints),
                    error_rate=round(error_rate, 4),
                    avg_response_time_ms=round(avg_rt, 2),
                    auth_failure_count=auth_failures,
                    distinct_ips=len(ips),
                    geo_countries=countries,
                    risk_score=round(risk, 4),
                )
            )
        return profiles

    async def detect_abuse_patterns(
        self,
        profiles: list[ClientProfile],
    ) -> list[AbuseDetection]:
        """Detect abuse patterns from client profiles."""
        logger.info(
            "api_rate_limiter.detect_abuse",
            client_count=len(profiles),
        )
        detections: list[AbuseDetection] = []

        for profile in profiles:
            # Credential stuffing
            if profile.auth_failure_count > _AUTH_FAILURE_THRESHOLD:
                detections.append(
                    AbuseDetection(
                        client_id=profile.client_id,
                        pattern=AbusePattern.CREDENTIAL_STUFFING,
                        confidence=min(
                            profile.auth_failure_count / (_AUTH_FAILURE_THRESHOLD * 2),
                            0.99,
                        ),
                        severity="critical" if profile.auth_failure_count > 50 else "high",
                        evidence={
                            "auth_failures": profile.auth_failure_count,
                            "distinct_ips": profile.distinct_ips,
                            "error_rate": profile.error_rate,
                        },
                        description=(
                            f"Client {profile.client_id}: "
                            f"{profile.auth_failure_count} auth failures "
                            f"from {profile.distinct_ips} IPs"
                        ),
                        first_seen=time.time(),
                        request_count=profile.total_requests,
                    )
                )

            # API scraping
            if (
                profile.unique_endpoints > _SCRAPING_ENDPOINT_THRESHOLD
                and profile.requests_per_minute > _DEFAULT_RPM
            ):
                detections.append(
                    AbuseDetection(
                        client_id=profile.client_id,
                        pattern=AbusePattern.API_SCRAPING,
                        confidence=0.85,
                        severity="high",
                        evidence={
                            "unique_endpoints": profile.unique_endpoints,
                            "rpm": profile.requests_per_minute,
                        },
                        description=(
                            f"Client {profile.client_id}: "
                            f"{profile.unique_endpoints} endpoints at "
                            f"{profile.requests_per_minute} rpm"
                        ),
                        first_seen=time.time(),
                        request_count=profile.total_requests,
                    )
                )

            # Brute force
            if profile.auth_failure_count > _BRUTE_FORCE_THRESHOLD and profile.distinct_ips <= 2:
                detections.append(
                    AbuseDetection(
                        client_id=profile.client_id,
                        pattern=AbusePattern.BRUTE_FORCE,
                        confidence=0.9,
                        severity="high",
                        evidence={
                            "auth_failures": profile.auth_failure_count,
                            "single_ip": profile.distinct_ips <= 2,
                        },
                        description=(
                            f"Client {profile.client_id}: "
                            f"{profile.auth_failure_count} auth failures "
                            f"from {profile.distinct_ips} IP(s)"
                        ),
                        first_seen=time.time(),
                        request_count=profile.total_requests,
                    )
                )

            # Distributed attack
            if (
                profile.distinct_ips > _DISTRIBUTED_IP_THRESHOLD
                and profile.requests_per_minute > _DEFAULT_RPM * 2
            ):
                detections.append(
                    AbuseDetection(
                        client_id=profile.client_id,
                        pattern=AbusePattern.DISTRIBUTED_ATTACK,
                        confidence=0.8,
                        severity="critical",
                        evidence={
                            "distinct_ips": profile.distinct_ips,
                            "rpm": profile.requests_per_minute,
                            "countries": profile.geo_countries,
                        },
                        description=(
                            f"Client {profile.client_id}: "
                            f"{profile.distinct_ips} IPs, "
                            f"{profile.requests_per_minute} rpm"
                        ),
                        first_seen=time.time(),
                        request_count=profile.total_requests,
                    )
                )

        return detections

    async def generate_adaptive_rules(
        self,
        detections: list[AbuseDetection],
        profiles: list[ClientProfile],
    ) -> list[RateLimitRule]:
        """Generate adaptive rate limit rules based on detections."""
        logger.info(
            "api_rate_limiter.generate_rules",
            detection_count=len(detections),
        )
        rules: list[RateLimitRule] = []
        detected_clients = {d.client_id for d in detections}

        for detection in detections:
            action = ActionType.THROTTLE
            rpm = _DEFAULT_RPM // 2
            ttl = 3600

            if detection.severity == "critical":
                action = ActionType.BLOCK
                rpm = 0
                ttl = 7200
            elif detection.severity == "high":
                action = ActionType.THROTTLE
                rpm = _DEFAULT_RPM // 4
                ttl = 3600
            elif detection.pattern == AbusePattern.CREDENTIAL_STUFFING:
                action = ActionType.CHALLENGE
                rpm = 5
                ttl = 1800

            rule = RateLimitRule(
                rule_id=f"rule-{uuid.uuid4().hex[:8]}",
                client_id=detection.client_id,
                endpoint_pattern="*",
                requests_per_minute=rpm,
                burst_limit=max(rpm * 2, 1),
                action=action,
                reason=(f"{detection.pattern.value}: {detection.description}"),
                ttl_seconds=ttl,
                adaptive=True,
            )
            rules.append(rule)
            self._rules[rule.rule_id] = rule

        # Generous limits for clean clients
        for profile in profiles:
            if profile.client_id not in detected_clients and profile.risk_score < 0.2:
                rule = RateLimitRule(
                    rule_id=f"rule-{uuid.uuid4().hex[:8]}",
                    client_id=profile.client_id,
                    endpoint_pattern="*",
                    requests_per_minute=_DEFAULT_RPM * 2,
                    burst_limit=_DEFAULT_RPM * 4,
                    action=ActionType.ALLOW,
                    reason="clean_client_adaptive_boost",
                    ttl_seconds=3600,
                    adaptive=True,
                )
                rules.append(rule)
                self._rules[rule.rule_id] = rule

        return rules

    async def enforce_rules(
        self,
        rules: list[RateLimitRule],
    ) -> list[EnforcementAction]:
        """Enforce rate limit rules against clients."""
        logger.info(
            "api_rate_limiter.enforce",
            rule_count=len(rules),
        )
        actions: list[EnforcementAction] = []

        for rule in rules:
            if rule.action == ActionType.BLOCK:
                self._blocked.add(rule.client_id)
                self._throttled.discard(rule.client_id)
            elif rule.action in (
                ActionType.THROTTLE,
                ActionType.CHALLENGE,
            ):
                self._throttled.add(rule.client_id)
            elif rule.action == ActionType.ALLOW:
                self._blocked.discard(rule.client_id)
                self._throttled.discard(rule.client_id)

            actions.append(
                EnforcementAction(
                    client_id=rule.client_id,
                    action=rule.action,
                    rule_id=rule.rule_id,
                    reason=rule.reason,
                    timestamp=time.time(),
                    duration_seconds=rule.ttl_seconds,
                )
            )

        return actions

    async def get_enforcement_summary(self) -> dict[str, Any]:
        """Get current enforcement summary."""
        return {
            "blocked_clients": list(self._blocked),
            "throttled_clients": list(self._throttled),
            "active_rules": len(self._rules),
            "blocked_count": len(self._blocked),
            "throttled_count": len(self._throttled),
            "timestamp": time.time(),
        }
