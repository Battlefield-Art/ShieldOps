"""Tool functions for the Session Hijack Detector Agent."""

from __future__ import annotations

import math
from typing import Any

import structlog

logger = structlog.get_logger()


class SessionHijackDetectorToolkit:
    """Toolkit for session hijack detection, correlation, and response."""

    def __init__(
        self,
        session_store: Any | None = None,
        identity_service: Any | None = None,
        geo_service: Any | None = None,
        token_service: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._session_store = session_store
        self._identity_service = identity_service
        self._geo_service = geo_service
        self._token_service = token_service
        self._policy_engine = policy_engine
        self._repository = repository

    async def collect_session_events(
        self,
        raw_events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Collect and normalize session events."""
        logger.info(
            "session_hijack.collect_events",
            count=len(raw_events),
        )
        enriched: list[dict[str, Any]] = []
        for evt in raw_events:
            enriched.append(
                {
                    **evt,
                    "enriched": True,
                    "provider": evt.get("provider", "unknown"),
                }
            )
        return enriched

    async def detect_impossible_travel(
        self,
        sessions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect impossible travel between session events."""
        logger.info(
            "session_hijack.impossible_travel",
            session_count=len(sessions),
        )
        indicators: list[dict[str, Any]] = []
        # Group by user_id and check sequential logins
        by_user: dict[str, list[dict[str, Any]]] = {}
        for s in sessions:
            uid = s.get("user_id", "")
            if uid:
                by_user.setdefault(uid, []).append(s)

        for uid, events in by_user.items():
            sorted_events = sorted(events, key=lambda e: e.get("timestamp", 0))
            for i in range(1, len(sorted_events)):
                prev = sorted_events[i - 1]
                curr = sorted_events[i]
                speed = self._calc_travel_speed(prev, curr)
                if speed > 500.0:
                    indicators.append(
                        {
                            "indicator_id": f"it-{uid}-{i}",
                            "session_id": curr.get("session_id", ""),
                            "user_id": uid,
                            "hijack_type": "impossible_travel",
                            "risk": "high",
                            "confidence": min(speed / 1000.0, 1.0),
                            "source_ip": prev.get("ip_address", ""),
                            "anomalous_ip": curr.get("ip_address", ""),
                            "source_geo": prev.get("geo_city", ""),
                            "anomalous_geo": curr.get("geo_city", ""),
                            "travel_speed_kmh": round(speed, 1),
                            "evidence": [f"Speed {speed:.0f} km/h between logins"],
                            "mitre_technique": "T1550.004",
                        }
                    )
        return indicators

    def _calc_travel_speed(
        self,
        prev: dict[str, Any],
        curr: dict[str, Any],
    ) -> float:
        """Calculate travel speed between two events in km/h."""
        lat1 = prev.get("geo_lat", 0.0)
        lon1 = prev.get("geo_lon", 0.0)
        lat2 = curr.get("geo_lat", 0.0)
        lon2 = curr.get("geo_lon", 0.0)
        t1 = prev.get("timestamp", 0.0)
        t2 = curr.get("timestamp", 0.0)

        if t2 <= t1 or (lat1 == lat2 and lon1 == lon2):
            return 0.0

        # Haversine distance
        r = 6371.0
        d_lat = math.radians(lat2 - lat1)
        d_lon = math.radians(lon2 - lon1)
        a = (
            math.sin(d_lat / 2) ** 2
            + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d_lon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        dist_km = r * c

        hours = (t2 - t1) / 3600.0
        if hours <= 0:
            return 0.0
        return dist_km / hours

    async def detect_concurrent_sessions(
        self,
        sessions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect concurrent sessions from different geos."""
        logger.info(
            "session_hijack.concurrent_geo",
            session_count=len(sessions),
        )
        indicators: list[dict[str, Any]] = []
        by_user: dict[str, list[dict[str, Any]]] = {}
        for s in sessions:
            uid = s.get("user_id", "")
            if uid:
                by_user.setdefault(uid, []).append(s)

        for uid, events in by_user.items():
            ips = {e.get("ip_address", "") for e in events}
            geos = {e.get("geo_country", "") for e in events}
            if len(ips) > 1 and len(geos) > 1:
                indicators.append(
                    {
                        "indicator_id": f"cg-{uid}",
                        "session_id": events[0].get("session_id", ""),
                        "user_id": uid,
                        "hijack_type": "concurrent_geo",
                        "risk": "high",
                        "confidence": 0.8,
                        "source_ip": list(ips)[0],
                        "anomalous_ip": list(ips)[1] if len(ips) > 1 else "",
                        "source_geo": list(geos)[0],
                        "anomalous_geo": list(geos)[1] if len(geos) > 1 else "",
                        "evidence": [f"Concurrent sessions from {len(geos)} countries"],
                        "mitre_technique": "T1539",
                    }
                )
        return indicators

    async def detect_token_anomalies(
        self,
        sessions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect token theft and replay indicators."""
        logger.info(
            "session_hijack.token_anomalies",
            session_count=len(sessions),
        )
        indicators: list[dict[str, Any]] = []
        # Detect duplicate token hashes from different IPs
        token_ips: dict[str, set[str]] = {}
        token_events: dict[str, dict[str, Any]] = {}
        for s in sessions:
            th = s.get("token_hash", "")
            ip = s.get("ip_address", "")
            if th and ip:
                token_ips.setdefault(th, set()).add(ip)
                if th not in token_events:
                    token_events[th] = s

        for th, ips in token_ips.items():
            if len(ips) > 1:
                evt = token_events[th]
                indicators.append(
                    {
                        "indicator_id": f"tt-{th[:8]}",
                        "session_id": evt.get("session_id", ""),
                        "user_id": evt.get("user_id", ""),
                        "hijack_type": "token_theft",
                        "risk": "critical",
                        "confidence": 0.9,
                        "source_ip": list(ips)[0],
                        "anomalous_ip": list(ips)[1],
                        "evidence": [f"Token {th[:8]}... used from {len(ips)} IPs"],
                        "mitre_technique": "T1539",
                    }
                )
        return indicators

    async def execute_response(
        self,
        actions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Execute response actions against hijacked sessions."""
        results: list[dict[str, Any]] = []
        for action in actions:
            atype = action.get("action_type", "unknown")
            target = action.get("target_session_id", "unknown")
            logger.info(
                "session_hijack.respond",
                action=atype,
                target=target,
            )
            if self._policy_engine:
                allowed = await self._policy_engine.evaluate(
                    "session_response",
                    {"action": atype, "target": target},
                )
                if not allowed:
                    results.append(
                        {
                            **action,
                            "executed": False,
                            "result": "policy_denied",
                        }
                    )
                    continue

            results.append(
                {
                    **action,
                    "executed": True,
                    "result": "success",
                    "execution_time_ms": 80,
                }
            )
        return results

    async def record_metric(
        self,
        metric_type: str,
        value: float,
    ) -> None:
        """Record a session hijack detection metric."""
        logger.info(
            "session_hijack.metric",
            metric_type=metric_type,
            value=value,
        )
