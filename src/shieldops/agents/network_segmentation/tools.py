"""Network Segmentation Agent — Tool functions for zone discovery and enforcement."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    NetworkZone,
    PolicyEnforcement,
    SegmentationViolation,
    TrafficFlow,
    ViolationSeverity,
    ZoneType,
)

logger = structlog.get_logger()

# Zone-pair authorization matrix: (source_type, dest_type) -> allowed
_DEFAULT_ZONE_MATRIX: dict[tuple[str, str], bool] = {
    (ZoneType.PUBLIC, ZoneType.DMZ): True,
    (ZoneType.DMZ, ZoneType.INTERNAL): True,
    (ZoneType.INTERNAL, ZoneType.INTERNAL): True,
    (ZoneType.INTERNAL, ZoneType.RESTRICTED): False,
    (ZoneType.PUBLIC, ZoneType.INTERNAL): False,
    (ZoneType.PUBLIC, ZoneType.RESTRICTED): False,
    (ZoneType.PUBLIC, ZoneType.MANAGEMENT): False,
    (ZoneType.DMZ, ZoneType.RESTRICTED): False,
    (ZoneType.DMZ, ZoneType.MANAGEMENT): False,
    (ZoneType.MANAGEMENT, ZoneType.MANAGEMENT): True,
    (ZoneType.MANAGEMENT, ZoneType.INTERNAL): True,
    (ZoneType.MANAGEMENT, ZoneType.RESTRICTED): True,
}

# MITRE ATT&CK techniques related to lateral movement / network
_VIOLATION_MITRE_MAP: dict[str, str] = {
    "unauthorized_cross_zone": "T1021",  # Remote Services
    "restricted_zone_access": "T1570",  # Lateral Tool Transfer
    "management_plane_exposure": "T1133",  # External Remote Services
    "excessive_egress": "T1048",  # Exfiltration Over Alternative Protocol
    "port_scan_pattern": "T1046",  # Network Service Discovery
}


class NetworkSegmentationToolkit:
    """Tools for discovering zones, mapping traffic, and enforcing segmentation."""

    def __init__(
        self,
        network_client: Any | None = None,
        firewall_client: Any | None = None,
        policy_engine: Any | None = None,
    ) -> None:
        self._network_client = network_client
        self._firewall_client = firewall_client
        self._policy_engine = policy_engine
        self._zone_cache: dict[str, NetworkZone] = {}
        self._flow_cache: list[TrafficFlow] = []
        self._zone_matrix: dict[tuple[str, str], bool] = dict(_DEFAULT_ZONE_MATRIX)

    async def discover_network_zones(
        self,
        tenant_id: str,
        environment: str = "production",
    ) -> list[NetworkZone]:
        """Discover network zones from infrastructure sources."""
        logger.info(
            "network_segmentation.discover_zones",
            tenant_id=tenant_id,
            environment=environment,
        )

        if self._network_client:
            raw_zones = await self._network_client.list_zones(
                tenant_id=tenant_id, environment=environment
            )
            zones = [NetworkZone(**z) for z in raw_zones]
        else:
            # Synthesize representative zones for analysis
            zones = self._synthesize_zones(tenant_id, environment)

        for zone in zones:
            self._zone_cache[zone.id] = zone

        logger.info(
            "network_segmentation.zones_discovered",
            count=len(zones),
        )
        return zones

    async def map_traffic_flows(
        self,
        tenant_id: str,
        zone_ids: list[str] | None = None,
    ) -> list[TrafficFlow]:
        """Map observed traffic flows between discovered zones."""
        logger.info(
            "network_segmentation.map_traffic",
            tenant_id=tenant_id,
            zone_count=len(zone_ids) if zone_ids else 0,
        )

        if self._network_client:
            raw_flows = await self._network_client.get_flows(tenant_id=tenant_id, zone_ids=zone_ids)
            flows = [TrafficFlow(**f) for f in raw_flows]
        else:
            flows = self._synthesize_flows(zone_ids or list(self._zone_cache))

        # Determine authorization based on zone matrix
        for flow in flows:
            src_zone = self._zone_cache.get(flow.source_zone)
            dst_zone = self._zone_cache.get(flow.dest_zone)
            if src_zone and dst_zone:
                key = (src_zone.zone_type.value, dst_zone.zone_type.value)
                flow.authorized = self._zone_matrix.get(key, False)

        self._flow_cache = flows
        logger.info(
            "network_segmentation.flows_mapped",
            total=len(flows),
            unauthorized=sum(1 for f in flows if not f.authorized),
        )
        return flows

    async def detect_violations(
        self,
        flows: list[TrafficFlow],
    ) -> list[SegmentationViolation]:
        """Detect segmentation policy violations from traffic flows."""
        logger.info(
            "network_segmentation.detect_violations",
            flow_count=len(flows),
        )

        violations: list[SegmentationViolation] = []
        for flow in flows:
            if flow.authorized:
                continue

            src_zone = self._zone_cache.get(flow.source_zone)
            dst_zone = self._zone_cache.get(flow.dest_zone)
            src_type = src_zone.zone_type.value if src_zone else "unknown"
            dst_type = dst_zone.zone_type.value if dst_zone else "unknown"

            vtype = self._classify_violation(src_type, dst_type, flow)
            severity = self._assess_severity(vtype, flow)
            mitre = _VIOLATION_MITRE_MAP.get(vtype, "")

            vid = hashlib.sha256(f"{flow.id}:{vtype}".encode()).hexdigest()[:12]

            violations.append(
                SegmentationViolation(
                    id=vid,
                    flow_id=flow.id,
                    source_zone=flow.source_zone,
                    dest_zone=flow.dest_zone,
                    violation_type=vtype,
                    description=(
                        f"Unauthorized {flow.protocol}:{flow.port} "
                        f"from {src_type} to {dst_type} "
                        f"({flow.bytes_per_day:.0f} bytes/day)"
                    ),
                    severity=severity,
                    mitre_technique=mitre,
                )
            )

        logger.info(
            "network_segmentation.violations_detected",
            count=len(violations),
        )
        return violations

    async def enforce_segmentation_policies(
        self,
        violations: list[SegmentationViolation],
    ) -> list[PolicyEnforcement]:
        """Enforce segmentation policies by creating/updating firewall rules."""
        logger.info(
            "network_segmentation.enforce_policies",
            violation_count=len(violations),
        )

        enforcements: list[PolicyEnforcement] = []
        for v in violations:
            action = self._determine_action(v)
            target = f"{v.source_zone}->{v.dest_zone}"
            eid = hashlib.sha256(f"{v.id}:{action}".encode()).hexdigest()[:12]

            applied = False
            success = False
            if self._firewall_client:
                try:
                    result = await self._firewall_client.apply_rule(
                        action=action,
                        source=v.source_zone,
                        destination=v.dest_zone,
                        violation_id=v.id,
                    )
                    applied = True
                    success = result.get("success", False)
                except Exception:
                    logger.exception(
                        "network_segmentation.enforce_error",
                        violation_id=v.id,
                    )
                    applied = True
                    success = False
            else:
                # Dry-run mode — mark as planned
                applied = False
                success = False

            enforcements.append(
                PolicyEnforcement(
                    id=eid,
                    violation_id=v.id,
                    action=action,
                    target=target,
                    applied=applied,
                    success=success,
                )
            )

        logger.info(
            "network_segmentation.enforcements_applied",
            total=len(enforcements),
            applied=sum(1 for e in enforcements if e.applied),
            success=sum(1 for e in enforcements if e.success),
        )
        return enforcements

    # -- internal helpers --

    def _synthesize_zones(self, tenant_id: str, environment: str) -> list[NetworkZone]:
        """Synthesize representative zones for tenants without live data."""
        prefix = f"{tenant_id}-{environment}"
        return [
            NetworkZone(
                id=f"{prefix}-public",
                name="Public Web Tier",
                zone_type=ZoneType.PUBLIC,
                cidrs=["10.0.0.0/24"],
                services=["nginx", "cdn"],
                ingress_rules=["allow 443/tcp from 0.0.0.0/0"],
                egress_rules=["allow 443/tcp to dmz"],
            ),
            NetworkZone(
                id=f"{prefix}-dmz",
                name="DMZ Application Tier",
                zone_type=ZoneType.DMZ,
                cidrs=["10.0.1.0/24"],
                services=["api-gateway", "waf"],
                ingress_rules=["allow 443/tcp from public"],
                egress_rules=["allow 8080/tcp to internal"],
            ),
            NetworkZone(
                id=f"{prefix}-internal",
                name="Internal Services",
                zone_type=ZoneType.INTERNAL,
                cidrs=["10.0.2.0/24"],
                services=["app-server", "cache", "queue"],
                ingress_rules=["allow 8080/tcp from dmz"],
                egress_rules=["allow 5432/tcp to restricted"],
            ),
            NetworkZone(
                id=f"{prefix}-restricted",
                name="Restricted Data Tier",
                zone_type=ZoneType.RESTRICTED,
                cidrs=["10.0.3.0/24"],
                services=["postgres", "redis", "vault"],
                ingress_rules=["allow 5432/tcp from internal"],
                egress_rules=["deny all"],
            ),
            NetworkZone(
                id=f"{prefix}-mgmt",
                name="Management Plane",
                zone_type=ZoneType.MANAGEMENT,
                cidrs=["10.0.255.0/24"],
                services=["bastion", "monitoring", "ci-cd"],
                ingress_rules=["allow 22/tcp from vpn"],
                egress_rules=["allow all to internal,restricted"],
            ),
        ]

    def _synthesize_flows(self, zone_ids: list[str]) -> list[TrafficFlow]:
        """Synthesize representative traffic flows for analysis."""
        flows: list[TrafficFlow] = []
        ts = time.time()
        counter = 0
        for src in zone_ids:
            for dst in zone_ids:
                if src == dst:
                    continue
                fid = hashlib.sha256(f"{src}:{dst}:{ts}".encode()).hexdigest()[:12]
                flows.append(
                    TrafficFlow(
                        id=fid,
                        source_zone=src,
                        dest_zone=dst,
                        protocol="tcp",
                        port=443 if counter % 2 == 0 else 8080,
                        bytes_per_day=float(1000 * (counter + 1)),
                        authorized=False,
                    )
                )
                counter += 1
        return flows

    @staticmethod
    def _classify_violation(src_type: str, dst_type: str, flow: TrafficFlow) -> str:
        """Classify the type of segmentation violation."""
        if dst_type == ZoneType.MANAGEMENT:
            return "management_plane_exposure"
        if dst_type == ZoneType.RESTRICTED:
            return "restricted_zone_access"
        if flow.bytes_per_day > 100_000:
            return "excessive_egress"
        return "unauthorized_cross_zone"

    @staticmethod
    def _assess_severity(violation_type: str, flow: TrafficFlow) -> ViolationSeverity:
        """Assess severity based on violation type and flow characteristics."""
        if violation_type == "management_plane_exposure":
            return ViolationSeverity.CRITICAL
        if violation_type == "restricted_zone_access":
            return ViolationSeverity.HIGH
        if violation_type == "excessive_egress":
            if flow.bytes_per_day > 500_000:
                return ViolationSeverity.HIGH
            return ViolationSeverity.MEDIUM
        if flow.bytes_per_day > 50_000:
            return ViolationSeverity.MEDIUM
        return ViolationSeverity.LOW

    @staticmethod
    def _determine_action(violation: SegmentationViolation) -> str:
        """Determine enforcement action based on violation severity."""
        if violation.severity in (
            ViolationSeverity.CRITICAL,
            ViolationSeverity.HIGH,
        ):
            return "block"
        if violation.severity == ViolationSeverity.MEDIUM:
            return "restrict"
        return "alert"
