"""AttackSurfaceDiscoveryEngine — Discover external attack surface via DNS, ports, and certs."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AttackSurfaceDiscoveryEngine = engine(
    "AttackSurfaceDiscoveryEngine",
    description="Discover external attack surface via DNS, ports, and certs.",
    enums={
        "discovery_method": EnumDef(
            "DiscoveryMethod",
            {
                "DNS_ENUM": "dns_enum",
                "PORT_SCAN": "port_scan",
                "CERT_TRANSPARENCY": "cert_transparency",
                "API_DISCOVERY": "api_discovery",
            },
        ),
        "asset_type": EnumDef(
            "AssetType",
            {
                "WEB_APP": "web_app",
                "API": "api",
                "DNS": "dns",
                "CERTIFICATE": "certificate",
                "CLOUD_RESOURCE": "cloud_resource",
            },
        ),
        "exposure_status": EnumDef(
            "ExposureStatus",
            {
                "EXPOSED": "exposed",
                "PARTIALLY_EXPOSED": "partially_exposed",
                "INTERNAL": "internal",
                "UNKNOWN": "unknown",
            },
        ),
    },
    record_fields=[
        FieldDef("hostname", str, ""),
        FieldDef("port", int, 0),
    ],
)

# Backward-compatible re-exports
DiscoveryMethod = AttackSurfaceDiscoveryEngine.DiscoveryMethod
AssetType = AttackSurfaceDiscoveryEngine.AssetType
ExposureStatus = AttackSurfaceDiscoveryEngine.ExposureStatus
DiscoveryRecord = AttackSurfaceDiscoveryEngine.Record
DiscoveryAnalysis = AttackSurfaceDiscoveryEngine.Analysis
DiscoveryReport = AttackSurfaceDiscoveryEngine.Report
