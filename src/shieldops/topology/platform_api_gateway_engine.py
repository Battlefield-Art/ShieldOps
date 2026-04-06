"""PlatformApiGatewayEngine API gateway health monitoring, rate limit analysis, routing optimi..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PlatformApiGatewayEngine = engine(
    "PlatformApiGatewayEngine",
    module="operations",  # uses record_item
    description="API gateway health monitoring and routing optimization.",
    enums={
        "gateway_policy": EnumDef(
            "GatewayPolicy",
            {
                "RATE_LIMIT": "rate_limit",
                "AUTH_REQUIRED": "auth_required",
                "IP_WHITELIST": "ip_whitelist",
                "CORS": "cors",
                "CUSTOM": "custom",
            },
        ),
        "gateway_health": EnumDef(
            "GatewayHealth",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "OVERLOADED": "overloaded",
                "DOWN": "down",
                "UNKNOWN": "unknown",
            },
        ),
        "routing_mode": EnumDef(
            "RoutingMode",
            {
                "ROUND_ROBIN": "round_robin",
                "WEIGHTED": "weighted",
                "LEAST_CONNECTIONS": "least_connections",
                "HEADER_BASED": "header_based",
                "PATH_BASED": "path_based",
            },
        ),
    },
)

# Backward-compatible re-exports
GatewayPolicy = PlatformApiGatewayEngine.GatewayPolicy
GatewayHealth = PlatformApiGatewayEngine.GatewayHealth
RoutingMode = PlatformApiGatewayEngine.RoutingMode
PlatformApiGatewayRecord = PlatformApiGatewayEngine.Record
PlatformApiGatewayAnalysis = PlatformApiGatewayEngine.Analysis
PlatformApiGatewayReport = PlatformApiGatewayEngine.Report
