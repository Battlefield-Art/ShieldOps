"""Authentication Pattern Analyzer — analyze authentication patterns and detect anomalies."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AuthenticationPatternAnalyzer = engine(
    "AuthenticationPatternAnalyzer",
    description="Analyze authentication patterns, detect anomalies, and track login behaviors.",
    enums={
        "auth_method": EnumDef(
            "AuthMethod",
            {
                "PASSWORD": "password",
                "MFA": "mfa",
                "SSO": "sso",
                "CERTIFICATE": "certificate",
                "BIOMETRIC": "biometric",
            },
        ),
        "pattern_type": EnumDef(
            "PatternType",
            {
                "LOGIN_TIME": "login_time",
                "LOCATION": "location",
                "DEVICE": "device",
                "FAILURE_RATE": "failure_rate",
                "SESSION_DURATION": "session_duration",
            },
        ),
        "pattern_status": EnumDef(
            "PatternStatus",
            {
                "NORMAL": "normal",
                "UNUSUAL": "unusual",
                "SUSPICIOUS": "suspicious",
                "ANOMALOUS": "anomalous",
                "BLOCKED": "blocked",
            },
        ),
    },
    score_field="pattern_score",
    key_field="user_name",
)

# Backward-compatible re-exports
AuthMethod = AuthenticationPatternAnalyzer.AuthMethod
PatternType = AuthenticationPatternAnalyzer.PatternType
PatternStatus = AuthenticationPatternAnalyzer.PatternStatus
AuthPatternRecord = AuthenticationPatternAnalyzer.Record
AuthPatternAnalysis = AuthenticationPatternAnalyzer.Analysis
AuthPatternReport = AuthenticationPatternAnalyzer.Report
