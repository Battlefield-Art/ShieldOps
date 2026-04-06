"""OCSF Schema Normalizer Engine — track and optimize OCSF schema normalization quality."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OCSFSchemaNormalizerEngine = engine(
    "OCSFSchemaNormalizerEngine",
    description="Track and optimize OCSF schema normalization quality.",
    enums={
        "vendor_source": EnumDef(
            "VendorSource",
            {
                "CROWDSTRIKE": "crowdstrike",
                "MICROSOFT_DEFENDER": "microsoft_defender",
                "WIZ": "wiz",
                "SPLUNK": "splunk",
                "ELASTIC": "elastic",
                "DATADOG": "datadog",
                "NEWRELIC": "newrelic",
                "PAGERDUTY": "pagerduty",
                "SERVICENOW": "servicenow",
                "AWS": "aws",
                "GCP": "gcp",
                "AZURE": "azure",
            },
        ),
        "ocsf_category": EnumDef(
            "OCSFCategory",
            {
                "SECURITY_FINDING": "security_finding",
                "DETECTION_FINDING": "detection_finding",
                "VULNERABILITY_FINDING": "vulnerability_finding",
                "IDENTITY_ACTIVITY": "identity_activity",
                "NETWORK_ACTIVITY": "network_activity",
                "SYSTEM_ACTIVITY": "system_activity",
            },
        ),
        "normalization_quality": EnumDef(
            "NormalizationQuality",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "MODERATE": "moderate",
                "POOR": "poor",
                "FAILED": "failed",
            },
        ),
    },
    record_fields=[
        FieldDef("field_mapping_count", int, 0),
        FieldDef("unmapped_fields", int, 0),
    ],
    score_field="completeness_score",
)

# Backward-compatible re-exports
VendorSource = OCSFSchemaNormalizerEngine.VendorSource
OCSFCategory = OCSFSchemaNormalizerEngine.OCSFCategory
NormalizationQuality = OCSFSchemaNormalizerEngine.NormalizationQuality
NormalizationRecord = OCSFSchemaNormalizerEngine.Record
NormalizationAnalysis = OCSFSchemaNormalizerEngine.Analysis
NormalizationReport = OCSFSchemaNormalizerEngine.Report
