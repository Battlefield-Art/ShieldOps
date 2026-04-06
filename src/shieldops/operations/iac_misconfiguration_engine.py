"""IaC Misconfiguration Engine — detect, map to benchmarks, auto-suggest fixes."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

IaCMisconfigurationEngine = engine(
    "IaCMisconfigurationEngine",
    description="Detect IaC misconfigurations, map to benchmarks, auto-suggest fixes.",
    enums={
        "iac_platform": EnumDef(
            "IaCPlatform",
            {
                "TERRAFORM": "terraform",
                "CLOUDFORMATION": "cloudformation",
                "PULUMI": "pulumi",
                "ANSIBLE": "ansible",
                "HELM": "helm",
            },
        ),
        "misconfig_category": EnumDef(
            "MisconfigCategory",
            {
                "OPEN_SECURITY_GROUP": "open_security_group",
                "UNENCRYPTED_STORAGE": "unencrypted_storage",
                "OVERPRIVILEGED_IAM": "overprivileged_iam",
                "PUBLIC_ENDPOINT": "public_endpoint",
                "MISSING_LOGGING": "missing_logging",
            },
        ),
        "compliance_mapping": EnumDef(
            "ComplianceMapping",
            {
                "CIS_AWS": "cis_aws",
                "CIS_GCP": "cis_gcp",
                "CIS_AZURE": "cis_azure",
                "NIST_800_53": "nist_800_53",
                "SOC2_CC": "soc2_cc",
            },
        ),
    },
    score_field="severity_score",
    key_field="misconfig_name",
)

# Backward-compatible re-exports
IaCPlatform = IaCMisconfigurationEngine.IaCPlatform
MisconfigCategory = IaCMisconfigurationEngine.MisconfigCategory
ComplianceMapping = IaCMisconfigurationEngine.ComplianceMapping
MisconfigRecord = IaCMisconfigurationEngine.Record
MisconfigAnalysis = IaCMisconfigurationEngine.Analysis
MisconfigReport = IaCMisconfigurationEngine.Report
