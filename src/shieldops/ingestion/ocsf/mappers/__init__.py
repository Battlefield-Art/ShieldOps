"""OCSF vendor-specific mapper implementations."""

from shieldops.ingestion.ocsf.mappers.azure_activity import AzureActivityMapper
from shieldops.ingestion.ocsf.mappers.cloudtrail import CloudTrailMapper
from shieldops.ingestion.ocsf.mappers.crowdstrike import CrowdStrikeMapper
from shieldops.ingestion.ocsf.mappers.guardduty import GuardDutyMapper
from shieldops.ingestion.ocsf.mappers.syslog import SyslogMapper
from shieldops.ingestion.ocsf.mappers.vpc_flow import VPCFlowMapper

__all__ = [
    "AzureActivityMapper",
    "CloudTrailMapper",
    "CrowdStrikeMapper",
    "GuardDutyMapper",
    "SyslogMapper",
    "VPCFlowMapper",
]
