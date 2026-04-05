"""Tests for all vendor-specific OCSF mappers."""

from __future__ import annotations

from shieldops.ingestion.ocsf.mappers.azure_activity import AzureActivityMapper
from shieldops.ingestion.ocsf.mappers.cloudtrail import CloudTrailMapper
from shieldops.ingestion.ocsf.mappers.crowdstrike import CrowdStrikeMapper
from shieldops.ingestion.ocsf.mappers.guardduty import GuardDutyMapper
from shieldops.ingestion.ocsf.mappers.syslog import SyslogMapper
from shieldops.ingestion.ocsf.mappers.vpc_flow import VPCFlowMapper
from shieldops.ingestion.ocsf.models import (
    OCSFAPIActivity,
    OCSFAuthenticationEvent,
    OCSFBaseEvent,
    OCSFNetworkActivity,
    OCSFSecurityFinding,
)


# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------
class TestCloudTrailMapper:
    def setup_method(self) -> None:
        self.mapper = CloudTrailMapper()

    def test_console_login_success(self) -> None:
        raw = {
            "eventName": "ConsoleLogin",
            "eventTime": "2026-03-15T08:30:00Z",
            "userIdentity": {"userName": "admin@corp.com", "arn": "arn:aws:iam::123:user/admin"},
            "sourceIPAddress": "203.0.113.50",
            "responseElements": {"ConsoleLogin": "Success"},
        }
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFAuthenticationEvent)
        assert result.user == "admin@corp.com"
        assert result.src_ip == "203.0.113.50"
        assert result.status == "success"
        assert result.action == "login"
        assert result.severity == "informational"
        assert result.normalized["category_uid"] == 3001

    def test_console_login_failure(self) -> None:
        raw = {
            "eventName": "ConsoleLogin",
            "eventTime": "2026-03-15T08:30:00Z",
            "userIdentity": {"userName": "attacker"},
            "sourceIPAddress": "198.51.100.1",
            "responseElements": {"ConsoleLogin": "Failure"},
        }
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFAuthenticationEvent)
        assert result.status == "failure"
        assert result.severity == "medium"

    def test_assume_role(self) -> None:
        raw = {
            "eventName": "AssumeRole",
            "eventTime": "2026-03-15T09:00:00Z",
            "userIdentity": {"arn": "arn:aws:iam::123:role/deployer"},
            "sourceIPAddress": "10.0.0.5",
        }
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFAuthenticationEvent)
        assert result.status == "success"

    def test_api_call(self) -> None:
        raw = {
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2026-03-15T10:00:00Z",
            "userIdentity": {"arn": "arn:aws:iam::123:user/dev"},
            "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-abc"}]}},
        }
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFAPIActivity)
        assert result.api_name == "DescribeInstances"
        assert result.service == "ec2.amazonaws.com"
        assert result.response_code == 200
        assert result.actor == "arn:aws:iam::123:user/dev"

    def test_access_denied(self) -> None:
        raw = {
            "eventName": "DeleteBucket",
            "eventSource": "s3.amazonaws.com",
            "eventTime": "2026-03-15T11:00:00Z",
            "userIdentity": {"arn": "arn:aws:iam::123:user/intern"},
            "errorCode": "AccessDenied",
            "errorMessage": "Access Denied",
        }
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFAPIActivity)
        assert result.response_code == 403
        assert result.severity == "high"

    def test_missing_fields_no_crash(self) -> None:
        result = self.mapper.map({})
        assert isinstance(result, (OCSFAPIActivity, OCSFAuthenticationEvent, OCSFBaseEvent))


# ---------------------------------------------------------------------------
# CrowdStrike
# ---------------------------------------------------------------------------
class TestCrowdStrikeMapper:
    def setup_method(self) -> None:
        self.mapper = CrowdStrikeMapper()

    def test_detection(self) -> None:
        raw = {
            "detection_id": "ldt:abc123",
            "detect_name": "Credential Dumping via Mimikatz",
            "severity": 4,
            "confidence": 95,
            "first_behavior": "2026-03-14T22:00:00Z",
            "last_behavior": "2026-03-14T22:05:00Z",
            "device": {
                "device_id": "dev001",
                "hostname": "workstation-42",
                "os_version": "Windows 11",
                "platform_name": "Windows",
            },
            "behaviors": [
                {"tactic": "Credential Access", "technique": "T1003"},
                {"tactic": "Credential Access", "technique": "T1003.001"},
            ],
        }
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFSecurityFinding)
        assert result.finding_id == "ldt:abc123"
        assert result.title == "Credential Dumping via Mimikatz"
        assert result.severity == "high"
        assert result.confidence == 95.0
        assert result.first_seen is not None
        assert result.last_seen is not None
        assert len(result.resources) == 1
        assert result.resources[0]["name"] == "workstation-42"
        assert result.normalized["tactics"] == ["Credential Access"]
        assert "T1003" in result.normalized["techniques"]

    def test_epoch_milliseconds(self) -> None:
        raw = {
            "detection_id": "ldt:epoch",
            "detect_name": "Test",
            "severity": 2,
            "first_behavior": 1710460800000,  # epoch ms
        }
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFSecurityFinding)
        assert result.first_seen is not None

    def test_missing_fields_no_crash(self) -> None:
        result = self.mapper.map({})
        assert isinstance(result, OCSFSecurityFinding)
        assert result.finding_id == ""


# ---------------------------------------------------------------------------
# GuardDuty
# ---------------------------------------------------------------------------
class TestGuardDutyMapper:
    def setup_method(self) -> None:
        self.mapper = GuardDutyMapper()

    def test_finding(self) -> None:
        raw = {
            "Id": "gd-finding-001",
            "Title": "Unauthorized API call from known malicious IP",
            "Description": "API call from known bad actor",
            "Severity": 8.5,
            "Confidence": 90,
            "Type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
            "CreatedAt": "2026-03-13T12:00:00Z",
            "UpdatedAt": "2026-03-14T06:00:00Z",
            "Resource": {
                "ResourceType": "AccessKey",
                "InstanceDetails": {"InstanceId": "i-target001"},
            },
            "Service": {
                "EventFirstSeen": "2026-03-13T12:00:00Z",
                "EventLastSeen": "2026-03-14T06:00:00Z",
            },
        }
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFSecurityFinding)
        assert result.finding_id == "gd-finding-001"
        assert result.severity == "critical"
        assert result.confidence == 90.0
        assert result.first_seen is not None
        assert result.last_seen is not None
        assert len(result.resources) == 1
        assert result.normalized["finding_type"] == "UnauthorizedAccess:IAMUser/MaliciousIPCaller"

    def test_low_severity(self) -> None:
        raw = {"Id": "gd-low", "Title": "Low test", "Severity": 1.5}
        result = self.mapper.map(raw)
        assert result.severity == "low"

    def test_missing_fields_no_crash(self) -> None:
        result = self.mapper.map({})
        assert isinstance(result, OCSFSecurityFinding)


# ---------------------------------------------------------------------------
# VPC Flow Logs
# ---------------------------------------------------------------------------
class TestVPCFlowMapper:
    def setup_method(self) -> None:
        self.mapper = VPCFlowMapper()

    def test_dict_format_accept(self) -> None:
        raw = {
            "srcaddr": "10.0.0.1",
            "dstaddr": "10.0.0.2",
            "srcport": "54321",
            "dstport": "443",
            "protocol": "6",
            "bytes": "2048",
            "packets": "15",
            "action": "ACCEPT",
            "start": "1710460800",
        }
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFNetworkActivity)
        assert result.src_ip == "10.0.0.1"
        assert result.dst_port == 443
        assert result.protocol == "tcp"
        assert result.bytes_in == 2048
        assert result.action == "allow"

    def test_dict_format_reject(self) -> None:
        raw = {
            "srcaddr": "198.51.100.5",
            "dstaddr": "10.0.0.3",
            "srcport": "12345",
            "dstport": "22",
            "protocol": "6",
            "bytes": "0",
            "action": "REJECT",
        }
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFNetworkActivity)
        assert result.action == "deny"
        assert result.severity == "low"

    def test_string_format(self) -> None:
        line = (
            "2 123456789 eni-abc 192.168.1.1 10.0.0.5"
            " 44444 80 6 10 5000 1710460800 1710460860 ACCEPT OK"
        )
        raw = {"message": line}
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFNetworkActivity)
        assert result.src_ip == "192.168.1.1"
        assert result.dst_ip == "10.0.0.5"
        assert result.dst_port == 80
        assert result.protocol == "tcp"
        assert result.action == "allow"

    def test_short_string_no_crash(self) -> None:
        raw = {"message": "2 123 eni-x"}
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFNetworkActivity)

    def test_missing_fields_no_crash(self) -> None:
        result = self.mapper.map({})
        assert isinstance(result, OCSFNetworkActivity)


# ---------------------------------------------------------------------------
# Azure Activity
# ---------------------------------------------------------------------------
class TestAzureActivityMapper:
    def setup_method(self) -> None:
        self.mapper = AzureActivityMapper()

    def test_activity_event(self) -> None:
        raw = {
            "operationName": "Microsoft.Compute/virtualMachines/write",
            "caller": "admin@contoso.com",
            "eventTimestamp": "2026-03-15T14:00:00Z",
            "status": {"value": "Succeeded"},
            "level": "Informational",
            "resourceProviderName": "Microsoft.Compute",
            "properties": {"vmSize": "Standard_D4s_v3"},
            "httpRequest": {"statusCode": 200},
        }
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFAPIActivity)
        assert result.api_name == "Microsoft.Compute/virtualMachines/write"
        assert result.actor == "admin@contoso.com"
        assert result.service == "Microsoft.Compute"
        assert result.response_code == 200
        assert result.severity == "informational"

    def test_error_level(self) -> None:
        raw = {
            "operationName": "Microsoft.Storage/delete",
            "caller": "user@corp.com",
            "status": {"value": "Failed"},
            "level": "Error",
        }
        result = self.mapper.map(raw)
        assert result.severity == "high"
        assert result.response_code == 500

    def test_missing_fields_no_crash(self) -> None:
        result = self.mapper.map({})
        assert isinstance(result, OCSFAPIActivity)


# ---------------------------------------------------------------------------
# Syslog
# ---------------------------------------------------------------------------
class TestSyslogMapper:
    def setup_method(self) -> None:
        self.mapper = SyslogMapper()

    def test_rfc5424_message(self) -> None:
        line = (
            "<134>1 2026-03-15T10:30:00Z webserver01 nginx 1234 - "
            '[meta sequenceId="1"] GET /api/health 200'
        )
        raw = {"message": line}
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFBaseEvent)
        assert result.source_provider == "syslog"
        assert result.normalized["hostname"] == "webserver01"
        assert result.normalized["app_name"] == "nginx"
        assert "GET /api/health 200" in result.normalized["message"]
        # PRI 134 = facility 16 (local0), severity 6 (info)
        assert result.severity == "informational"

    def test_rfc5424_with_structured_data(self) -> None:
        line = (
            "<165>1 2026-03-15T11:00:00Z fw01 iptables - - "
            '[firewall@32473 action="drop" src="10.0.0.1" dst="10.0.0.2"] Blocked packet'
        )
        raw = {"message": line}
        result = self.mapper.map(raw)
        sd = result.normalized.get("structured_data", {})
        assert "firewall@32473" in sd
        assert sd["firewall@32473"]["action"] == "drop"

    def test_pre_parsed_dict(self) -> None:
        raw = {
            "hostname": "db-server",
            "app_name": "postgres",
            "severity": "medium",
            "message": "connection timeout",
        }
        result = self.mapper.map(raw)
        assert result.source_provider == "syslog"
        assert result.normalized["hostname"] == "db-server"
        assert result.severity == "medium"

    def test_unparseable_message_no_crash(self) -> None:
        raw = {"message": "<999>garbage data that does not match rfc5424"}
        result = self.mapper.map(raw)
        assert isinstance(result, OCSFBaseEvent)
        assert result.source_provider == "syslog"

    def test_empty_event_no_crash(self) -> None:
        result = self.mapper.map({})
        assert isinstance(result, OCSFBaseEvent)
