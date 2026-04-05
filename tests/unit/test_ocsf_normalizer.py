"""Tests for OCSF event normalizer."""

from __future__ import annotations

from shieldops.ingest.normalizer import (
    CATEGORY_API,
    CATEGORY_AUTH,
    CATEGORY_SECURITY_FINDING,
    normalize,
    normalize_cloudtrail,
    normalize_crowdstrike_fdr,
    normalize_syslog,
)


class TestCloudTrailNormalization:
    def test_api_call_event(self) -> None:
        event = {
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "sourceIPAddress": "10.0.1.50",
            "userIdentity": {"type": "IAMUser", "userName": "deploy-bot", "accountId": "123456"},
            "eventTime": "2026-04-05T10:00:00Z",
            "awsRegion": "us-east-1",
        }
        result = normalize_cloudtrail(event)
        assert result.category_uid == CATEGORY_API
        assert result.category_name == "api_activity"
        assert result.activity_name == "DescribeInstances"
        assert result.src["ip"] == "10.0.1.50"
        assert result.actor["user_name"] == "deploy-bot"
        assert result.status == "success"

    def test_auth_event(self) -> None:
        event = {
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "sourceIPAddress": "203.0.113.5",
            "userIdentity": {"type": "IAMUser", "userName": "admin"},
            "eventTime": "2026-04-05T10:00:00Z",
        }
        result = normalize_cloudtrail(event)
        assert result.category_uid == CATEGORY_AUTH
        assert result.category_name == "authentication"

    def test_error_event(self) -> None:
        event = {
            "eventName": "DeleteBucket",
            "eventSource": "s3.amazonaws.com",
            "errorCode": "AccessDenied",
            "userIdentity": {"type": "IAMUser", "userName": "attacker"},
        }
        result = normalize_cloudtrail(event)
        assert result.status == "failure"
        assert result.severity == "low"
        assert result.metadata["error_code"] == "AccessDenied"

    def test_observables_extracted(self) -> None:
        event = {
            "eventName": "PutObject",
            "sourceIPAddress": "10.0.1.1",
            "userIdentity": {"userName": "svc-upload", "arn": "arn:aws:iam::role/svc"},
        }
        result = normalize_cloudtrail(event)
        types = [o["type"] for o in result.observables]
        assert "ip_address" in types
        assert "user" in types
        assert "arn" in types

    def test_resources_extracted(self) -> None:
        event = {
            "eventName": "GetObject",
            "requestParameters": {"bucketName": "my-bucket"},
            "userIdentity": {},
        }
        result = normalize_cloudtrail(event)
        assert len(result.resources) == 1
        assert result.resources[0]["name"] == "my-bucket"


class TestCrowdStrikeFDRNormalization:
    def test_detection_event(self) -> None:
        event = {
            "DetectName": "Credential Dumping",
            "Severity": 4,
            "ComputerName": "workstation-01",
            "DeviceId": "dev-abc",
            "UserName": "jdoe",
            "LocalIP": "192.168.1.100",
            "Tactic": "Credential Access",
            "Technique": "T1003",
        }
        result = normalize_crowdstrike_fdr(event)
        assert result.category_uid == CATEGORY_SECURITY_FINDING
        assert result.severity == "high"
        assert result.severity_id == 4
        assert result.message == "Credential Dumping"
        assert result.src["hostname"] == "workstation-01"
        assert result.metadata["technique"] == "T1003"

    def test_low_severity(self) -> None:
        event = {"Severity": 1, "DetectName": "Low priority alert"}
        result = normalize_crowdstrike_fdr(event)
        assert result.severity == "informational"
        assert result.severity_id == 1

    def test_critical_severity(self) -> None:
        event = {"Severity": 5, "DetectName": "Ransomware detected"}
        result = normalize_crowdstrike_fdr(event)
        assert result.severity == "critical"
        assert result.severity_id == 5

    def test_observables_include_hash(self) -> None:
        event = {
            "SHA256String": "abc123def456",
            "ComputerName": "srv-01",
            "UserName": "admin",
            "IOCType": "domain",
            "IOCValue": "evil.com",
        }
        result = normalize_crowdstrike_fdr(event)
        types = [o["type"] for o in result.observables]
        assert "hash_sha256" in types
        assert "hostname" in types
        assert "domain" in types

    def test_lowercase_field_names(self) -> None:
        event = {"detect_name": "Test", "severity": 3, "hostname": "srv-02"}
        result = normalize_crowdstrike_fdr(event)
        assert result.message == "Test"
        assert result.severity_id == 3


class TestSyslogNormalization:
    def test_basic_syslog(self) -> None:
        event = {
            "hostname": "web-01",
            "severity": "high",
            "message": "Failed password for root",
            "program": "sshd",
            "pid": "1234",
        }
        result = normalize_syslog(event)
        assert result.severity == "high"
        assert result.severity_id == 4
        assert "Failed password" in result.message
        assert result.metadata["program"] == "sshd"

    def test_missing_fields(self) -> None:
        event = {"message": "something happened"}
        result = normalize_syslog(event)
        assert result.message == "something happened"
        assert result.source_provider == "syslog"


class TestNormalizeDispatch:
    def test_cloudtrail_dispatch(self) -> None:
        event = {"eventName": "GetObject", "userIdentity": {}}
        result = normalize("cloudtrail", event)
        assert result.source_provider == "aws_cloudtrail"

    def test_crowdstrike_dispatch(self) -> None:
        event = {"DetectName": "Malware", "Severity": 3}
        result = normalize("crowdstrike_fdr", event)
        assert result.source_provider == "crowdstrike_fdr"

    def test_syslog_dispatch(self) -> None:
        event = {"message": "test", "hostname": "srv"}
        result = normalize("syslog", event)
        assert result.source_provider == "syslog"

    def test_unknown_source_returns_raw(self) -> None:
        event = {"foo": "bar"}
        result = normalize("unknown_vendor", event)
        assert result.source_provider == "unknown_vendor"
        assert "Raw event" in result.message

    def test_to_dict(self) -> None:
        event = {"eventName": "Test", "userIdentity": {}}
        result = normalize("cloudtrail", event)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "category_uid" in d
        assert "time" in d
        assert "source_provider" in d
