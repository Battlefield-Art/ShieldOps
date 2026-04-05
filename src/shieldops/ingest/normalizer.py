"""OCSF event normalizer — transforms vendor events to standard schema."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger()

# OCSF category UIDs
CATEGORY_AUTH = 3001
CATEGORY_API = 6003
CATEGORY_NETWORK = 4001
CATEGORY_SECURITY_FINDING = 2001
CATEGORY_PROCESS = 1001

# Severity mapping
SEVERITY_MAP = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


class OCSFEvent:
    """Normalized OCSF event."""

    def __init__(self, **kwargs: Any) -> None:
        self.category_uid: int = kwargs.get("category_uid", 0)
        self.category_name: str = kwargs.get("category_name", "unknown")
        self.class_uid: int = kwargs.get("class_uid", 0)
        self.severity_id: int = kwargs.get("severity_id", 1)
        self.severity: str = kwargs.get("severity", "informational")
        self.time: str = kwargs.get("time", datetime.now(UTC).isoformat())
        self.message: str = kwargs.get("message", "")
        self.actor: dict[str, Any] = kwargs.get("actor", {})
        self.src: dict[str, Any] = kwargs.get("src", {})
        self.dst: dict[str, Any] = kwargs.get("dst", {})
        self.observables: list[dict[str, Any]] = kwargs.get("observables", [])
        self.metadata: dict[str, Any] = kwargs.get("metadata", {})
        self.raw_data: str = kwargs.get("raw_data", "")
        self.source_provider: str = kwargs.get("source_provider", "")
        self.activity_name: str = kwargs.get("activity_name", "")
        self.status: str = kwargs.get("status", "")
        self.resources: list[dict[str, Any]] = kwargs.get("resources", [])

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


def normalize_cloudtrail(event: dict[str, Any]) -> OCSFEvent:
    """Normalize AWS CloudTrail event to OCSF."""
    event_name = event.get("eventName", "")
    event_source = event.get("eventSource", "")
    source_ip = event.get("sourceIPAddress", "")
    user_identity = event.get("userIdentity", {})
    event_time = event.get("eventTime", datetime.now(UTC).isoformat())
    error_code = event.get("errorCode", "")
    region = event.get("awsRegion", "")

    # Determine category
    auth_events = {"ConsoleLogin", "AssumeRole", "GetSessionToken", "SwitchRole"}
    if event_name in auth_events:
        category_uid = CATEGORY_AUTH
        category_name = "authentication"
    else:
        category_uid = CATEGORY_API
        category_name = "api_activity"

    # Build actor
    actor = {
        "user_type": user_identity.get("type", ""),
        "user_name": user_identity.get("userName", ""),
        "account_id": user_identity.get("accountId", ""),
        "arn": user_identity.get("arn", ""),
        "access_key_id": user_identity.get("accessKeyId", ""),
    }

    # Build observables
    observables = []
    if source_ip:
        observables.append({"type": "ip_address", "value": source_ip})
    if actor["user_name"]:
        observables.append({"type": "user", "value": actor["user_name"]})
    if actor["arn"]:
        observables.append({"type": "arn", "value": actor["arn"]})

    # Build resources
    resources = []
    request_params = event.get("requestParameters", {})
    if isinstance(request_params, dict):
        for key in ("bucketName", "instanceId", "functionName", "roleName", "groupName"):
            if key in request_params:
                resources.append({"type": key, "name": request_params[key]})

    status = "failure" if error_code else "success"

    return OCSFEvent(
        category_uid=category_uid,
        category_name=category_name,
        class_uid=category_uid,
        severity_id=2 if error_code else 1,
        severity="low" if error_code else "informational",
        time=event_time,
        message=f"{event_name} from {event_source}",
        actor=actor,
        src={"ip": source_ip, "region": region},
        observables=observables,
        resources=resources,
        activity_name=event_name,
        status=status,
        source_provider="aws_cloudtrail",
        metadata={"event_source": event_source, "error_code": error_code, "region": region},
        raw_data=str(event)[:5000],
    )


def normalize_crowdstrike_fdr(event: dict[str, Any]) -> OCSFEvent:
    """Normalize CrowdStrike FDR event to OCSF."""
    detect_name = event.get("DetectName", event.get("detect_name", ""))
    detect_desc = event.get("DetectDescription", event.get("detect_description", ""))
    severity = event.get("Severity", event.get("severity", 0))
    hostname = event.get("ComputerName", event.get("hostname", ""))
    device_id = event.get("DeviceId", event.get("device_id", ""))
    timestamp = event.get("Timestamp", event.get("timestamp", datetime.now(UTC).isoformat()))
    tactic = event.get("Tactic", event.get("tactic", ""))
    technique = event.get("Technique", event.get("technique", ""))
    ioc_type = event.get("IOCType", event.get("ioc_type", ""))
    ioc_value = event.get("IOCValue", event.get("ioc_value", ""))
    user_name = event.get("UserName", event.get("user_name", ""))
    src_ip = event.get("LocalIP", event.get("local_ip", ""))
    file_hash = event.get("SHA256String", event.get("sha256", ""))

    # Map CrowdStrike severity (1-5) to OCSF
    severity_map = {
        1: ("informational", 1),
        2: ("low", 2),
        3: ("medium", 3),
        4: ("high", 4),
        5: ("critical", 5),
    }
    sev_name, sev_id = severity_map.get(int(severity) if severity else 1, ("informational", 1))

    # Build observables
    observables = []
    if hostname:
        observables.append({"type": "hostname", "value": hostname})
    if src_ip:
        observables.append({"type": "ip_address", "value": src_ip})
    if user_name:
        observables.append({"type": "user", "value": user_name})
    if file_hash:
        observables.append({"type": "hash_sha256", "value": file_hash})
    if ioc_value:
        observables.append({"type": ioc_type or "indicator", "value": ioc_value})

    return OCSFEvent(
        category_uid=CATEGORY_SECURITY_FINDING,
        category_name="security_finding",
        class_uid=CATEGORY_SECURITY_FINDING,
        severity_id=sev_id,
        severity=sev_name,
        time=str(timestamp),
        message=detect_name or detect_desc or "CrowdStrike Detection",
        actor={"user_name": user_name, "device_id": device_id},
        src={"ip": src_ip, "hostname": hostname},
        observables=observables,
        activity_name=detect_name,
        status="detected",
        source_provider="crowdstrike_fdr",
        metadata={
            "tactic": tactic,
            "technique": technique,
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "device_id": device_id,
        },
        raw_data=str(event)[:5000],
    )


def normalize_syslog(event: dict[str, Any]) -> OCSFEvent:
    """Normalize syslog event to OCSF."""
    facility = event.get("facility", "")
    severity_str = event.get("severity", "informational").lower()
    hostname = event.get("hostname", "")
    message = event.get("message", event.get("msg", ""))
    timestamp = event.get("timestamp", datetime.now(UTC).isoformat())
    program = event.get("program", event.get("app_name", ""))
    pid = event.get("pid", "")

    sev_id = SEVERITY_MAP.get(severity_str, 1)

    observables = []
    if hostname:
        observables.append({"type": "hostname", "value": hostname})

    return OCSFEvent(
        category_uid=CATEGORY_PROCESS,
        category_name="system_activity",
        class_uid=CATEGORY_PROCESS,
        severity_id=sev_id,
        severity=severity_str,
        time=timestamp,
        message=str(message)[:1000],
        src={"hostname": hostname},
        observables=observables,
        activity_name=program,
        status="logged",
        source_provider="syslog",
        metadata={"facility": facility, "program": program, "pid": str(pid)},
        raw_data=str(event)[:5000],
    )


def normalize(source: str, event: dict[str, Any]) -> OCSFEvent:
    """Auto-detect source and normalize to OCSF."""
    normalizers = {
        "cloudtrail": normalize_cloudtrail,
        "crowdstrike_fdr": normalize_crowdstrike_fdr,
        "syslog": normalize_syslog,
    }

    normalizer = normalizers.get(source)
    if normalizer:
        try:
            result = normalizer(event)
            logger.debug("ocsf.normalized", source=source, category=result.category_name)
            return result
        except Exception as e:
            logger.warning("ocsf.normalization_error", source=source, error=str(e))

    # Fallback: wrap raw event
    return OCSFEvent(
        raw_data=str(event)[:5000],
        source_provider=source,
        message=f"Raw event from {source}",
        time=datetime.now(UTC).isoformat(),
    )
