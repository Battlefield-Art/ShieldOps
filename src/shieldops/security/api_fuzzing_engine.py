"""APIFuzzingEngine — Track API fuzz testing results."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

APIFuzzingEngine = engine(
    "APIFuzzingEngine",
    description="Track API fuzz testing and detect vulns.",
    enums={
        "strategy": EnumDef(
            "FuzzStrategy",
            {
                "RANDOM": "random",
                "MUTATION": "mutation",
                "GENERATION": "generation",
                "DICTIONARY": "dictionary",
                "SMART": "smart",
            },
        ),
        "anomaly": EnumDef(
            "ResponseAnomaly",
            {
                "NONE": "none",
                "ERROR_LEAK": "error_leak",
                "CRASH": "crash",
                "TIMEOUT": "timeout",
                "UNEXPECTED_DATA": "unexpected_data",
                "STATUS_ANOMALY": "status_anomaly",
            },
        ),
        "input_type": EnumDef(
            "InputType",
            {
                "QUERY_PARAM": "query_param",
                "PATH_PARAM": "path_param",
                "BODY_JSON": "body_json",
                "HEADER": "header",
                "COOKIE": "cookie",
                "FORM_DATA": "form_data",
            },
        ),
    },
    record_fields=[
        FieldDef("status_code", int, 200),
        FieldDef("response_time_ms", float, 0.0),
        FieldDef("vulnerability", str, ""),
    ],
    key_field="endpoint",
)

# Backward-compatible re-exports
FuzzStrategy = APIFuzzingEngine.FuzzStrategy
ResponseAnomaly = APIFuzzingEngine.ResponseAnomaly
InputType = APIFuzzingEngine.InputType
APIFuzzRecord = APIFuzzingEngine.Record
APIFuzzAnalysis = APIFuzzingEngine.Analysis
APIFuzzReport = APIFuzzingEngine.Report
