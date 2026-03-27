# security/ — Security Engine Modules

400+ security engine modules covering threat detection, SOAR, zero trust, XDR, identity security, AI security, and data protection.

## Engine Categories

| Category | Count | Examples |
|----------|-------|---------|
| Threat Detection | 80+ | RBA pipeline, MITRE mapping, hunt automation |
| Identity Security | 40+ | OAuth grants, lateral movement, NHI governance |
| AI Security | 30+ | Prompt injection, LLM firewall, model backdoor, RAG poisoning |
| Data Security | 25+ | DLP, data classification, exfiltration detection |
| XDR/SOC | 30+ | Cross-vendor correlation, OCSF mapping, signal correlation |
| Agent Security | 20+ | Capability tracking, trust chains, communication auditing |
| Vulnerability | 20+ | Scanless matching, EPSS scoring, exploit tracking |
| Compliance | 15+ | CIS benchmarks, NIST controls, evidence collection |

## Standard Engine Pattern

Every engine file follows this exact structure:
```python
"""EngineName — one-line description."""
from __future__ import annotations
import time, uuid
from enum import StrEnum
from typing import Any
import structlog
from pydantic import BaseModel, Field

# 3 StrEnum classes
class Enum1(StrEnum): ...
class Enum2(StrEnum): ...
class Enum3(StrEnum): ...

# 3 Pydantic models
class SomeRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    created_at: float = Field(default_factory=time.time)

class SomeAnalysis(BaseModel): ...
class SomeReport(BaseModel): ...

# Engine class
class SomeEngine:
    def __init__(self, max_records: int = 10000) -> None:
        self._records: list[SomeRecord] = []
        self._max = max_records

    def add_record(self, **kwargs) -> SomeRecord: ...  # Ring-buffer
    def process(self, key: str) -> SomeAnalysis: ...
    def generate_report(self) -> SomeReport: ...
    def get_stats(self) -> dict[str, Any]: ...
    def clear_data(self) -> None: ...
    def domain_method_1(self) -> ...: ...  # 3 domain methods
    def domain_method_2(self) -> ...: ...
    def domain_method_3(self) -> ...: ...
```

## Key Engines
- `prompt_injection_classifier.py` — Multi-layer injection detection
- `llm_firewall_engine.py` — LLM request/response filtering
- `agent_capability_tracker.py` — AI agent governance
- `xdr_signal_correlator.py` — Cross-domain signal correlation
- `ocsf_event_mapper.py` — Vendor-neutral event normalization
- `identity_threat_detector.py` — Real-time identity threats
- `ransomware_fingerprint_engine.py` — Variant identification
