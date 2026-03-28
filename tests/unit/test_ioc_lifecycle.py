"""Unit tests for ioc_lifecycle agent."""

from __future__ import annotations

import pytest

from shieldops.agents.ioc_lifecycle.models import (
    IOCClassification,
    IOCEnrichment,
    IOCLifecycleState,
    IOCRecord,
    IOCStage,
    IOCStatus,
    IOCType,
)
from shieldops.agents.ioc_lifecycle.tools import (
    SOURCE_TEMPLATES,
    IOCLifecycleToolkit,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_ioc_stage_values(self):
        assert IOCStage.COLLECT == "collect"
        assert IOCStage.VALIDATE == "validate"
        assert IOCStage.ENRICH == "enrich"
        assert IOCStage.CLASSIFY == "classify"
        assert IOCStage.AGE_CHECK == "age_check"
        assert IOCStage.REPORT == "report"

    def test_ioc_type_values(self):
        assert IOCType.IP == "ip"
        assert IOCType.DOMAIN == "domain"
        assert IOCType.HASH_MD5 == "hash_md5"
        assert IOCType.HASH_SHA256 == "hash_sha256"
        assert IOCType.URL == "url"
        assert IOCType.EMAIL == "email"
        assert IOCType.CVE == "cve"

    def test_ioc_status_values(self):
        assert IOCStatus.ACTIVE == "active"
        assert IOCStatus.AGED == "aged"
        assert IOCStatus.EXPIRED == "expired"
        assert IOCStatus.FALSE_POSITIVE == "false_positive"
        assert IOCStatus.RETIRED == "retired"


# ---------------------------------------------------------------------------
# State & Models
# ---------------------------------------------------------------------------


class TestState:
    def test_defaults(self):
        state = IOCLifecycleState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == IOCStage.COLLECT
        assert state.sources == []
        assert state.iocs == []
        assert state.enrichments == []
        assert state.classifications == []
        assert state.false_positive_count == 0
        assert state.stats == {}
        assert state.report == {}
        assert state.reasoning_chain == []
        assert state.session_start == 0.0

    def test_with_values(self):
        state = IOCLifecycleState(
            request_id="req-1",
            tenant_id="t-1",
            sources=["threat_feed", "siem_alert"],
        )
        assert state.request_id == "req-1"
        assert state.tenant_id == "t-1"
        assert len(state.sources) == 2


class TestModels:
    def test_ioc_record_defaults(self):
        r = IOCRecord()
        assert r.id == ""
        assert r.ioc_type == IOCType.IP
        assert r.value == ""
        assert r.status == IOCStatus.ACTIVE
        assert r.confidence == 0.0
        assert r.tags == []
        assert r.metadata == {}

    def test_ioc_enrichment_defaults(self):
        e = IOCEnrichment()
        assert e.ioc_id == ""
        assert e.threat_score == 0.0
        assert e.malware_families == []
        assert e.geo_location == ""
        assert e.related_campaigns == []

    def test_ioc_classification_defaults(self):
        c = IOCClassification()
        assert c.ioc_id == ""
        assert c.severity == "medium"
        assert c.kill_chain_phase == ""
        assert c.mitre_tactics == []
        assert c.is_false_positive is False
        assert c.fp_reason == ""


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        return IOCLifecycleToolkit()

    @pytest.mark.asyncio
    async def test_collect_iocs_threat_feed(self, toolkit):
        iocs = await toolkit.collect_iocs(["threat_feed"])
        templates = SOURCE_TEMPLATES["threat_feed"]
        assert len(iocs) == len(templates)
        for ioc in iocs:
            assert isinstance(ioc, IOCRecord)
            assert ioc.id.startswith("ioc-")
            assert ioc.status == IOCStatus.ACTIVE
            assert ioc.source == "threat_feed"

    @pytest.mark.asyncio
    async def test_collect_iocs_multiple_sources(self, toolkit):
        iocs = await toolkit.collect_iocs(
            ["threat_feed", "siem_alert"],
        )
        expected = len(SOURCE_TEMPLATES["threat_feed"]) + len(SOURCE_TEMPLATES["siem_alert"])
        assert len(iocs) == expected

    @pytest.mark.asyncio
    async def test_collect_iocs_default(self, toolkit):
        iocs = await toolkit.collect_iocs(["unknown_source"])
        assert len(iocs) == len(SOURCE_TEMPLATES["default"])

    @pytest.mark.asyncio
    async def test_validate_iocs(self, toolkit):
        iocs = [
            IOCRecord(id="ioc-1", ioc_type=IOCType.IP, value="1.2.3.4"),
            IOCRecord(id="ioc-2", ioc_type=IOCType.IP, value="1.2.3.4"),
            IOCRecord(id="ioc-3", ioc_type=IOCType.IP, value=""),
            IOCRecord(id="ioc-4", ioc_type=IOCType.DOMAIN, value="evil.com"),
        ]
        validated = await toolkit.validate_iocs(iocs)
        assert len(validated) == 2
        values = [i.value for i in validated]
        assert "1.2.3.4" in values
        assert "evil.com" in values

    @pytest.mark.asyncio
    async def test_enrich_ioc_ip(self, toolkit):
        ioc = IOCRecord(
            id="ioc-test",
            ioc_type=IOCType.IP,
            value="198.51.100.23",
            confidence=0.85,
            tags=["c2", "malware"],
        )
        enrichment = await toolkit.enrich_ioc(ioc)
        assert isinstance(enrichment, IOCEnrichment)
        assert enrichment.ioc_id == "ioc-test"
        assert enrichment.threat_score > 0
        assert enrichment.geo_location == "US"
        assert enrichment.asn == "AS13335"
        assert "emotet" in enrichment.malware_families
        assert len(enrichment.related_campaigns) > 0

    @pytest.mark.asyncio
    async def test_enrich_ioc_domain(self, toolkit):
        ioc = IOCRecord(
            id="ioc-dom",
            ioc_type=IOCType.DOMAIN,
            value="evil.example.com",
            confidence=0.70,
            tags=["phishing"],
        )
        enrichment = await toolkit.enrich_ioc(ioc)
        assert enrichment.geo_location == ""
        assert enrichment.asn == ""

    @pytest.mark.asyncio
    async def test_classify_ioc_critical(self, toolkit):
        ioc = IOCRecord(
            id="ioc-1",
            ioc_type=IOCType.IP,
            tags=["c2"],
        )
        enrichment = IOCEnrichment(
            ioc_id="ioc-1",
            threat_score=0.95,
        )
        cls = await toolkit.classify_ioc(ioc, enrichment)
        assert isinstance(cls, IOCClassification)
        assert cls.severity == "critical"
        assert cls.kill_chain_phase == "command_and_control"
        assert cls.is_false_positive is False

    @pytest.mark.asyncio
    async def test_classify_ioc_false_positive(self, toolkit):
        ioc = IOCRecord(
            id="ioc-fp",
            ioc_type=IOCType.IP,
            tags=[],
        )
        enrichment = IOCEnrichment(
            ioc_id="ioc-fp",
            threat_score=0.1,
        )
        cls = await toolkit.classify_ioc(ioc, enrichment)
        assert cls.is_false_positive is True
        assert cls.fp_reason != ""

    @pytest.mark.asyncio
    async def test_check_age_fresh(self, toolkit):
        import time

        now = time.time()
        iocs = [
            IOCRecord(
                id="ioc-fresh",
                first_seen=now,
                status=IOCStatus.ACTIVE,
            ),
        ]
        result = await toolkit.check_age(iocs)
        assert len(result) == 1
        assert result[0].status == IOCStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_check_age_expired(self, toolkit):
        import time

        old_time = time.time() - (200 * 86400)
        iocs = [
            IOCRecord(
                id="ioc-old",
                first_seen=old_time,
                status=IOCStatus.ACTIVE,
            ),
        ]
        result = await toolkit.check_age(iocs)
        assert result[0].status == IOCStatus.EXPIRED


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_collect_node(self):
        from shieldops.agents.ioc_lifecycle.nodes import (
            collect,
            set_toolkit,
        )

        set_toolkit(IOCLifecycleToolkit())
        state = IOCLifecycleState(
            sources=["threat_feed"],
        )
        result = await collect(state)
        assert "iocs" in result
        assert len(result["iocs"]) > 0
        assert result["stage"] == IOCStage.VALIDATE

    @pytest.mark.asyncio
    async def test_validate_node(self):
        from shieldops.agents.ioc_lifecycle.nodes import (
            set_toolkit,
            validate,
        )

        set_toolkit(IOCLifecycleToolkit())
        state = IOCLifecycleState(
            iocs=[
                IOCRecord(
                    id="ioc-1",
                    ioc_type=IOCType.IP,
                    value="1.2.3.4",
                ),
            ],
        )
        result = await validate(state)
        assert len(result["iocs"]) == 1
        assert result["stage"] == IOCStage.ENRICH

    @pytest.mark.asyncio
    async def test_enrich_node(self):
        from shieldops.agents.ioc_lifecycle.nodes import (
            enrich,
            set_toolkit,
        )

        set_toolkit(IOCLifecycleToolkit())
        state = IOCLifecycleState(
            iocs=[
                IOCRecord(
                    id="ioc-1",
                    ioc_type=IOCType.IP,
                    value="1.2.3.4",
                    confidence=0.8,
                ),
            ],
        )
        result = await enrich(state)
        assert len(result["enrichments"]) == 1
        assert result["stage"] == IOCStage.CLASSIFY

    @pytest.mark.asyncio
    async def test_classify_node(self):
        from shieldops.agents.ioc_lifecycle.nodes import (
            classify,
            set_toolkit,
        )

        set_toolkit(IOCLifecycleToolkit())
        state = IOCLifecycleState(
            iocs=[
                IOCRecord(id="ioc-1", tags=["c2"]),
            ],
            enrichments=[
                IOCEnrichment(
                    ioc_id="ioc-1",
                    threat_score=0.9,
                ),
            ],
        )
        result = await classify(state)
        assert len(result["classifications"]) == 1
        assert result["stage"] == IOCStage.AGE_CHECK

    @pytest.mark.asyncio
    async def test_age_check_node(self):
        import time

        from shieldops.agents.ioc_lifecycle.nodes import (
            age_check,
            set_toolkit,
        )

        set_toolkit(IOCLifecycleToolkit())
        state = IOCLifecycleState(
            iocs=[
                IOCRecord(
                    id="ioc-1",
                    first_seen=time.time(),
                    status=IOCStatus.ACTIVE,
                ),
            ],
            classifications=[],
            false_positive_count=0,
        )
        result = await age_check(state)
        assert len(result["iocs"]) == 1
        assert result["stage"] == IOCStage.REPORT
        assert "stats" in result

    @pytest.mark.asyncio
    async def test_report_node(self):
        import time

        from shieldops.agents.ioc_lifecycle.nodes import (
            report,
            set_toolkit,
        )

        set_toolkit(IOCLifecycleToolkit())
        state = IOCLifecycleState(
            tenant_id="t-1",
            session_start=time.time(),
            iocs=[IOCRecord(id="ioc-1")],
            enrichments=[IOCEnrichment(ioc_id="ioc-1")],
            classifications=[
                IOCClassification(ioc_id="ioc-1"),
            ],
            false_positive_count=0,
            stats={"total_iocs": 1},
        )
        result = await report(state)
        assert "report" in result
        assert result["report"]["status"] == "complete"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.ioc_lifecycle.runner import (
            IOCLifecycleRunner,
        )

        runner = IOCLifecycleRunner()
        assert runner is not None
