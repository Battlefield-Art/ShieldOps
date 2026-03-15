# Threat Intel Agent

Automated threat intelligence agent that collects indicators of compromise (IOCs) from multiple feeds, correlates them against your environment, assesses risk, and distributes actionable intelligence to detection systems.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Collect    │────▶│  Correlate   │────▶│    Assess    │────▶│  Distribute  │
│    IOCs      │     │   Signals    │     │    Risk      │     │   Actions    │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
  STIX/TAXII Feeds    MITRE ATT&CK Map     Confidence Score    SIEM Detection
  OSINT Sources       Kill Chain Stage     Tactic Chains       Firewall Rules
  Vendor Advisories   Threat Objects       Impact Analysis     SOC Playbooks
```

## Workflow

1. **Collect** -- Ingests IOCs from STIX/TAXII feeds, OSINT sources, vendor advisories, and internal honeypot detections. Normalizes data into a unified threat object model with STIX 2.1 format.
2. **Correlate** -- Maps IOCs to MITRE ATT&CK techniques, identifies kill chain stages, and cross-references against observed network traffic, DNS logs, and endpoint telemetry in your environment.
3. **Assess** -- Scores each threat using multi-source fusion: feed quality rating, temporal decay, environmental relevance, and tactic chain analysis. Produces a composite risk score (0-100).
4. **Distribute** -- Pushes verified high-confidence IOCs to detection systems (SIEM rules, firewall blocklists, EDR policies). Generates hunt hypotheses for the SOC team and triggers automated playbooks for critical threats.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `THREAT_FEED_URLS` | Comma-separated STIX/TAXII feed URLs | Required |
| `THREAT_CONFIDENCE_THRESHOLD` | Min confidence to auto-distribute | `0.85` |
| `IOC_DECAY_HOURS` | Hours before IOC relevance decays | `72` |
| `MITRE_ATTACK_VERSION` | ATT&CK framework version | `14.0` |
| `THREAT_HUNT_AUTO_TRIGGER` | Auto-trigger hunts on high-risk IOCs | `true` |

## Usage

```bash
# Trigger via CLI
shieldops run-agent threat_intel --mode continuous

# Trigger via API
curl -X POST /api/v1/agents/threat_intel/run \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"feeds": ["alienvault", "abuse_ch"], "correlate": true}'
```

Returns a threat intelligence report with IOC counts, correlation hits, risk assessments, and distribution actions taken.
