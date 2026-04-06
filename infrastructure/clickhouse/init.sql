-- =============================================================================
-- ShieldOps ClickHouse schema bootstrap (run once against any node in the cluster)
--
-- Creates the shieldops database, the replicated local events table on every
-- node via ON CLUSTER, the distributed proxy table, and the four analytics
-- materialized views (events_per_hour, top_source_ips_24h, alert_volume_trend,
-- mitre_technique_frequency).
--
-- Prerequisites:
--   * A 3-node cluster named `shieldops_cluster` (see config.xml)
--   * ZooKeeper ensemble reachable
--   * shieldops user with access_management=1
-- =============================================================================

CREATE DATABASE IF NOT EXISTS shieldops ON CLUSTER shieldops_cluster;

-- -----------------------------------------------------------------------------
-- events_local — replicated base table, one shard per node
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS shieldops.events_local ON CLUSTER shieldops_cluster (
    event_id        String,
    org_id          String,
    timestamp       DateTime64(3),
    event_type      LowCardinality(String),
    severity        LowCardinality(String),
    source_provider LowCardinality(String),
    source_type     LowCardinality(String) DEFAULT '',
    source_ip       String DEFAULT '',
    mitre_technique LowCardinality(String) DEFAULT '',
    raw_event       String,
    normalized      String,
    enrichments     String,

    INDEX idx_event_type event_type TYPE set(100) GRANULARITY 4,
    INDEX idx_severity severity TYPE set(10) GRANULARITY 4,
    INDEX idx_source_ip source_ip TYPE bloom_filter(0.01) GRANULARITY 4
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/events', '{replica}')
PARTITION BY (org_id, toYYYYMM(timestamp))
ORDER BY (org_id, event_type, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- -----------------------------------------------------------------------------
-- events — Distributed fan-out table application code reads/writes
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS shieldops.events ON CLUSTER shieldops_cluster
AS shieldops.events_local
ENGINE = Distributed(shieldops_cluster, shieldops, events_local, rand());

-- -----------------------------------------------------------------------------
-- Materialized View: events_per_hour
-- Aggregates event counts per org / event_type bucketed by hour.
-- -----------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS shieldops.mv_events_per_hour
ON CLUSTER shieldops_cluster
ENGINE = ReplicatedSummingMergeTree('/clickhouse/tables/{shard}/mv_events_per_hour', '{replica}')
PARTITION BY toYYYYMM(hour)
ORDER BY (org_id, event_type, hour)
AS SELECT
    org_id,
    event_type,
    toStartOfHour(timestamp) AS hour,
    count() AS cnt
FROM shieldops.events_local
GROUP BY org_id, event_type, hour;

-- -----------------------------------------------------------------------------
-- Materialized View: top_source_ips_24h
-- Tracks the most noisy source IPs per org per day.
-- -----------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS shieldops.mv_top_source_ips_24h
ON CLUSTER shieldops_cluster
ENGINE = ReplicatedSummingMergeTree('/clickhouse/tables/{shard}/mv_top_source_ips_24h', '{replica}')
PARTITION BY toYYYYMM(day)
ORDER BY (org_id, source_ip, day)
AS SELECT
    org_id,
    source_ip,
    toDate(timestamp) AS day,
    count() AS cnt
FROM shieldops.events_local
WHERE source_ip != ''
GROUP BY org_id, source_ip, day;

-- -----------------------------------------------------------------------------
-- Materialized View: alert_volume_trend
-- Daily alert volume per severity for trend dashboards.
-- -----------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS shieldops.mv_alert_volume_trend
ON CLUSTER shieldops_cluster
ENGINE = ReplicatedSummingMergeTree('/clickhouse/tables/{shard}/mv_alert_volume_trend', '{replica}')
PARTITION BY toYYYYMM(day)
ORDER BY (org_id, severity, day)
AS SELECT
    org_id,
    severity,
    toDate(timestamp) AS day,
    count() AS cnt
FROM shieldops.events_local
GROUP BY org_id, severity, day;

-- -----------------------------------------------------------------------------
-- Materialized View: mitre_technique_frequency
-- MITRE ATT&CK technique frequency per org per week for heat maps.
-- -----------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS shieldops.mv_mitre_technique_frequency
ON CLUSTER shieldops_cluster
ENGINE = ReplicatedSummingMergeTree('/clickhouse/tables/{shard}/mv_mitre_technique_frequency', '{replica}')
PARTITION BY toYYYYMM(week)
ORDER BY (org_id, mitre_technique, week)
AS SELECT
    org_id,
    mitre_technique,
    toMonday(timestamp) AS week,
    count() AS cnt
FROM shieldops.events_local
WHERE mitre_technique != ''
GROUP BY org_id, mitre_technique, week;
