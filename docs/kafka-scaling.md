# Kafka Ingestion Scaling Runbook

ShieldOps ingests raw telemetry through a Kafka-backed pipeline:

```
API (POST /api/v1/ingestion/events)
        │
        ▼
  KafkaEventProducer  ──►  topic: ingest.raw  ──►  KafkaEventConsumer  ──►  OCSF normalize ──► EventStore
                                                           │
                                                           └─► topic: ingest.dlq  (malformed)
```

Target throughput: **500 GB/day** sustained (~6 MB/s, ~60k events/s at 100 B/event).

## Topic layout

| Topic        | Partitions | Replication | Retention |
|--------------|-----------:|------------:|-----------|
| `ingest.raw` |         64 |           3 | 72 h      |
| `ingest.dlq` |          6 |           3 | 14 d      |

- `ingest.raw` is keyed by `org_id` so per-tenant ordering is preserved and
  large tenants spread across multiple partitions.
- Producer uses `acks=all`, `enable_idempotence=true`, and gzip compression.

## Consumer group

- Group: `shieldops-ingestion`
- `enable.auto.commit = false` — offsets commit only after a successful
  batch insert into the event store.
- Batch size: 500 messages / 1000 ms max wait.

## Backpressure

The ingestion API reads the consumer group's total lag before accepting a
request. If lag exceeds the configured threshold (default **10,000 messages**,
set via `set_backpressure_threshold`), the API returns `429 Too Many Requests`.
Clients are expected to back off and retry.

## Autoscaling with KEDA

We use [KEDA](https://keda.sh) to drive the consumer Deployment's replica count
off of Kafka lag. Example `ScaledObject` (Kubernetes):

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: shieldops-ingest-consumer
  namespace: shieldops
spec:
  scaleTargetRef:
    name: shieldops-ingest-consumer
  minReplicaCount: 3
  maxReplicaCount: 64   # == number of partitions on ingest.raw
  pollingInterval: 15
  cooldownPeriod: 120
  triggers:
    - type: kafka
      metadata:
        bootstrapServers: kafka.shieldops.svc.cluster.local:9092
        consumerGroup: shieldops-ingestion
        topic: ingest.raw
        lagThreshold: "2000"   # scale up when avg lag/partition > 2k msgs
        offsetResetPolicy: earliest
```

Rules of thumb:
- Never exceed `partitions` replicas — extra pods sit idle.
- 1 replica can normalize roughly 5k events/s; size `maxReplicaCount` so that
  `replicas * 5k ≥ target msgs/s * 1.5`.

## Manual scaling runbook

Use this when KEDA is unavailable or lag is climbing unexpectedly.

1. **Confirm lag is the problem.**
   ```bash
   kafka-consumer-groups.sh --bootstrap-server kafka:9092 \
     --group shieldops-ingestion --describe
   ```
   Look for rising `LAG` column. If it is flat, check downstream storage.

2. **Scale the Deployment.**
   ```bash
   kubectl -n shieldops scale deploy/shieldops-ingest-consumer --replicas=16
   ```
   Do not exceed the partition count of `ingest.raw` (currently 64).

3. **If still lagging after 5 minutes**, check the storage write path:
   ```bash
   kubectl -n shieldops logs deploy/shieldops-ingest-consumer --tail=200 \
     | grep kafka_consumer.store_insert_failed
   ```
   Slow inserts are the most common root cause.

4. **Shed load if necessary** by lowering the API backpressure threshold:
   ```bash
   curl -XPOST https://api.shieldops/api/v1/admin/ingestion/backpressure \
     -d '{"threshold": 2000}'
   ```
   Callers will receive `429` and back off.

5. **Drain DLQ** once the incident clears:
   ```bash
   shieldops dlq replay --topic ingest.dlq --since 1h
   ```

## Schema evolution

Producer writes raw events as **JSON strings**. Consumers parse lazily and use
`.get()` lookups when reading new fields, so adding fields is always
non-breaking. Removing or renaming a field requires a dual-write migration —
update the OCSF mapper to understand both names for at least one retention
window before removing the old name.

## Failure modes

| Symptom                      | Likely cause                   | Action                               |
|------------------------------|--------------------------------|--------------------------------------|
| 429s on `/ingestion/events`  | Consumer lag > threshold       | Scale consumers; check storage       |
| DLQ rate > 1%                | Mapper regression / bad vendor | Inspect DLQ headers; fix mapper      |
| Duplicate events downstream  | Redis dedup unavailable        | Check Redis; dedup is fail-open      |
| Producer `unavailable_skip`  | Kafka unreachable              | Check broker; API falls back to sync |
