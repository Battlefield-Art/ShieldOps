# Kafka Topic Management

Create, delete, and tune topics on the production MSK cluster.

## When to use
- Onboarding a new agent fleet that needs a dedicated topic.
- Decommissioning a topic (deprecation complete, no consumers).
- Tuning retention on a high-volume topic.
- Rebalancing partitions after broker scaling.

## Prerequisites
- AWS SSO `shieldops-production` with `kafka-operator` role.
- `kafka-topics.sh` available (use the admin container: `infrastructure/docker/kafka-admin`).
- MSK client auth: TLS with IAM.
- Bootstrap brokers: `terraform output -raw kafka_brokers`.

## Environment setup

```bash
export BOOTSTRAP=$(terraform -chdir=infrastructure/terraform/aws/production output -raw kafka_brokers)
export CONFIG=/tmp/client.properties
cat > $CONFIG <<'EOF'
security.protocol=SASL_SSL
sasl.mechanism=AWS_MSK_IAM
sasl.jaas.config=software.amazon.msk.auth.iam.IAMLoginModule required;
sasl.client.callback.handler.class=software.amazon.msk.auth.iam.IAMClientCallbackHandler
EOF
```

## Create a topic

```bash
kafka-topics.sh --bootstrap-server $BOOTSTRAP --command-config $CONFIG \
  --create \
  --topic shieldops.agent.runs \
  --partitions 12 \
  --replication-factor 3 \
  --config retention.ms=604800000 \
  --config min.insync.replicas=2 \
  --config cleanup.policy=delete \
  --config compression.type=zstd
```

Sizing rule of thumb:
- partitions = peak MB/s ÷ 10 (per-partition ceiling), rounded up to a multiple of broker count.
- replication factor = 3 for production.
- `min.insync.replicas = 2` for durability.

## List topics

```bash
kafka-topics.sh --bootstrap-server $BOOTSTRAP --command-config $CONFIG --list
```

## Describe a topic

```bash
kafka-topics.sh --bootstrap-server $BOOTSTRAP --command-config $CONFIG \
  --describe --topic shieldops.agent.runs
```

## Change retention

```bash
kafka-configs.sh --bootstrap-server $BOOTSTRAP --command-config $CONFIG \
  --alter --entity-type topics --entity-name shieldops.agent.runs \
  --add-config retention.ms=259200000   # 3 days
```

## Delete a topic

1. **Verify no consumers**
   ```bash
   kafka-consumer-groups.sh --bootstrap-server $BOOTSTRAP --command-config $CONFIG \
     --list | xargs -I{} kafka-consumer-groups.sh --bootstrap-server $BOOTSTRAP \
     --command-config $CONFIG --describe --group {} 2>/dev/null \
     | grep shieldops.agent.runs
   ```
2. **Delete**
   ```bash
   kafka-topics.sh --bootstrap-server $BOOTSTRAP --command-config $CONFIG \
     --delete --topic shieldops.agent.runs
   ```
3. **Verify gone** — re-run `--list`.

## Increase partitions

```bash
kafka-topics.sh --bootstrap-server $BOOTSTRAP --command-config $CONFIG \
  --alter --topic shieldops.agent.runs --partitions 24
```
Warning: partition count can only increase; message ordering guarantees for keys may shift. Document and coordinate with consumer teams first.

## Verification
- `--describe` shows the expected partition count and config.
- `UnderReplicatedPartitions` metric stays at 0.
- `OfflinePartitionsCount` stays at 0.
- Consumer lag does not grow unexpectedly.

## Reference metrics (ops dashboard)
- `AWS/Kafka / CpuUser` — broker CPU
- `AWS/Kafka / UnderReplicatedPartitions` — should always be 0
- `AWS/Kafka / OfflinePartitionsCount` — should always be 0
- `AWS/Kafka / KafkaDataLogsDiskUsed` — alert at 75%
