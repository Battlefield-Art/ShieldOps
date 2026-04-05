###############################################################################
# ShieldOps — Production MSK Kafka (3 Brokers, IAM Auth, Encrypted)
###############################################################################

# ---------------------------------------------------------------------------
# KMS Key for MSK Encryption
# ---------------------------------------------------------------------------

resource "aws_kms_key" "msk" {
  description             = "KMS key for ShieldOps production MSK encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "${local.name_prefix}-msk-kms"
  }
}

resource "aws_kms_alias" "msk" {
  name          = "alias/${local.name_prefix}-msk"
  target_key_id = aws_kms_key.msk.key_id
}

# ---------------------------------------------------------------------------
# MSK Configuration
# ---------------------------------------------------------------------------

resource "aws_msk_configuration" "main" {
  name           = "${local.name_prefix}-kafka-config"
  kafka_versions = ["3.6.0"]
  description    = "ShieldOps production Kafka broker configuration"

  server_properties = <<-PROPERTIES
    auto.create.topics.enable=false
    default.replication.factor=3
    min.insync.replicas=2
    num.partitions=6
    num.replica.fetchers=2
    replica.lag.time.max.ms=30000
    log.retention.hours=168
    log.segment.bytes=1073741824
    log.retention.check.interval.ms=300000
    unclean.leader.election.enable=false
    message.max.bytes=10485760
  PROPERTIES

  lifecycle {
    create_before_destroy = true
  }
}

# ---------------------------------------------------------------------------
# CloudWatch Log Group for MSK
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "msk" {
  name              = "/msk/${local.name_prefix}"
  retention_in_days = 30

  tags = {
    Name = "${local.name_prefix}-msk-logs"
  }
}

# ---------------------------------------------------------------------------
# MSK Cluster
# ---------------------------------------------------------------------------

resource "aws_msk_cluster" "main" {
  cluster_name           = "${local.name_prefix}-kafka"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = var.kafka_instance_type
    client_subnets  = aws_subnet.private[*].id
    security_groups = [aws_security_group.msk.id]

    storage_info {
      ebs_storage_info {
        volume_size = var.kafka_ebs_volume_size
      }
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.main.arn
    revision = aws_msk_configuration.main.latest_revision
  }

  encryption_info {
    encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn

    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  client_authentication {
    sasl {
      iam = true
    }
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk.name
      }
    }
  }

  tags = {
    Name = "${local.name_prefix}-kafka"
  }
}
