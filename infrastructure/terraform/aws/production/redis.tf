###############################################################################
# ShieldOps — Production ElastiCache Redis (Cluster Mode, Encrypted)
###############################################################################

# ---------------------------------------------------------------------------
# Subnet Group
# ---------------------------------------------------------------------------

resource "aws_elasticache_subnet_group" "main" {
  name        = "${local.name_prefix}-redis-subnet"
  description = "Redis subnet group for ShieldOps production"
  subnet_ids  = aws_subnet.private[*].id

  tags = {
    Name = "${local.name_prefix}-redis-subnet"
  }
}

# ---------------------------------------------------------------------------
# Redis Auth Token
# ---------------------------------------------------------------------------

resource "random_password" "redis_auth" {
  length           = 64
  special          = true
  override_special = "!&#$^<>-"
}

resource "aws_secretsmanager_secret" "redis_auth" {
  name        = "${var.project_name}/${var.environment}/redis-auth-token"
  description = "ElastiCache Redis AUTH token for ShieldOps production"

  tags = {
    Name = "${local.name_prefix}-redis-auth-token"
  }
}

resource "aws_secretsmanager_secret_version" "redis_auth" {
  secret_id     = aws_secretsmanager_secret.redis_auth.id
  secret_string = random_password.redis_auth.result
}

# ---------------------------------------------------------------------------
# Redis Replication Group (Cluster Mode Enabled)
# ---------------------------------------------------------------------------

resource "aws_elasticache_replication_group" "main" {
  replication_group_id = "${local.name_prefix}-redis"
  description          = "ShieldOps production Redis cluster for caching and coordination"

  engine         = "redis"
  engine_version = "7.1"
  node_type      = var.redis_node_type
  port           = 6379

  # Cluster mode: 2 shards, 1 replica per shard
  num_node_groups         = var.redis_num_shards
  replicas_per_node_group = var.redis_replicas_per_shard

  multi_az_enabled           = true
  automatic_failover_enabled = true

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_auth.result

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.elasticache.id]

  maintenance_window       = "sun:05:00-sun:06:00"
  snapshot_retention_limit = 7
  snapshot_window          = "02:00-03:00"

  apply_immediately = false

  tags = {
    Name = "${local.name_prefix}-redis"
  }
}
