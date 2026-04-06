###############################################################################
# ShieldOps — Operations Dashboard
#
# Operations-centric view (distinct from monitoring.tf's overview dashboard).
# Focused on SLO-relevant metrics: ALB throughput, error budget, ECS capacity,
# RDS health, Redis/Kafka saturation.
###############################################################################

resource "aws_cloudwatch_dashboard" "operations" {
  dashboard_name = "${local.name_prefix}-operations"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 24
        height = 4
        properties = {
          title  = "ALB — Request Rate & Error Rate (SLO)"
          region = local.region
          view   = "timeSeries"
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.main.arn_suffix, { stat = "Sum", label = "Requests" }],
            [".", "HTTPCode_Target_5XX_Count", ".", ".", { stat = "Sum", label = "5xx" }],
            [".", "HTTPCode_Target_4XX_Count", ".", ".", { stat = "Sum", label = "4xx" }],
          ]
          period = 60
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 4
        width  = 12
        height = 6
        properties = {
          title  = "ALB — Target Response Time (p50/p95/p99)"
          region = local.region
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.main.arn_suffix, { stat = "p50", label = "p50" }],
            ["...", { stat = "p95", label = "p95" }],
            ["...", { stat = "p99", label = "p99" }],
          ]
          period = 60
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 4
        width  = 12
        height = 6
        properties = {
          title  = "ECS API — Running Tasks vs Desired"
          region = local.region
          metrics = [
            ["ECS/ContainerInsights", "RunningTaskCount", "ClusterName", aws_ecs_cluster.main.name, "ServiceName", aws_ecs_service.api.name],
            [".", "DesiredTaskCount", ".", ".", ".", "."],
            [".", "PendingTaskCount", ".", ".", ".", "."],
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 10
        width  = 8
        height = 6
        properties = {
          title  = "ECS API — CPU / Memory"
          region = local.region
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", aws_ecs_cluster.main.name, "ServiceName", aws_ecs_service.api.name],
            [".", "MemoryUtilization", ".", ".", ".", "."],
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 10
        width  = 8
        height = 6
        properties = {
          title  = "ECS Worker — CPU / Memory"
          region = local.region
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", aws_ecs_cluster.main.name, "ServiceName", aws_ecs_service.worker.name],
            [".", "MemoryUtilization", ".", ".", ".", "."],
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 10
        width  = 8
        height = 6
        properties = {
          title  = "RDS — Connections & CPU"
          region = local.region
          metrics = [
            ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", aws_db_instance.main.identifier],
            [".", "CPUUtilization", ".", "."],
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 16
        width  = 12
        height = 6
        properties = {
          title  = "RDS — Free Storage & IOPS"
          region = local.region
          metrics = [
            ["AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier", aws_db_instance.main.identifier],
            [".", "ReadIOPS", ".", "."],
            [".", "WriteIOPS", ".", "."],
          ]
          period = 300
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 16
        width  = 12
        height = 6
        properties = {
          title  = "Redis — Memory / Evictions / Latency"
          region = local.region
          metrics = [
            ["AWS/ElastiCache", "DatabaseMemoryUsagePercentage", "ReplicationGroupId", aws_elasticache_replication_group.main.id],
            [".", "Evictions", ".", "."],
            [".", "EngineCPUUtilization", ".", "."],
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 22
        width  = 24
        height = 6
        properties = {
          title  = "Kafka — Broker CPU & Partition Health"
          region = local.region
          metrics = [
            ["AWS/Kafka", "CpuUser", "Cluster Name", aws_msk_cluster.main.cluster_name],
            [".", "UnderReplicatedPartitions", ".", "."],
            [".", "OfflinePartitionsCount", ".", "."],
            [".", "KafkaDataLogsDiskUsed", ".", "."],
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "text"
        x      = 0
        y      = 28
        width  = 24
        height = 3
        properties = {
          markdown = "### Runbooks\n- [Deploy new version](https://github.com/shieldops/shieldops/blob/main/docs/runbooks/deploy-new-version.md) | [Rollback](https://github.com/shieldops/shieldops/blob/main/docs/runbooks/rollback-deployment.md)\n- [RDS failover](https://github.com/shieldops/shieldops/blob/main/docs/runbooks/rds-failover.md) | [Backup/restore](https://github.com/shieldops/shieldops/blob/main/docs/runbooks/database-backup-restore.md)\n- [Scale up/down](https://github.com/shieldops/shieldops/blob/main/docs/runbooks/scale-up-down.md) | [High error rate](https://github.com/shieldops/shieldops/blob/main/docs/runbooks/investigate-high-error-rate.md)"
        }
      },
    ]
  })
}
