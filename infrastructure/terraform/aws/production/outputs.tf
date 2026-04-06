###############################################################################
# ShieldOps — Production Outputs
###############################################################################

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

output "vpc_id" {
  description = "ID of the production VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

# ---------------------------------------------------------------------------
# Load Balancer
# ---------------------------------------------------------------------------

output "alb_dns_name" {
  description = "DNS name of the production ALB"
  value       = aws_lb.main.dns_name
}

output "alb_arn" {
  description = "ARN of the production ALB"
  value       = aws_lb.main.arn
}

# ---------------------------------------------------------------------------
# ECS
# ---------------------------------------------------------------------------

output "ecs_cluster_arn" {
  description = "ARN of the ECS cluster"
  value       = aws_ecs_cluster.main.arn
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "ecs_api_service_name" {
  description = "Name of the ECS API service"
  value       = aws_ecs_service.api.name
}

output "ecs_worker_service_name" {
  description = "Name of the ECS worker service"
  value       = aws_ecs_service.worker.name
}

# ---------------------------------------------------------------------------
# ECR
# ---------------------------------------------------------------------------

output "ecr_api_repository_url" {
  description = "URL of the API ECR repository"
  value       = aws_ecr_repository.api.repository_url
}

output "ecr_worker_repository_url" {
  description = "URL of the worker ECR repository"
  value       = aws_ecr_repository.worker.repository_url
}

output "ecr_dashboard_repository_url" {
  description = "URL of the dashboard ECR repository"
  value       = aws_ecr_repository.dashboard.repository_url
}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint (host only)"
  value       = aws_db_instance.main.address
}

output "rds_port" {
  description = "RDS PostgreSQL port"
  value       = aws_db_instance.main.port
}

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

output "redis_endpoint" {
  description = "ElastiCache Redis configuration endpoint (cluster mode)"
  value       = aws_elasticache_replication_group.main.configuration_endpoint_address
}

output "redis_port" {
  description = "ElastiCache Redis port"
  value       = aws_elasticache_replication_group.main.port
}

# ---------------------------------------------------------------------------
# Kafka
# ---------------------------------------------------------------------------

output "kafka_brokers" {
  description = "MSK Kafka bootstrap brokers (TLS)"
  value       = aws_msk_cluster.main.bootstrap_brokers_tls
}

output "kafka_cluster_arn" {
  description = "ARN of the MSK cluster"
  value       = aws_msk_cluster.main.arn
}

# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

output "data_lake_bucket" {
  description = "Name of the data lake S3 bucket"
  value       = aws_s3_bucket.data_lake.id
}

output "backups_bucket" {
  description = "Name of the backups S3 bucket"
  value       = aws_s3_bucket.backups.id
}

# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------

output "sns_topic_arn" {
  description = "ARN of the SNS topic for CloudWatch alarms"
  value       = aws_sns_topic.alarms.arn
}

output "cloudwatch_dashboard_url" {
  description = "URL of the CloudWatch dashboard"
  value       = "https://${local.region}.console.aws.amazon.com/cloudwatch/home?region=${local.region}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "operations_dashboard_url" {
  description = "URL of the operations CloudWatch dashboard"
  value       = "https://${local.region}.console.aws.amazon.com/cloudwatch/home?region=${local.region}#dashboards:name=${aws_cloudwatch_dashboard.operations.dashboard_name}"
}

# ---------------------------------------------------------------------------
# Backup Verification
# ---------------------------------------------------------------------------

output "backup_test_lambda_arn" {
  description = "ARN of the weekly backup verification Lambda"
  value       = aws_lambda_function.backup_test.arn
}

output "backup_test_schedule" {
  description = "Cron schedule for backup verification"
  value       = aws_cloudwatch_event_rule.backup_test_weekly.schedule_expression
}

# ---------------------------------------------------------------------------
# PagerDuty
# ---------------------------------------------------------------------------

output "pagerduty_critical_topic_arn" {
  description = "ARN of the dedicated SNS topic for PagerDuty critical paging"
  value       = aws_sns_topic.pagerduty_critical.arn
}

# ---------------------------------------------------------------------------
# Log Archive
# ---------------------------------------------------------------------------

output "log_archive_bucket" {
  description = "S3 bucket name for long-term log archive"
  value       = aws_s3_bucket.log_archive.id
}

output "log_archive_firehose_arn" {
  description = "ARN of the Kinesis Firehose for CloudWatch Logs archival"
  value       = aws_kinesis_firehose_delivery_stream.log_archive.arn
}

# ---------------------------------------------------------------------------
# WAF
# ---------------------------------------------------------------------------

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.arn
}

# ---------------------------------------------------------------------------
# CI/CD
# ---------------------------------------------------------------------------

output "github_actions_deploy_role_arn" {
  description = "ARN of the IAM role for GitHub Actions OIDC deploy"
  value       = aws_iam_role.github_actions_deploy.arn
}

# ---------------------------------------------------------------------------
# DNS / TLS / Status Page
# ---------------------------------------------------------------------------

output "api_url" {
  description = "Public HTTPS URL for the ShieldOps API"
  value       = "https://${var.subdomain_api}.${var.domain_name}"
}

output "app_url" {
  description = "Public HTTPS URL for the ShieldOps dashboard (app)"
  value       = "https://${var.subdomain_app}.${var.domain_name}"
}

output "status_url" {
  description = "Public URL for the ShieldOps status page (external provider)"
  value       = "https://${var.subdomain_status}.${var.domain_name}"
}

output "certificate_arn" {
  description = "ARN of the ACM certificate wired to the ALB HTTPS listener"
  value       = local.effective_certificate_arn
}

output "route53_zone_id" {
  description = "ID of the Route53 hosted zone for the ShieldOps domain"
  value       = data.aws_route53_zone.main.zone_id
}

output "status_page_sns_topic_arn" {
  description = "ARN of the SNS topic feeding the external status page provider"
  value       = aws_sns_topic.status_page.arn
}

output "canary_names" {
  description = "Names of the CloudWatch Synthetics canaries monitoring public services"
  value       = { for k, c in aws_synthetics_canary.service : k => c.name }
}
