###############################################################################
# ShieldOps — Production Variables
###############################################################################

# ---------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"

  validation {
    condition     = var.environment == "production"
    error_message = "This module is for production only."
  }
}

variable "project_name" {
  description = "Project name used as a prefix for all resources"
  type        = string
  default     = "shieldops"
}

variable "cost_center" {
  description = "Cost center tag for billing allocation"
  type        = string
  default     = "engineering"
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

variable "vpc_cidr" {
  description = "CIDR block for the production VPC"
  type        = string
  default     = "10.0.0.0/16"
}

# ---------------------------------------------------------------------------
# ECS — API Service
# ---------------------------------------------------------------------------

variable "api_cpu" {
  description = "CPU units for the API ECS task (1 vCPU = 1024)"
  type        = number
  default     = 2048
}

variable "api_memory" {
  description = "Memory (MiB) for the API ECS task"
  type        = number
  default     = 4096
}

variable "api_desired_count" {
  description = "Desired number of API ECS tasks"
  type        = number
  default     = 2
}

variable "api_min_capacity" {
  description = "Minimum number of API ECS tasks for auto-scaling"
  type        = number
  default     = 2
}

variable "api_max_capacity" {
  description = "Maximum number of API ECS tasks for auto-scaling"
  type        = number
  default     = 10
}

variable "api_image" {
  description = "Docker image URI for the ShieldOps API"
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# ECS — Worker Service
# ---------------------------------------------------------------------------

variable "worker_cpu" {
  description = "CPU units for the worker ECS task (1 vCPU = 1024)"
  type        = number
  default     = 4096
}

variable "worker_memory" {
  description = "Memory (MiB) for the worker ECS task"
  type        = number
  default     = 8192
}

variable "worker_desired_count" {
  description = "Desired number of worker ECS tasks"
  type        = number
  default     = 1
}

variable "worker_min_capacity" {
  description = "Minimum number of worker ECS tasks for auto-scaling"
  type        = number
  default     = 1
}

variable "worker_max_capacity" {
  description = "Maximum number of worker ECS tasks for auto-scaling"
  type        = number
  default     = 20
}

variable "worker_image" {
  description = "Docker image URI for the ShieldOps worker"
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# ECS — Dashboard Service
# ---------------------------------------------------------------------------

variable "dashboard_image" {
  description = "Docker image URI for the ShieldOps dashboard"
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Database (RDS PostgreSQL)
# ---------------------------------------------------------------------------

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r6g.large"
}

variable "db_allocated_storage" {
  description = "Allocated storage in GB for the RDS instance"
  type        = number
  default     = 100
}

# ---------------------------------------------------------------------------
# Cache (ElastiCache Redis)
# ---------------------------------------------------------------------------

variable "redis_node_type" {
  description = "ElastiCache node type for Redis"
  type        = string
  default     = "cache.r6g.large"
}

variable "redis_num_shards" {
  description = "Number of Redis shards (node groups) for cluster mode"
  type        = number
  default     = 2
}

variable "redis_replicas_per_shard" {
  description = "Number of replicas per shard"
  type        = number
  default     = 1
}

# ---------------------------------------------------------------------------
# Kafka (MSK)
# ---------------------------------------------------------------------------

variable "kafka_instance_type" {
  description = "MSK broker instance type"
  type        = string
  default     = "kafka.m5.large"
}

variable "kafka_ebs_volume_size" {
  description = "EBS volume size (GB) per MSK broker"
  type        = number
  default     = 100
}

# ---------------------------------------------------------------------------
# TLS / Domain
# ---------------------------------------------------------------------------

variable "domain_name" {
  description = "Apex domain for the ShieldOps platform"
  type        = string
  default     = "shieldops.io"
}

variable "subdomain_api" {
  description = "Subdomain label for the public API endpoint"
  type        = string
  default     = "api"
}

variable "subdomain_app" {
  description = "Subdomain label for the dashboard/app endpoint"
  type        = string
  default     = "app"
}

variable "subdomain_status" {
  description = "Subdomain label for the external status page"
  type        = string
  default     = "status"
}

variable "status_page_target" {
  description = "CNAME target for the external status page provider (e.g. statuspage.io, betterstack, atlassian)"
  type        = string
  default     = "statuspage.io."
}

variable "certificate_arn" {
  description = "Optional override ARN of an existing ACM certificate. Leave empty to provision via acm.tf"
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

variable "secrets_arn" {
  description = "ARN of the existing Secrets Manager secret containing application secrets"
  type        = string
}

# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------

variable "alarm_email" {
  description = "Email address for CloudWatch alarm notifications"
  type        = string
  default     = ""
}

variable "pagerduty_integration_url" {
  description = "PagerDuty CloudWatch integration URL (from a PagerDuty service). When empty, PagerDuty paging is disabled."
  type        = string
  default     = ""
  sensitive   = true
}

# ---------------------------------------------------------------------------
# WAF
# ---------------------------------------------------------------------------

variable "waf_rate_limit" {
  description = "Maximum requests per 5-minute period per IP"
  type        = number
  default     = 2000
}
