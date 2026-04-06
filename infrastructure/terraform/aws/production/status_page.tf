###############################################################################
# ShieldOps — Status Page & Synthetic Monitoring
#
# This file provisions the AWS-side resources that feed the external status
# page (the page itself is vendor-hosted — see below):
#
#   1. CloudWatch Synthetics canaries: one per public service (api, app,
#      ingestion). Canaries run every 5 minutes and exercise the /health
#      endpoint over HTTPS, validating certificate + reachability.
#   2. SNS topic: receives canary failure events and forwards to the
#      external status page provider (via webhook subscription added
#      out-of-band, or to on-call via `alarm_email`).
#   3. S3 bucket: required by CloudWatch Synthetics for canary artifacts
#      (screenshots, HAR files, logs).
#
# External dependency: the public-facing status page is hosted by a SaaS
# provider (statuspage.io / Atlassian Statuspage / BetterStack / Instatus).
# Integration is one of:
#   - Webhook subscription from `aws_sns_topic.status_page` → vendor ingest
#   - Polling of CloudWatch metrics via vendor's AWS integration
# Configure the subscription via the vendor console and reference the SNS
# topic ARN exported below.
###############################################################################

# ---------------------------------------------------------------------------
# Locals — service catalog for canaries
# ---------------------------------------------------------------------------

locals {
  status_page_services = {
    api = {
      url         = "https://${var.subdomain_api}.${var.domain_name}/health"
      description = "ShieldOps public API health"
    }
    app = {
      url         = "https://${var.subdomain_app}.${var.domain_name}/"
      description = "ShieldOps dashboard (app) availability"
    }
    ingestion = {
      url         = "https://${var.subdomain_api}.${var.domain_name}/api/v1/ingest/health"
      description = "ShieldOps telemetry ingestion health"
    }
  }
}

# ---------------------------------------------------------------------------
# SNS topic — status page integration + on-call fanout
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "status_page" {
  name              = "${local.name_prefix}-status-page"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Name        = "${local.name_prefix}-status-page"
    Environment = var.environment
    Service     = "shieldops"
    ManagedBy   = "terraform"
  }
}

resource "aws_sns_topic_subscription" "status_page_email" {
  count = var.alarm_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.status_page.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ---------------------------------------------------------------------------
# S3 bucket — canary artifacts
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "canary_artifacts" {
  bucket = "${local.name_prefix}-canary-artifacts-${local.account_id}"

  tags = {
    Name        = "${local.name_prefix}-canary-artifacts"
    Environment = var.environment
    Service     = "shieldops"
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket_public_access_block" "canary_artifacts" {
  bucket = aws_s3_bucket.canary_artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "canary_artifacts" {
  bucket = aws_s3_bucket.canary_artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "canary_artifacts" {
  bucket = aws_s3_bucket.canary_artifacts.id

  rule {
    id     = "expire-old-artifacts"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }
  }
}

# ---------------------------------------------------------------------------
# IAM role — CloudWatch Synthetics execution
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "canary_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "canary" {
  name               = "${local.name_prefix}-canary-role"
  assume_role_policy = data.aws_iam_policy_document.canary_assume.json

  tags = {
    Name        = "${local.name_prefix}-canary-role"
    Environment = var.environment
    Service     = "shieldops"
    ManagedBy   = "terraform"
  }
}

data "aws_iam_policy_document" "canary" {
  statement {
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [
      aws_s3_bucket.canary_artifacts.arn,
      "${aws_s3_bucket.canary_artifacts.arn}/*",
    ]
  }

  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/cwsyn-*"]
  }

  statement {
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CloudWatchSynthetics"]
    }
  }
}

resource "aws_iam_role_policy" "canary" {
  name   = "${local.name_prefix}-canary-policy"
  role   = aws_iam_role.canary.id
  policy = data.aws_iam_policy_document.canary.json
}

# ---------------------------------------------------------------------------
# Canary runtime script — generated heartbeat monitor per service
# ---------------------------------------------------------------------------

data "archive_file" "canary_script" {
  for_each = local.status_page_services

  type        = "zip"
  output_path = "${path.module}/.terraform/canary-${each.key}.zip"

  source {
    filename = "nodejs/node_modules/heartbeat.js"
    content  = <<-EOT
      const synthetics = require('Synthetics');
      const log = require('SyntheticsLogger');

      const heartbeat = async function () {
        const url = '${each.value.url}';
        log.info('Fetching ' + url);
        const page = await synthetics.getPage();
        const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
        if (!response) {
          throw new Error('No response received from ' + url);
        }
        const status = response.status();
        if (status < 200 || status > 299) {
          throw new Error('Unhealthy status ' + status + ' from ' + url);
        }
        log.info('OK ' + status + ' ' + url);
      };

      exports.handler = async () => {
        return await heartbeat();
      };
    EOT
  }
}

# ---------------------------------------------------------------------------
# CloudWatch Synthetics canaries — one per public service
# ---------------------------------------------------------------------------

resource "aws_synthetics_canary" "service" {
  for_each = local.status_page_services

  name                 = substr("${var.project_name}-${each.key}-hb", 0, 21)
  artifact_s3_location = "s3://${aws_s3_bucket.canary_artifacts.id}/${each.key}/"
  execution_role_arn   = aws_iam_role.canary.arn
  runtime_version      = "syn-nodejs-puppeteer-6.2"
  handler              = "heartbeat.handler"
  zip_file             = data.archive_file.canary_script[each.key].output_path
  start_canary         = true

  schedule {
    expression          = "rate(5 minutes)"
    duration_in_seconds = 0
  }

  run_config {
    timeout_in_seconds    = 60
    memory_in_mb          = 1024
    active_tracing        = false
    environment_variables = {}
  }

  success_retention_period = 7
  failure_retention_period = 30

  tags = {
    Name        = "${local.name_prefix}-${each.key}-canary"
    Environment = var.environment
    Service     = each.key
    ManagedBy   = "terraform"
  }
}

# ---------------------------------------------------------------------------
# CloudWatch alarms — one per canary → SNS status page topic
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "canary_failure" {
  for_each = local.status_page_services

  alarm_name          = "${local.name_prefix}-${each.key}-canary-failure"
  alarm_description   = "${each.value.description} — canary success rate below 100%"
  namespace           = "CloudWatchSynthetics"
  metric_name         = "SuccessPercent"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 1
  threshold           = 100
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"

  dimensions = {
    CanaryName = aws_synthetics_canary.service[each.key].name
  }

  alarm_actions = [aws_sns_topic.status_page.arn]
  ok_actions    = [aws_sns_topic.status_page.arn]

  tags = {
    Name        = "${local.name_prefix}-${each.key}-canary-alarm"
    Environment = var.environment
    Service     = each.key
    ManagedBy   = "terraform"
  }
}
