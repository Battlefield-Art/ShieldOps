###############################################################################
# ShieldOps — ClickHouse Nightly Backup Lambda
#
# Runs nightly on an EventBridge schedule. Issues BACKUP TABLE statements
# against each ClickHouse node's HTTP interface (port 8123), streaming the
# resulting parts into an S3 bucket. The bucket has a lifecycle policy that
# transitions backups to Glacier after 30 days and expires them after 365
# days, matching enterprise retention defaults.
###############################################################################

# ---------------------------------------------------------------------------
# S3 Backup Bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "clickhouse_backups" {
  bucket = "${local.name_prefix}-clickhouse-backups-${local.account_id}"

  tags = {
    Name        = "${local.name_prefix}-clickhouse-backups"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

resource "aws_s3_bucket_versioning" "clickhouse_backups" {
  bucket = aws_s3_bucket.clickhouse_backups.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "clickhouse_backups" {
  bucket = aws_s3_bucket.clickhouse_backups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "clickhouse_backups" {
  bucket                  = aws_s3_bucket.clickhouse_backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "clickhouse_backups" {
  bucket = aws_s3_bucket.clickhouse_backups.id

  rule {
    id     = "transition-to-glacier"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# ---------------------------------------------------------------------------
# Lambda IAM role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "clickhouse_backup_lambda" {
  name = "${local.name_prefix}-clickhouse-backup-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name        = "${local.name_prefix}-clickhouse-backup-lambda-role"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

resource "aws_iam_role_policy_attachment" "clickhouse_backup_vpc" {
  role       = aws_iam_role.clickhouse_backup_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "clickhouse_backup_lambda" {
  name = "${local.name_prefix}-clickhouse-backup-lambda"
  role = aws_iam_role.clickhouse_backup_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
        ]
        Resource = [
          aws_s3_bucket.clickhouse_backups.arn,
          "${aws_s3_bucket.clickhouse_backups.arn}/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [aws_secretsmanager_secret.clickhouse_password.arn]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "*"
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Lambda security group (runs in the VPC to reach ClickHouse ENIs)
# ---------------------------------------------------------------------------

resource "aws_security_group" "clickhouse_backup_lambda" {
  name        = "${local.name_prefix}-clickhouse-backup-lambda-sg"
  description = "Security group for the ClickHouse backup Lambda"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all egress (ClickHouse HTTP, Secrets Manager, S3 gateway)"
  }

  tags = {
    Name        = "${local.name_prefix}-clickhouse-backup-lambda-sg"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

resource "aws_security_group_rule" "clickhouse_http_from_backup_lambda" {
  type                     = "ingress"
  from_port                = 8123
  to_port                  = 8123
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.clickhouse_backup_lambda.id
  security_group_id        = aws_security_group.clickhouse.id
  description              = "ClickHouse HTTP from backup Lambda"
}

# ---------------------------------------------------------------------------
# Lambda source archive
# ---------------------------------------------------------------------------

data "archive_file" "clickhouse_backup_lambda" {
  type        = "zip"
  output_path = "${path.module}/build/clickhouse_backup_lambda.zip"

  source {
    filename = "handler.py"
    content  = <<-PY
      """ClickHouse nightly backup Lambda.

      For each cluster node it issues:
          BACKUP TABLE shieldops.events TO S3('s3://<bucket>/<ts>/<node>/', '<key>', '<secret>')
      via the ClickHouse HTTP interface. Errors are logged and re-raised so
      CloudWatch alarms can fire on failure.
      """
      import json
      import os
      import urllib.request
      import urllib.parse
      import urllib.error
      from datetime import datetime, timezone

      import boto3

      CLUSTER_NODES = os.environ["CLUSTER_NODES"].split(",")
      BUCKET = os.environ["BACKUP_BUCKET"]
      REGION = os.environ["AWS_REGION"]
      SECRET_ARN = os.environ["PASSWORD_SECRET_ARN"]
      CH_USER = os.environ.get("CH_USER", "shieldops")


      def _get_password() -> str:
          client = boto3.client("secretsmanager", region_name=REGION)
          return client.get_secret_value(SecretId=SECRET_ARN)["SecretString"]


      def _ch_query(host: str, password: str, query: str) -> str:
          url = f"http://{host}:8123/?" + urllib.parse.urlencode({"query": query})
          req = urllib.request.Request(
              url,
              headers={
                  "X-ClickHouse-User": CH_USER,
                  "X-ClickHouse-Key": password,
              },
          )
          with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310
              return resp.read().decode("utf-8", errors="replace")


      def handler(event, context):  # noqa: ARG001
          password = _get_password()
          ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
          results = []
          errors = []

          for node in CLUSTER_NODES:
              backup_path = f"s3://{BUCKET}/{ts}/{node}/events.zip"
              query = (
                  f"BACKUP TABLE shieldops.events_local "
                  f"TO S3('{backup_path}', '', '') "
                  f"SETTINGS async=0"
              )
              try:
                  body = _ch_query(node, password, query)
                  results.append({"node": node, "backup": backup_path, "body": body[:500]})
              except urllib.error.URLError as exc:
                  errors.append({"node": node, "error": str(exc)})

          payload = {
              "timestamp": ts,
              "bucket": BUCKET,
              "results": results,
              "errors": errors,
          }
          print(json.dumps(payload))
          if errors:
              raise RuntimeError(f"ClickHouse backup failed: {errors}")
          return payload
    PY
  }
}

# ---------------------------------------------------------------------------
# Lambda function
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "clickhouse_backup" {
  function_name = "${local.name_prefix}-clickhouse-backup"
  role          = aws_iam_role.clickhouse_backup_lambda.arn
  handler       = "handler.handler"
  runtime       = "python3.12"
  timeout       = 900
  memory_size   = 512

  filename         = data.archive_file.clickhouse_backup_lambda.output_path
  source_code_hash = data.archive_file.clickhouse_backup_lambda.output_base64sha256

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.clickhouse_backup_lambda.id]
  }

  environment {
    variables = {
      CLUSTER_NODES       = join(",", [for i in local.clickhouse_nodes : "clickhouse-${i}.${var.clickhouse_internal_zone_name}"])
      BACKUP_BUCKET       = aws_s3_bucket.clickhouse_backups.bucket
      PASSWORD_SECRET_ARN = aws_secretsmanager_secret.clickhouse_password.arn
      CH_USER             = "shieldops"
    }
  }

  tags = {
    Name        = "${local.name_prefix}-clickhouse-backup"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

# ---------------------------------------------------------------------------
# EventBridge schedule — nightly at 02:00 UTC
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "clickhouse_backup_nightly" {
  name                = "${local.name_prefix}-clickhouse-backup-nightly"
  description         = "Nightly ClickHouse backup trigger"
  schedule_expression = "cron(0 2 * * ? *)"

  tags = {
    Name        = "${local.name_prefix}-clickhouse-backup-nightly"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

resource "aws_cloudwatch_event_target" "clickhouse_backup_nightly" {
  rule      = aws_cloudwatch_event_rule.clickhouse_backup_nightly.name
  target_id = "clickhouse-backup-lambda"
  arn       = aws_lambda_function.clickhouse_backup.arn
}

resource "aws_lambda_permission" "clickhouse_backup_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.clickhouse_backup.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.clickhouse_backup_nightly.arn
}

# ---------------------------------------------------------------------------
# Alarm — backup Lambda failure
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "clickhouse_backup_errors" {
  alarm_name          = "${local.name_prefix}-clickhouse-backup-errors"
  alarm_description   = "ClickHouse nightly backup Lambda failed in the last 24h"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 86400
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.clickhouse_backup.function_name
  }

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]

  tags = {
    Name        = "${local.name_prefix}-clickhouse-backup-errors-alarm"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

output "clickhouse_backup_bucket" {
  description = "S3 bucket holding nightly ClickHouse backups"
  value       = aws_s3_bucket.clickhouse_backups.bucket
}

output "clickhouse_backup_lambda_name" {
  description = "Name of the ClickHouse backup Lambda function"
  value       = aws_lambda_function.clickhouse_backup.function_name
}
