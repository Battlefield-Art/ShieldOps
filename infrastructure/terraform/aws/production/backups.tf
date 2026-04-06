###############################################################################
# ShieldOps — Backup Verification
#
# Weekly Lambda that exercises RDS snapshot restoration to validate backups.
# On failure, publishes to the alarms SNS topic (which fans out to email +
# PagerDuty — see pagerduty.tf).
###############################################################################

# ---------------------------------------------------------------------------
# IAM Role for Backup Verification Lambda
# ---------------------------------------------------------------------------

resource "aws_iam_role" "backup_test_lambda" {
  name = "${local.name_prefix}-backup-test-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "${local.name_prefix}-backup-test-lambda"
  }
}

resource "aws_iam_role_policy_attachment" "backup_test_lambda_basic" {
  role       = aws_iam_role.backup_test_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "backup_test_lambda" {
  name = "${local.name_prefix}-backup-test-lambda"
  role = aws_iam_role.backup_test_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBSnapshots",
          "rds:RestoreDBInstanceFromDBSnapshot",
          "rds:DeleteDBInstance",
          "rds:AddTagsToResource",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish",
        ]
        Resource = aws_sns_topic.alarms.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
        ]
        Resource = aws_kms_key.rds.arn
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Backup Verification Lambda Source
# ---------------------------------------------------------------------------

data "archive_file" "backup_test_lambda" {
  type        = "zip"
  output_path = "${path.module}/build/backup_test_lambda.zip"

  source {
    filename = "index.py"
    content  = <<-EOT
      import datetime as dt
      import os
      import time

      import boto3

      rds = boto3.client("rds")
      sns = boto3.client("sns")

      SOURCE_DB = os.environ["SOURCE_DB_IDENTIFIER"]
      SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
      SUBNET_GROUP = os.environ["DB_SUBNET_GROUP"]


      def notify(subject, message):
          sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)


      def handler(event, context):
          ts = dt.datetime.utcnow().strftime("%Y%m%d%H%M%S")
          test_id = f"{SOURCE_DB}-backuptest-{ts}"

          try:
              snaps = rds.describe_db_snapshots(
                  DBInstanceIdentifier=SOURCE_DB,
                  SnapshotType="automated",
                  MaxRecords=20,
              )["DBSnapshots"]
              available = [s for s in snaps if s["Status"] == "available"]
              if not available:
                  raise RuntimeError(f"No available automated snapshots for {SOURCE_DB}")

              latest = max(available, key=lambda s: s["SnapshotCreateTime"])
              snap_id = latest["DBSnapshotIdentifier"]

              rds.restore_db_instance_from_db_snapshot(
                  DBInstanceIdentifier=test_id,
                  DBSnapshotIdentifier=snap_id,
                  DBInstanceClass="db.t3.medium",
                  DBSubnetGroupName=SUBNET_GROUP,
                  MultiAZ=False,
                  PubliclyAccessible=False,
                  DeletionProtection=False,
                  Tags=[
                      {"Key": "Purpose", "Value": "backup-verification"},
                      {"Key": "Ephemeral", "Value": "true"},
                  ],
              )

              deadline = time.time() + 25 * 60
              status = "creating"
              while time.time() < deadline:
                  resp = rds.describe_db_instances(DBInstanceIdentifier=test_id)
                  status = resp["DBInstances"][0]["DBInstanceStatus"]
                  if status == "available":
                      break
                  time.sleep(30)

              rds.delete_db_instance(
                  DBInstanceIdentifier=test_id,
                  SkipFinalSnapshot=True,
                  DeleteAutomatedBackups=True,
              )

              if status != "available":
                  raise TimeoutError(
                      f"Restored instance {test_id} did not become available (status={status})"
                  )

              return {
                  "ok": True,
                  "snapshot": snap_id,
                  "restored_instance": test_id,
                  "status": status,
              }

          except Exception as exc:  # noqa: BLE001
              notify(
                  subject=f"[ShieldOps] Backup verification FAILED for {SOURCE_DB}",
                  message=f"Backup verification failed: {exc!r}\nTest identifier: {test_id}",
              )
              try:
                  rds.delete_db_instance(
                      DBInstanceIdentifier=test_id,
                      SkipFinalSnapshot=True,
                      DeleteAutomatedBackups=True,
                  )
              except Exception:  # noqa: BLE001
                  pass
              raise
    EOT
  }
}

# ---------------------------------------------------------------------------
# Backup Verification Lambda
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "backup_test_lambda" {
  name              = "/aws/lambda/${local.name_prefix}-backup-test"
  retention_in_days = 90

  tags = {
    Name = "${local.name_prefix}-backup-test-logs"
  }
}

resource "aws_lambda_function" "backup_test" {
  function_name = "${local.name_prefix}-backup-test"
  role          = aws_iam_role.backup_test_lambda.arn
  runtime       = "python3.12"
  handler       = "index.handler"
  timeout       = 900
  memory_size   = 256

  filename         = data.archive_file.backup_test_lambda.output_path
  source_code_hash = data.archive_file.backup_test_lambda.output_base64sha256

  environment {
    variables = {
      SOURCE_DB_IDENTIFIER = aws_db_instance.main.identifier
      SNS_TOPIC_ARN        = aws_sns_topic.alarms.arn
      DB_SUBNET_GROUP      = aws_db_subnet_group.main.name
    }
  }

  depends_on = [
    aws_iam_role_policy.backup_test_lambda,
    aws_cloudwatch_log_group.backup_test_lambda,
  ]

  tags = {
    Name = "${local.name_prefix}-backup-test"
  }
}

# ---------------------------------------------------------------------------
# Weekly Schedule (Mondays 08:00 UTC)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "backup_test_weekly" {
  name                = "${local.name_prefix}-backup-test-weekly"
  description         = "Weekly RDS snapshot restoration verification"
  schedule_expression = "cron(0 8 ? * MON *)"

  tags = {
    Name = "${local.name_prefix}-backup-test-weekly"
  }
}

resource "aws_cloudwatch_event_target" "backup_test_weekly" {
  rule      = aws_cloudwatch_event_rule.backup_test_weekly.name
  target_id = "backup-test-lambda"
  arn       = aws_lambda_function.backup_test.arn
}

resource "aws_lambda_permission" "backup_test_events" {
  statement_id  = "AllowExecutionFromCloudWatchEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.backup_test.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.backup_test_weekly.arn
}

# ---------------------------------------------------------------------------
# Alarm on Lambda failure (extra belt-and-suspenders)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "backup_test_failed" {
  alarm_name          = "${local.name_prefix}-backup-test-failed"
  alarm_description   = "Weekly backup verification Lambda reported errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.backup_test.function_name
  }

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]

  tags = {
    Name = "${local.name_prefix}-backup-test-failed-alarm"
  }
}
