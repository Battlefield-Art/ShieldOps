###############################################################################
# ShieldOps — PagerDuty Integration
#
# Wires the alarms SNS topic to a PagerDuty CloudWatch integration endpoint
# and promotes critical alarms to page on-call.
###############################################################################

# ---------------------------------------------------------------------------
# SNS → PagerDuty subscription
# ---------------------------------------------------------------------------

resource "aws_sns_topic_subscription" "pagerduty" {
  count                  = var.pagerduty_integration_url != "" ? 1 : 0
  topic_arn              = aws_sns_topic.alarms.arn
  protocol               = "https"
  endpoint               = var.pagerduty_integration_url
  endpoint_auto_confirms = true

  # PagerDuty may return transient 5xx; retry aggressively.
  delivery_policy = jsonencode({
    healthyRetryPolicy = {
      minDelayTarget     = 20
      maxDelayTarget     = 20
      numRetries         = 5
      numMaxDelayRetries = 0
      numMinDelayRetries = 0
      numNoDelayRetries  = 0
      backoffFunction    = "linear"
    }
  })
}

# ---------------------------------------------------------------------------
# Dedicated critical-paging SNS topic
#
# Some alarms are noisy (recoverable) and should not page. Critical alarms
# are wired here; the main alarms topic remains the "everything" channel.
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "pagerduty_critical" {
  name = "${local.name_prefix}-pagerduty-critical"

  tags = {
    Name = "${local.name_prefix}-pagerduty-critical"
  }
}

resource "aws_sns_topic_subscription" "pagerduty_critical" {
  count                  = var.pagerduty_integration_url != "" ? 1 : 0
  topic_arn              = aws_sns_topic.pagerduty_critical.arn
  protocol               = "https"
  endpoint               = var.pagerduty_integration_url
  endpoint_auto_confirms = true
}

# ---------------------------------------------------------------------------
# Promote critical alarms to also notify PagerDuty
#
# We add PagerDuty as an additional alarm action via aws_cloudwatch_metric_alarm
# attribute merging is not possible, so we create dedicated "critical" alarms
# that directly target the PagerDuty topic. These mirror the existing alarms
# in monitoring.tf at stricter thresholds to avoid double-firing.
# ---------------------------------------------------------------------------

# 5xx error rate > 1% sustained (critical — pages)
resource "aws_cloudwatch_metric_alarm" "critical_alb_5xx" {
  alarm_name          = "${local.name_prefix}-critical-5xx-error-rate"
  alarm_description   = "CRITICAL: ALB 5xx error rate exceeds 1% for 10 minutes — paging on-call"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 10
  threshold           = 1
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "error_rate"
    expression  = "(errors / requests) * 100"
    label       = "5xx Error Rate (%)"
    return_data = true
  }

  metric_query {
    id = "errors"
    metric {
      metric_name = "HTTPCode_Target_5XX_Count"
      namespace   = "AWS/ApplicationELB"
      period      = 60
      stat        = "Sum"
      dimensions = {
        TargetGroup  = aws_lb_target_group.api.arn_suffix
        LoadBalancer = aws_lb.main.arn_suffix
      }
    }
  }

  metric_query {
    id = "requests"
    metric {
      metric_name = "RequestCount"
      namespace   = "AWS/ApplicationELB"
      period      = 60
      stat        = "Sum"
      dimensions = {
        TargetGroup  = aws_lb_target_group.api.arn_suffix
        LoadBalancer = aws_lb.main.arn_suffix
      }
    }
  }

  alarm_actions = [aws_sns_topic.pagerduty_critical.arn]
  ok_actions    = [aws_sns_topic.pagerduty_critical.arn]

  tags = {
    Name     = "${local.name_prefix}-critical-5xx-error-rate-alarm"
    Severity = "critical"
  }
}

# RDS connections > 80% of max — critical
resource "aws_cloudwatch_metric_alarm" "critical_rds_connections" {
  alarm_name          = "${local.name_prefix}-critical-rds-connections"
  alarm_description   = "CRITICAL: RDS connections exceed 80% of max for 5 minutes — paging on-call"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 60
  statistic           = "Average"
  threshold           = 160
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }

  alarm_actions = [aws_sns_topic.pagerduty_critical.arn]
  ok_actions    = [aws_sns_topic.pagerduty_critical.arn]

  tags = {
    Name     = "${local.name_prefix}-critical-rds-connections-alarm"
    Severity = "critical"
  }
}

# Unhealthy hosts — any unhealthy host for > 5 min is critical
resource "aws_cloudwatch_metric_alarm" "critical_unhealthy_hosts" {
  alarm_name          = "${local.name_prefix}-critical-unhealthy-hosts"
  alarm_description   = "CRITICAL: ALB has unhealthy targets for 5 minutes — paging on-call"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    TargetGroup  = aws_lb_target_group.api.arn_suffix
    LoadBalancer = aws_lb.main.arn_suffix
  }

  alarm_actions = [aws_sns_topic.pagerduty_critical.arn]
  ok_actions    = [aws_sns_topic.pagerduty_critical.arn]

  tags = {
    Name     = "${local.name_prefix}-critical-unhealthy-hosts-alarm"
    Severity = "critical"
  }
}

# RDS free storage critical
resource "aws_cloudwatch_metric_alarm" "critical_rds_low_storage" {
  alarm_name          = "${local.name_prefix}-critical-rds-low-storage"
  alarm_description   = "CRITICAL: RDS free storage below 5GB — paging on-call"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 5368709120 # 5 GB
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }

  alarm_actions = [aws_sns_topic.pagerduty_critical.arn]
  ok_actions    = [aws_sns_topic.pagerduty_critical.arn]

  tags = {
    Name     = "${local.name_prefix}-critical-rds-low-storage-alarm"
    Severity = "critical"
  }
}

# Backup verification failure — critical
resource "aws_cloudwatch_metric_alarm" "critical_backup_test_failed" {
  alarm_name          = "${local.name_prefix}-critical-backup-test-failed"
  alarm_description   = "CRITICAL: Weekly backup verification failed — paging on-call"
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

  alarm_actions = [aws_sns_topic.pagerduty_critical.arn]
  ok_actions    = [aws_sns_topic.pagerduty_critical.arn]

  tags = {
    Name     = "${local.name_prefix}-critical-backup-test-failed-alarm"
    Severity = "critical"
  }
}
