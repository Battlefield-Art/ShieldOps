###############################################################################
# ShieldOps — Log Retention & Archival
#
# Flow:
#   CloudWatch Logs (90d hot)
#     → Subscription filter → Kinesis Firehose
#     → S3 archive bucket (Standard 0-90d → Glacier 1yr → Delete 7yr)
###############################################################################

# ---------------------------------------------------------------------------
# S3 Bucket: Log Archive
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "log_archive" {
  bucket = "shieldops-log-archive-${local.account_id}"

  tags = {
    Name      = "${local.name_prefix}-log-archive"
    Retention = "7-years"
  }
}

resource "aws_s3_bucket_versioning" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "log_archive" {
  bucket                  = aws_s3_bucket.log_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    id     = "archive-lifecycle"
    status = "Enabled"

    filter {
      prefix = ""
    }

    # 0-90d: Standard (hot)
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    # 90-365d: IA
    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    # Delete after 7 years (regulatory baseline)
    expiration {
      days = 2555
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ---------------------------------------------------------------------------
# Firehose Delivery Stream: CloudWatch Logs → S3
# ---------------------------------------------------------------------------

resource "aws_iam_role" "firehose_log_archive" {
  name = "${local.name_prefix}-firehose-log-archive"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "${local.name_prefix}-firehose-log-archive"
  }
}

resource "aws_iam_role_policy" "firehose_log_archive" {
  name = "${local.name_prefix}-firehose-log-archive"
  role = aws_iam_role.firehose_log_archive.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject",
        ]
        Resource = [
          aws_s3_bucket.log_archive.arn,
          "${aws_s3_bucket.log_archive.arn}/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:PutLogEvents"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "firehose_log_archive" {
  name              = "/aws/kinesisfirehose/${local.name_prefix}-log-archive"
  retention_in_days = 30

  tags = {
    Name = "${local.name_prefix}-firehose-log-archive-logs"
  }
}

resource "aws_kinesis_firehose_delivery_stream" "log_archive" {
  name        = "${local.name_prefix}-log-archive"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose_log_archive.arn
    bucket_arn          = aws_s3_bucket.log_archive.arn
    buffering_size      = 64
    buffering_interval  = 300
    compression_format  = "GZIP"
    prefix              = "logs/!{partitionKeyFromQuery:log_group}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"

    dynamic_partitioning_configuration {
      enabled = true
    }

    processing_configuration {
      enabled = true
      processors {
        type = "MetadataExtraction"
        parameters {
          parameter_name  = "MetadataExtractionQuery"
          parameter_value = "{log_group: .logGroup}"
        }
        parameters {
          parameter_name  = "JsonParsingEngine"
          parameter_value = "JQ-1.6"
        }
      }
    }

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose_log_archive.name
      log_stream_name = "S3Delivery"
    }
  }

  tags = {
    Name = "${local.name_prefix}-log-archive"
  }
}

# ---------------------------------------------------------------------------
# CloudWatch Logs → Firehose Subscription Filters
# ---------------------------------------------------------------------------

resource "aws_iam_role" "cwl_to_firehose" {
  name = "${local.name_prefix}-cwl-to-firehose"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "${local.name_prefix}-cwl-to-firehose"
  }
}

resource "aws_iam_role_policy" "cwl_to_firehose" {
  name = "${local.name_prefix}-cwl-to-firehose"
  role = aws_iam_role.cwl_to_firehose.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch",
      ]
      Resource = aws_kinesis_firehose_delivery_stream.log_archive.arn
    }]
  })
}

resource "aws_cloudwatch_log_subscription_filter" "api_to_archive" {
  name            = "${local.name_prefix}-api-to-archive"
  log_group_name  = aws_cloudwatch_log_group.api.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.log_archive.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn
}

resource "aws_cloudwatch_log_subscription_filter" "worker_to_archive" {
  name            = "${local.name_prefix}-worker-to-archive"
  log_group_name  = aws_cloudwatch_log_group.worker.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.log_archive.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn
}
