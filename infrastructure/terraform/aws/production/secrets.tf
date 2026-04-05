###############################################################################
# ShieldOps — Production Secrets Manager
###############################################################################

# ---------------------------------------------------------------------------
# Application Secrets (existing — referenced by ARN)
# ---------------------------------------------------------------------------

data "aws_secretsmanager_secret" "app" {
  arn = var.secrets_arn
}

# ---------------------------------------------------------------------------
# RDS Password (managed by Terraform)
# ---------------------------------------------------------------------------

resource "random_password" "rds" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}:?"
}

resource "aws_secretsmanager_secret" "rds_password" {
  name        = "${var.project_name}/${var.environment}/rds-password"
  description = "RDS PostgreSQL password for ShieldOps production"

  tags = {
    Name = "${local.name_prefix}-rds-password"
  }
}

resource "aws_secretsmanager_secret_version" "rds_password" {
  secret_id     = aws_secretsmanager_secret.rds_password.id
  secret_string = random_password.rds.result
}
