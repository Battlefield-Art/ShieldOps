###############################################################################
# ShieldOps — Terraform Backend Configuration (Production)
###############################################################################

terraform {
  backend "s3" {
    bucket         = "shieldops-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "shieldops-terraform-locks"
    encrypt        = true
  }
}
