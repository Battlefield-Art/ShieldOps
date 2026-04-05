###############################################################################
# ShieldOps — Production Infrastructure (AWS)
# AI Security Control Plane — Production Deployment
###############################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.35"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "ShieldOps"
      Environment = var.environment
      ManagedBy   = "terraform"
      CostCenter  = var.cost_center
      Service     = "shieldops"
    }
  }
}

# ---------------------------------------------------------------------------
# Data Sources
# ---------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = "${var.project_name}-${var.environment}"
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.id
  azs         = slice(data.aws_availability_zones.available.names, 0, 3)

  common_tags = {
    Project     = "ShieldOps"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
    Service     = "shieldops"
  }
}
