#!/usr/bin/env python3
"""ShieldOps AWS CDK Application Entry Point.

Deploys the full ShieldOps AI Security Control Plane to AWS,
including ECS Fargate, RDS, ElastiCache, MSK, ALB, CloudFront,
WAF, and all supporting infrastructure.
"""

import os

import aws_cdk as cdk
from stacks.shieldops_stack import ShieldOpsStack

app = cdk.App()

# ---------------------------------------------------------------------------
# Environment configuration — override via CDK context or env vars
# ---------------------------------------------------------------------------
account = app.node.try_get_context("account") or os.environ.get("CDK_DEFAULT_ACCOUNT", "ACCOUNT_ID")
region = app.node.try_get_context("region") or os.environ.get("CDK_DEFAULT_REGION", "us-east-1")
domain_name = app.node.try_get_context("domain") or "shieldops.io"

env = cdk.Environment(account=account, region=region)

# ---------------------------------------------------------------------------
# Production stack
# ---------------------------------------------------------------------------
ShieldOpsStack(
    app,
    "ShieldOps-Production",
    env=env,
    domain_name=domain_name,
    description="ShieldOps AI Security Control Plane — production deployment",
)

app.synth()
