###############################################################################
# ShieldOps — Production Security Groups
###############################################################################

# ---------------------------------------------------------------------------
# ALB Security Group
# ---------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb-sg"
  description = "Security group for the production ALB"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-alb-sg"
  }
}

resource "aws_security_group_rule" "alb_ingress_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from anywhere"
}

resource "aws_security_group_rule" "alb_ingress_http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from anywhere (redirects to HTTPS)"
}

resource "aws_security_group_rule" "alb_egress_to_ecs_api" {
  type                     = "egress"
  from_port                = 8000
  to_port                  = 8000
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = aws_security_group.alb.id
  description              = "Traffic to ECS API tasks"
}

resource "aws_security_group_rule" "alb_egress_to_ecs_dashboard" {
  type                     = "egress"
  from_port                = 3000
  to_port                  = 3000
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = aws_security_group.alb.id
  description              = "Traffic to ECS dashboard tasks"
}

# ---------------------------------------------------------------------------
# ECS Tasks Security Group
# ---------------------------------------------------------------------------

resource "aws_security_group" "ecs" {
  name        = "${local.name_prefix}-ecs-sg"
  description = "Security group for production ECS Fargate tasks"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-ecs-sg"
  }
}

resource "aws_security_group_rule" "ecs_ingress_from_alb_api" {
  type                     = "ingress"
  from_port                = 8000
  to_port                  = 8000
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
  security_group_id        = aws_security_group.ecs.id
  description              = "API traffic from ALB"
}

resource "aws_security_group_rule" "ecs_ingress_from_alb_dashboard" {
  type                     = "ingress"
  from_port                = 3000
  to_port                  = 3000
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
  security_group_id        = aws_security_group.ecs.id
  description              = "Dashboard traffic from ALB"
}

resource "aws_security_group_rule" "ecs_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.ecs.id
  description       = "Allow all outbound traffic"
}

# ---------------------------------------------------------------------------
# RDS Security Group
# ---------------------------------------------------------------------------

resource "aws_security_group" "rds" {
  name        = "${local.name_prefix}-rds-sg"
  description = "Security group for production RDS PostgreSQL"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-rds-sg"
  }
}

resource "aws_security_group_rule" "rds_ingress_from_ecs" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = aws_security_group.rds.id
  description              = "PostgreSQL from ECS tasks only"
}

# ---------------------------------------------------------------------------
# ElastiCache Security Group
# ---------------------------------------------------------------------------

resource "aws_security_group" "elasticache" {
  name        = "${local.name_prefix}-elasticache-sg"
  description = "Security group for production ElastiCache Redis"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-elasticache-sg"
  }
}

resource "aws_security_group_rule" "elasticache_ingress_from_ecs" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = aws_security_group.elasticache.id
  description              = "Redis from ECS tasks only"
}

# ---------------------------------------------------------------------------
# MSK Kafka Security Group
# ---------------------------------------------------------------------------

resource "aws_security_group" "msk" {
  name        = "${local.name_prefix}-msk-sg"
  description = "Security group for production MSK Kafka"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-msk-sg"
  }
}

resource "aws_security_group_rule" "msk_ingress_from_ecs" {
  type                     = "ingress"
  from_port                = 9094
  to_port                  = 9098
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = aws_security_group.msk.id
  description              = "Kafka TLS + IAM from ECS tasks only"
}

resource "aws_security_group_rule" "msk_ingress_internal" {
  type              = "ingress"
  from_port         = 9094
  to_port           = 9098
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.msk.id
  description       = "Inter-broker communication"
}

resource "aws_security_group_rule" "msk_zookeeper_internal" {
  type              = "ingress"
  from_port         = 2181
  to_port           = 2181
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.msk.id
  description       = "ZooKeeper internal"
}
