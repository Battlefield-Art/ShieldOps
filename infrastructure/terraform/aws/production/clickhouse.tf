###############################################################################
# ShieldOps — ClickHouse HA Production Cluster (3-node, multi-AZ)
#
# Deploys a 3-node ClickHouse cluster across 3 availability zones for high
# availability. Each node runs on an m5.xlarge EC2 instance with a dedicated
# 1TB gp3 EBS data volume. Nodes are placed in the existing production VPC
# private subnets and registered in a private Route53 hosted zone so the
# ShieldOps application can resolve them by stable hostnames:
#
#   clickhouse-1.shieldops.internal
#   clickhouse-2.shieldops.internal
#   clickhouse-3.shieldops.internal
#
# Replication and distributed queries are configured via config.xml which
# references a ZooKeeper ensemble (zk-1/2/3.shieldops.internal) managed out
# of band (see infrastructure/kubernetes/ for the ZK deployment).
###############################################################################

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "clickhouse_instance_type" {
  description = "EC2 instance type for ClickHouse nodes"
  type        = string
  default     = "m5.xlarge"
}

variable "clickhouse_data_volume_size_gb" {
  description = "Size of the ClickHouse data EBS volume in GB"
  type        = number
  default     = 1024
}

variable "clickhouse_ami_id" {
  description = "AMI ID for ClickHouse nodes (Ubuntu 22.04 LTS recommended). Empty = auto-lookup"
  type        = string
  default     = ""
}

variable "clickhouse_internal_zone_name" {
  description = "Internal Route53 private hosted zone name"
  type        = string
  default     = "shieldops.internal"
}

variable "clickhouse_ssh_key_name" {
  description = "EC2 key pair name for SSH access (optional)"
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Data Sources — reuse existing production network resources
# ---------------------------------------------------------------------------

data "aws_ami" "ubuntu_2204" {
  count       = var.clickhouse_ami_id == "" ? 1 : 0
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  clickhouse_ami_id = var.clickhouse_ami_id != "" ? var.clickhouse_ami_id : data.aws_ami.ubuntu_2204[0].id
  clickhouse_nodes  = [1, 2, 3]
}

# ---------------------------------------------------------------------------
# Private Route53 Zone for internal service discovery
# ---------------------------------------------------------------------------

resource "aws_route53_zone" "internal" {
  name = var.clickhouse_internal_zone_name

  vpc {
    vpc_id = aws_vpc.main.id
  }

  tags = {
    Name        = "${local.name_prefix}-internal-zone"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

# ---------------------------------------------------------------------------
# Security Group — ClickHouse cluster
# ---------------------------------------------------------------------------

resource "aws_security_group" "clickhouse" {
  name        = "${local.name_prefix}-clickhouse-sg"
  description = "Security group for ShieldOps ClickHouse HA cluster"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name        = "${local.name_prefix}-clickhouse-sg"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

resource "aws_security_group_rule" "clickhouse_native_from_ecs" {
  type                     = "ingress"
  from_port                = 9000
  to_port                  = 9000
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = aws_security_group.clickhouse.id
  description              = "ClickHouse native protocol from ECS tasks"
}

resource "aws_security_group_rule" "clickhouse_http_from_ecs" {
  type                     = "ingress"
  from_port                = 8123
  to_port                  = 8123
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = aws_security_group.clickhouse.id
  description              = "ClickHouse HTTP interface from ECS tasks"
}

resource "aws_security_group_rule" "clickhouse_native_intra" {
  type              = "ingress"
  from_port         = 9000
  to_port           = 9000
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.clickhouse.id
  description       = "ClickHouse native protocol intra-cluster"
}

resource "aws_security_group_rule" "clickhouse_http_intra" {
  type              = "ingress"
  from_port         = 8123
  to_port           = 8123
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.clickhouse.id
  description       = "ClickHouse HTTP intra-cluster"
}

resource "aws_security_group_rule" "clickhouse_replication_intra" {
  type              = "ingress"
  from_port         = 9009
  to_port           = 9009
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.clickhouse.id
  description       = "ClickHouse inter-server replication"
}

resource "aws_security_group_rule" "clickhouse_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.clickhouse.id
  description       = "Allow all egress (package installation, S3 backups, etc.)"
}

# ---------------------------------------------------------------------------
# IAM role for ClickHouse EC2 instances (S3 backups + SSM)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "clickhouse" {
  name = "${local.name_prefix}-clickhouse-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name        = "${local.name_prefix}-clickhouse-role"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

resource "aws_iam_role_policy_attachment" "clickhouse_ssm" {
  role       = aws_iam_role.clickhouse.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "clickhouse_s3_backup" {
  name = "${local.name_prefix}-clickhouse-s3-backup"
  role = aws_iam_role.clickhouse.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:GetBucketLocation",
      ]
      Resource = [
        aws_s3_bucket.clickhouse_backups.arn,
        "${aws_s3_bucket.clickhouse_backups.arn}/*",
      ]
    }]
  })
}

resource "aws_iam_role_policy" "clickhouse_secrets" {
  name = "${local.name_prefix}-clickhouse-secrets"
  role = aws_iam_role.clickhouse.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.clickhouse_password.arn]
    }]
  })
}

resource "aws_iam_instance_profile" "clickhouse" {
  name = "${local.name_prefix}-clickhouse-profile"
  role = aws_iam_role.clickhouse.name
}

# ---------------------------------------------------------------------------
# Secrets Manager — ClickHouse user password
# ---------------------------------------------------------------------------

resource "random_password" "clickhouse_user" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret" "clickhouse_password" {
  name                    = "${local.name_prefix}/clickhouse/shieldops-user"
  description             = "Password for the ClickHouse 'shieldops' application user"
  recovery_window_in_days = 7

  tags = {
    Name        = "${local.name_prefix}-clickhouse-password"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

resource "aws_secretsmanager_secret_version" "clickhouse_password" {
  secret_id     = aws_secretsmanager_secret.clickhouse_password.id
  secret_string = random_password.clickhouse_user.result
}

# ---------------------------------------------------------------------------
# User data — installs clickhouse-server and bootstraps config
# ---------------------------------------------------------------------------

locals {
  clickhouse_user_data_tpl = <<-EOT
    #!/bin/bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    NODE_INDEX="$${node_index}"
    CLUSTER_ZONE="${var.clickhouse_internal_zone_name}"
    PASSWORD_SECRET_ARN="${aws_secretsmanager_secret.clickhouse_password.arn}"
    AWS_REGION="${var.aws_region}"

    apt-get update -y
    apt-get install -y apt-transport-https ca-certificates dirmngr gnupg curl jq awscli xfsprogs

    # Format and mount EBS data volume.
    DEVICE="/dev/nvme1n1"
    MOUNT="/var/lib/clickhouse"
    mkdir -p "$MOUNT"
    if ! blkid "$DEVICE"; then
      mkfs.xfs "$DEVICE"
    fi
    echo "$DEVICE $MOUNT xfs defaults,noatime 0 2" >> /etc/fstab
    mount -a

    # Install ClickHouse.
    GNUPGHOME=$(mktemp -d) gpg --no-default-keyring \
        --keyring /usr/share/keyrings/clickhouse-keyring.gpg \
        --keyserver hkp://keyserver.ubuntu.com:80 \
        --recv-keys 8919F6BD2B48D754
    echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" \
        > /etc/apt/sources.list.d/clickhouse.list
    apt-get update -y
    apt-get install -y clickhouse-server clickhouse-client

    chown -R clickhouse:clickhouse /var/lib/clickhouse

    # Fetch password from Secrets Manager and hash it.
    CH_PASSWORD=$(aws secretsmanager get-secret-value \
        --region "$AWS_REGION" \
        --secret-id "$PASSWORD_SECRET_ARN" \
        --query SecretString --output text)
    CH_PASSWORD_SHA256=$(printf '%%s' "$CH_PASSWORD" | sha256sum | awk '{print $1}')

    # Write macros specific to this node. {shard}/{replica} substitutions used by
    # ReplicatedMergeTree come from here.
    cat > /etc/clickhouse-server/config.d/macros.xml <<MACROS
    <clickhouse>
      <macros>
        <shard>0$${NODE_INDEX}</shard>
        <replica>clickhouse-$${NODE_INDEX}</replica>
        <cluster>shieldops_cluster</cluster>
      </macros>
    </clickhouse>
    MACROS

    # Listen on all interfaces.
    cat > /etc/clickhouse-server/config.d/listen.xml <<LISTEN
    <clickhouse>
      <listen_host>0.0.0.0</listen_host>
    </clickhouse>
    LISTEN

    systemctl enable clickhouse-server
    systemctl restart clickhouse-server
  EOT
}

# ---------------------------------------------------------------------------
# ENIs — stable private IPs for each ClickHouse node
# ---------------------------------------------------------------------------

resource "aws_network_interface" "clickhouse" {
  for_each = toset([for i in local.clickhouse_nodes : tostring(i)])

  subnet_id       = aws_subnet.private[tonumber(each.key) - 1].id
  security_groups = [aws_security_group.clickhouse.id]
  description     = "ClickHouse node ${each.key} primary ENI"

  tags = {
    Name        = "${local.name_prefix}-clickhouse-${each.key}-eni"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

# ---------------------------------------------------------------------------
# EBS Volumes — 1 TB gp3 per node
# ---------------------------------------------------------------------------

resource "aws_ebs_volume" "clickhouse_data" {
  for_each = toset([for i in local.clickhouse_nodes : tostring(i)])

  availability_zone = local.azs[tonumber(each.key) - 1]
  size              = var.clickhouse_data_volume_size_gb
  type              = "gp3"
  iops              = 6000
  throughput        = 500
  encrypted         = true

  tags = {
    Name        = "${local.name_prefix}-clickhouse-${each.key}-data"
    Service     = "clickhouse"
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

resource "aws_volume_attachment" "clickhouse_data" {
  for_each = toset([for i in local.clickhouse_nodes : tostring(i)])

  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.clickhouse_data[each.key].id
  instance_id = aws_instance.clickhouse[each.key].id
}

# ---------------------------------------------------------------------------
# EC2 Instances — 3 ClickHouse nodes across 3 AZs
# ---------------------------------------------------------------------------

resource "aws_instance" "clickhouse" {
  for_each = toset([for i in local.clickhouse_nodes : tostring(i)])

  ami                  = local.clickhouse_ami_id
  instance_type        = var.clickhouse_instance_type
  iam_instance_profile = aws_iam_instance_profile.clickhouse.name
  key_name             = var.clickhouse_ssh_key_name != "" ? var.clickhouse_ssh_key_name : null

  network_interface {
    network_interface_id = aws_network_interface.clickhouse[each.key].id
    device_index         = 0
  }

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = replace(local.clickhouse_user_data_tpl, "$${node_index}", each.key)

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
  }

  tags = {
    Name        = "${local.name_prefix}-clickhouse-${each.key}"
    Service     = "clickhouse"
    NodeIndex   = each.key
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

# ---------------------------------------------------------------------------
# Route53 internal A records
# ---------------------------------------------------------------------------

resource "aws_route53_record" "clickhouse" {
  for_each = toset([for i in local.clickhouse_nodes : tostring(i)])

  zone_id = aws_route53_zone.internal.zone_id
  name    = "clickhouse-${each.key}.${var.clickhouse_internal_zone_name}"
  type    = "A"
  ttl     = 60
  records = [aws_network_interface.clickhouse[each.key].private_ip]
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "clickhouse_cluster_endpoints" {
  description = "Internal hostnames of the ClickHouse cluster nodes"
  value = [
    for i in local.clickhouse_nodes :
    "clickhouse-${i}.${var.clickhouse_internal_zone_name}"
  ]
}

output "clickhouse_cluster_sg_id" {
  description = "Security group ID guarding the ClickHouse cluster"
  value       = aws_security_group.clickhouse.id
}

output "clickhouse_password_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the shieldops CH user password"
  value       = aws_secretsmanager_secret.clickhouse_password.arn
}

output "clickhouse_internal_zone_id" {
  description = "Route53 internal hosted zone ID used by ClickHouse discovery"
  value       = aws_route53_zone.internal.zone_id
}
