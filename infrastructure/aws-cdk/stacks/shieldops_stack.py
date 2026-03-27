"""ShieldOps Production CDK Stack.

Provisions the complete AWS infrastructure for the ShieldOps AI Security
Control Plane:

  VPC -> ECS Fargate (API + Worker + OPA sidecars) -> ALB -> CloudFront
  RDS PostgreSQL | ElastiCache Redis | MSK Kafka
  S3 | ACM | Secrets Manager | CloudWatch | ECR | WAF | Route 53
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    Tags,
)
from aws_cdk import (
    aws_certificatemanager as acm,
)
from aws_cdk import (
    aws_cloudfront as cloudfront,
)
from aws_cdk import (
    aws_cloudfront_origins as origins,
)
from aws_cdk import (
    aws_cloudwatch as cloudwatch,
)
from aws_cdk import (
    aws_cloudwatch_actions as cw_actions,
)
from aws_cdk import (
    aws_ec2 as ec2,
)
from aws_cdk import (
    aws_ecr as ecr,
)
from aws_cdk import (
    aws_ecs as ecs,
)
from aws_cdk import (
    aws_elasticache as elasticache,
)
from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_logs as logs,
)
from aws_cdk import (
    aws_msk_alpha as msk,
)
from aws_cdk import (
    aws_rds as rds,
)
from aws_cdk import (
    aws_route53 as route53,
)
from aws_cdk import (
    aws_route53_targets as targets,
)
from aws_cdk import (
    aws_s3 as s3,
)
from aws_cdk import (
    aws_secretsmanager as secretsmanager,
)
from aws_cdk import (
    aws_sns as sns,
)
from aws_cdk import (
    aws_wafv2 as wafv2,
)
from constructs import Construct


class ShieldOpsStack(Stack):
    """Full production stack for ShieldOps."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        domain_name: str = "shieldops.io",
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.domain_name = domain_name

        # Apply global tags
        Tags.of(self).add("Project", "ShieldOps")
        Tags.of(self).add("Environment", "production")
        Tags.of(self).add("ManagedBy", "CDK")

        # Build every layer
        self._create_vpc()
        self._create_ecr()
        self._create_secrets()
        self._create_rds()
        self._create_redis()
        self._create_msk()
        self._create_ecs_cluster()
        self._create_alb()
        self._create_ecs_api_service()
        self._create_ecs_worker_service()
        self._create_s3_and_cloudfront()
        self._create_waf()
        self._create_cloudwatch()
        self._create_dns()
        self._outputs()

    # ------------------------------------------------------------------
    # 1. VPC — 3 AZs, public + private subnets, NAT gateways
    # ------------------------------------------------------------------
    def _create_vpc(self) -> None:
        self.vpc = ec2.Vpc(
            self,
            "Vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
            max_azs=3,
            nat_gateways=3,  # one per AZ for HA
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=22,
                ),
                ec2.SubnetConfiguration(
                    name="Isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                ),
            ],
            enable_dns_support=True,
            enable_dns_hostnames=True,
        )

        # VPC Flow Logs for security auditing
        self.vpc.add_flow_log(
            "FlowLog",
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(),
            traffic_type=ec2.FlowLogTrafficType.ALL,
        )

    # ------------------------------------------------------------------
    # 2. ECR — Container repositories
    # ------------------------------------------------------------------
    def _create_ecr(self) -> None:
        self.ecr_api = ecr.Repository(
            self,
            "ApiRepo",
            repository_name="shieldops/api",
            removal_policy=RemovalPolicy.RETAIN,
            image_scan_on_push=True,
            lifecycle_rules=[
                ecr.LifecycleRule(max_image_count=30, description="Keep last 30 images")
            ],
        )

        self.ecr_worker = ecr.Repository(
            self,
            "WorkerRepo",
            repository_name="shieldops/worker",
            removal_policy=RemovalPolicy.RETAIN,
            image_scan_on_push=True,
            lifecycle_rules=[
                ecr.LifecycleRule(max_image_count=30, description="Keep last 30 images")
            ],
        )

        self.ecr_opa = ecr.Repository(
            self,
            "OpaRepo",
            repository_name="shieldops/opa",
            removal_policy=RemovalPolicy.RETAIN,
            image_scan_on_push=True,
            lifecycle_rules=[
                ecr.LifecycleRule(max_image_count=10, description="Keep last 10 images")
            ],
        )

    # ------------------------------------------------------------------
    # 3. Secrets Manager — API keys, DB password
    # ------------------------------------------------------------------
    def _create_secrets(self) -> None:
        # Database master password (auto-generated)
        self.db_secret = secretsmanager.Secret(
            self,
            "DbSecret",
            secret_name="shieldops/db-credentials",  # noqa: S106,
            description="ShieldOps RDS PostgreSQL master credentials",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"username": "shieldops"}',  # noqa: S106,
                generate_string_key="password",
                exclude_punctuation=True,
                password_length=32,
            ),
        )

        # Application secrets (placeholder — populate after deploy)
        self.app_secrets = secretsmanager.Secret(
            self,
            "AppSecrets",
            secret_name="shieldops/app-secrets",  # noqa: S106,
            description="ShieldOps application secrets (API keys, tokens)",
            secret_string_value=cdk.SecretValue.unsafe_plain_text(
                '{"ANTHROPIC_API_KEY":"REPLACE_ME",'
                '"LANGSMITH_API_KEY":"REPLACE_ME",'
                '"STRIPE_SECRET_KEY":"REPLACE_ME",'
                '"SLACK_BOT_TOKEN":"REPLACE_ME",'
                '"PAGERDUTY_API_KEY":"REPLACE_ME"}'
            ),
        )

    # ------------------------------------------------------------------
    # 4. RDS PostgreSQL — Multi-AZ, r6g.xlarge, 100 GB, encrypted
    # ------------------------------------------------------------------
    def _create_rds(self) -> None:
        self.db_sg = ec2.SecurityGroup(
            self,
            "DbSg",
            vpc=self.vpc,
            description="ShieldOps RDS PostgreSQL",
            allow_all_outbound=False,
        )

        self.db = rds.DatabaseInstance(
            self,
            "Database",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_16_2,
            ),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.XLARGE),
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
            ),
            security_groups=[self.db_sg],
            credentials=rds.Credentials.from_secret(self.db_secret),
            database_name="shieldops",
            multi_az=True,
            allocated_storage=100,
            max_allocated_storage=500,
            storage_type=rds.StorageType.GP3,
            storage_encrypted=True,
            backup_retention=Duration.days(14),
            deletion_protection=True,
            removal_policy=RemovalPolicy.SNAPSHOT,
            monitoring_interval=Duration.seconds(60),
            enable_performance_insights=True,
            performance_insight_retention=rds.PerformanceInsightRetention.DEFAULT,
            cloudwatch_logs_exports=["postgresql"],
            auto_minor_version_upgrade=True,
            copy_tags_to_snapshot=True,
        )

    # ------------------------------------------------------------------
    # 5. ElastiCache Redis — Cluster mode, r6g.large
    # ------------------------------------------------------------------
    def _create_redis(self) -> None:
        self.redis_sg = ec2.SecurityGroup(
            self,
            "RedisSg",
            vpc=self.vpc,
            description="ShieldOps ElastiCache Redis",
            allow_all_outbound=False,
        )

        redis_subnet_group = elasticache.CfnSubnetGroup(
            self,
            "RedisSubnetGroup",
            description="ShieldOps Redis subnet group",
            subnet_ids=[
                s.subnet_id
                for s in self.vpc.select_subnets(
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
                ).subnets
            ],
        )

        self.redis = elasticache.CfnReplicationGroup(
            self,
            "Redis",
            replication_group_description="ShieldOps Redis cluster",
            engine="redis",
            engine_version="7.1",
            cache_node_type="cache.r6g.large",
            num_node_groups=3,  # cluster-mode shards
            replicas_per_node_group=1,  # 1 replica per shard
            automatic_failover_enabled=True,
            multi_az_enabled=True,
            at_rest_encryption_enabled=True,
            transit_encryption_enabled=True,
            cache_subnet_group_name=redis_subnet_group.ref,
            security_group_ids=[self.redis_sg.security_group_id],
            snapshot_retention_limit=7,
            snapshot_window="03:00-05:00",
            preferred_maintenance_window="sun:05:00-sun:07:00",
            auto_minor_version_upgrade=True,
            port=6379,
        )

    # ------------------------------------------------------------------
    # 6. MSK Kafka — 3 brokers, m5.large, 100 GB each
    # ------------------------------------------------------------------
    def _create_msk(self) -> None:
        self.kafka_sg = ec2.SecurityGroup(
            self,
            "KafkaSg",
            vpc=self.vpc,
            description="ShieldOps MSK Kafka",
            allow_all_outbound=False,
        )

        self.kafka = msk.Cluster(
            self,
            "Kafka",
            cluster_name="shieldops-kafka",
            kafka_version=msk.KafkaVersion.V3_6_0,
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
            ),
            security_groups=[self.kafka_sg],
            number_of_broker_nodes=3,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
            ebs_storage_info=msk.EbsStorageInfo(volume_size=100),
            encryption_in_transit=msk.EncryptionInTransitConfig(
                client_broker=msk.ClientBrokerEncryption.TLS,
                enable_in_cluster=True,
            ),
            monitoring=msk.MonitoringConfiguration(
                cluster_monitoring_level=msk.ClusterMonitoringLevel.PER_TOPIC_PER_PARTITION,
                enable_prometheus_jmx_exporter=True,
                enable_prometheus_node_exporter=True,
            ),
            removal_policy=RemovalPolicy.RETAIN,
        )

    # ------------------------------------------------------------------
    # 7. ECS Fargate Cluster
    # ------------------------------------------------------------------
    def _create_ecs_cluster(self) -> None:
        self.cluster = ecs.Cluster(
            self,
            "Cluster",
            vpc=self.vpc,
            cluster_name="shieldops",
            container_insights_v2=ecs.ContainerInsights.ENABLED,
        )

        # Shared task execution role
        self.execution_role = iam.Role(
            self,
            "TaskExecutionRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonECSTaskExecutionRolePolicy"
                ),
            ],
        )
        # Allow pulling secrets
        self.db_secret.grant_read(self.execution_role)
        self.app_secrets.grant_read(self.execution_role)

        # Shared task role (what the containers themselves can do)
        self.task_role = iam.Role(
            self,
            "TaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
        )
        self.db_secret.grant_read(self.task_role)
        self.app_secrets.grant_read(self.task_role)

    # ------------------------------------------------------------------
    # 8. Application Load Balancer — HTTPS, health checks
    # ------------------------------------------------------------------
    def _create_alb(self) -> None:
        self.alb = elbv2.ApplicationLoadBalancer(
            self,
            "Alb",
            vpc=self.vpc,
            internet_facing=True,
            load_balancer_name="shieldops-alb",
        )

        # ACM certificate for TLS
        self.certificate = acm.Certificate(
            self,
            "Certificate",
            domain_name=self.domain_name,
            subject_alternative_names=[f"*.{self.domain_name}"],
            validation=acm.CertificateValidation.from_dns(),
        )

        # HTTPS listener
        self.https_listener = self.alb.add_listener(
            "HttpsListener",
            port=443,
            protocol=elbv2.ApplicationProtocol.HTTPS,
            certificates=[self.certificate],
            default_action=elbv2.ListenerAction.fixed_response(
                status_code=404,
                content_type="application/json",
                message_body='{"error":"not_found"}',
            ),
        )

        # HTTP -> HTTPS redirect
        self.alb.add_listener(
            "HttpRedirect",
            port=80,
            default_action=elbv2.ListenerAction.redirect(
                protocol="HTTPS",
                port="443",
                permanent=True,
            ),
        )

    # ------------------------------------------------------------------
    # 9. ECS API Service — 3 replicas, 2 vCPU, 4 GB, OPA sidecar
    # ------------------------------------------------------------------
    def _create_ecs_api_service(self) -> None:
        # Log groups
        api_log_group = logs.LogGroup(
            self,
            "ApiLogs",
            log_group_name="/ecs/shieldops/api",
            retention=logs.RetentionDays.THIRTY_DAYS,
            removal_policy=RemovalPolicy.DESTROY,
        )
        opa_api_log_group = logs.LogGroup(
            self,
            "OpaApiLogs",
            log_group_name="/ecs/shieldops/opa-api",
            retention=logs.RetentionDays.FOURTEEN_DAYS,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Task definition
        api_task = ecs.FargateTaskDefinition(
            self,
            "ApiTask",
            cpu=2048,  # 2 vCPU
            memory_limit_mib=4096,  # 4 GB
            execution_role=self.execution_role,
            task_role=self.task_role,
        )

        # --- API container ---
        api_container = api_task.add_container(
            "api",
            image=ecs.ContainerImage.from_ecr_repository(self.ecr_api, tag="latest"),
            essential=True,
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="api",
                log_group=api_log_group,
            ),
            environment={
                "ENV": "production",
                "OPA_ENDPOINT": "http://localhost:8181",
                "REDIS_URL": f"redis://{self.redis.attr_configuration_end_point_address}:"
                f"{self.redis.attr_configuration_end_point_port}",
                "KAFKA_BROKERS": self.kafka.bootstrap_brokers_tls,
            },
            secrets={
                "DATABASE_URL": ecs.Secret.from_secrets_manager(self.db_secret),
                "ANTHROPIC_API_KEY": ecs.Secret.from_secrets_manager(
                    self.app_secrets, field="ANTHROPIC_API_KEY"
                ),
                "LANGSMITH_API_KEY": ecs.Secret.from_secrets_manager(
                    self.app_secrets, field="LANGSMITH_API_KEY"
                ),
                "STRIPE_SECRET_KEY": ecs.Secret.from_secrets_manager(
                    self.app_secrets, field="STRIPE_SECRET_KEY"
                ),
                "SLACK_BOT_TOKEN": ecs.Secret.from_secrets_manager(
                    self.app_secrets, field="SLACK_BOT_TOKEN"
                ),
            },
            health_check=ecs.HealthCheck(
                command=["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"],
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5),
                retries=3,
                start_period=Duration.seconds(60),
            ),
        )
        api_container.add_port_mappings(
            ecs.PortMapping(container_port=8000, protocol=ecs.Protocol.TCP)
        )

        # --- OPA sidecar ---
        opa_container = api_task.add_container(
            "opa",
            image=ecs.ContainerImage.from_ecr_repository(self.ecr_opa, tag="latest"),
            essential=False,
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="opa",
                log_group=opa_api_log_group,
            ),
            environment={"OPA_LOG_LEVEL": "info"},
            health_check=ecs.HealthCheck(
                command=["CMD-SHELL", "curl -f http://localhost:8181/health || exit 1"],
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5),
                retries=3,
            ),
        )
        opa_container.add_port_mappings(
            ecs.PortMapping(container_port=8181, protocol=ecs.Protocol.TCP)
        )

        # Security group for the API service
        api_sg = ec2.SecurityGroup(
            self,
            "ApiSg",
            vpc=self.vpc,
            description="ShieldOps API ECS tasks",
        )

        # Service
        self.api_service = ecs.FargateService(
            self,
            "ApiService",
            cluster=self.cluster,
            task_definition=api_task,
            desired_count=3,
            security_groups=[api_sg],
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
            ),
            circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True),
            enable_execute_command=True,  # for debugging via ECS Exec
            min_healthy_percent=100,
            max_healthy_percent=200,
        )

        # Register with ALB target group
        api_target_group = elbv2.ApplicationTargetGroup(
            self,
            "ApiTargetGroup",
            vpc=self.vpc,
            port=8000,
            protocol=elbv2.ApplicationProtocol.HTTP,
            targets=[self.api_service],
            health_check=elbv2.HealthCheck(
                path="/health",
                port="8000",
                healthy_http_codes="200",
                interval=Duration.seconds(30),
                timeout=Duration.seconds(10),
                healthy_threshold_count=2,
                unhealthy_threshold_count=3,
            ),
            deregistration_delay=Duration.seconds(30),
        )

        # Path-based routing: /api/* -> API service
        self.https_listener.add_action(
            "ApiRoute",
            priority=10,
            conditions=[elbv2.ListenerCondition.path_patterns(["/api/*", "/health", "/ready"])],
            action=elbv2.ListenerAction.forward([api_target_group]),
        )

        # Allow ALB -> API tasks
        self.api_service.connections.allow_from(self.alb, ec2.Port.tcp(8000))

        # Allow API -> RDS
        self.db_sg.add_ingress_rule(api_sg, ec2.Port.tcp(5432), "API -> RDS")
        # Allow API -> Redis
        self.redis_sg.add_ingress_rule(api_sg, ec2.Port.tcp(6379), "API -> Redis")
        # Allow API -> Kafka
        self.kafka_sg.add_ingress_rule(api_sg, ec2.Port.tcp(9094), "API -> Kafka TLS")

    # ------------------------------------------------------------------
    # 10. ECS Worker Service — 2-20 replicas, 4 vCPU, 8 GB, OPA sidecar
    # ------------------------------------------------------------------
    def _create_ecs_worker_service(self) -> None:
        worker_log_group = logs.LogGroup(
            self,
            "WorkerLogs",
            log_group_name="/ecs/shieldops/worker",
            retention=logs.RetentionDays.THIRTY_DAYS,
            removal_policy=RemovalPolicy.DESTROY,
        )
        opa_worker_log_group = logs.LogGroup(
            self,
            "OpaWorkerLogs",
            log_group_name="/ecs/shieldops/opa-worker",
            retention=logs.RetentionDays.FOURTEEN_DAYS,
            removal_policy=RemovalPolicy.DESTROY,
        )

        worker_task = ecs.FargateTaskDefinition(
            self,
            "WorkerTask",
            cpu=4096,  # 4 vCPU
            memory_limit_mib=8192,  # 8 GB
            execution_role=self.execution_role,
            task_role=self.task_role,
        )

        # --- Worker container ---
        worker_task.add_container(
            "worker",
            image=ecs.ContainerImage.from_ecr_repository(self.ecr_worker, tag="latest"),
            essential=True,
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="worker",
                log_group=worker_log_group,
            ),
            environment={
                "ENV": "production",
                "OPA_ENDPOINT": "http://localhost:8181",
                "REDIS_URL": f"redis://{self.redis.attr_configuration_end_point_address}:"
                f"{self.redis.attr_configuration_end_point_port}",
                "KAFKA_BROKERS": self.kafka.bootstrap_brokers_tls,
            },
            secrets={
                "DATABASE_URL": ecs.Secret.from_secrets_manager(self.db_secret),
                "ANTHROPIC_API_KEY": ecs.Secret.from_secrets_manager(
                    self.app_secrets, field="ANTHROPIC_API_KEY"
                ),
                "LANGSMITH_API_KEY": ecs.Secret.from_secrets_manager(
                    self.app_secrets, field="LANGSMITH_API_KEY"
                ),
                "PAGERDUTY_API_KEY": ecs.Secret.from_secrets_manager(
                    self.app_secrets, field="PAGERDUTY_API_KEY"
                ),
            },
            health_check=ecs.HealthCheck(
                command=["CMD-SHELL", "python -c 'import shieldops; print(\"ok\")' || exit 1"],
                interval=Duration.seconds(30),
                timeout=Duration.seconds(10),
                retries=3,
                start_period=Duration.seconds(120),
            ),
            command=[
                "python",
                "-m",
                "shieldops.worker",
                "--concurrency",
                "8",
                "--queues",
                "agents,remediation,investigation,security",
            ],
        )

        # --- OPA sidecar ---
        opa_worker = worker_task.add_container(
            "opa",
            image=ecs.ContainerImage.from_ecr_repository(self.ecr_opa, tag="latest"),
            essential=False,
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="opa",
                log_group=opa_worker_log_group,
            ),
            environment={"OPA_LOG_LEVEL": "info"},
        )
        opa_worker.add_port_mappings(
            ecs.PortMapping(container_port=8181, protocol=ecs.Protocol.TCP)
        )

        # Security group
        worker_sg = ec2.SecurityGroup(
            self,
            "WorkerSg",
            vpc=self.vpc,
            description="ShieldOps Worker ECS tasks",
        )

        # Service
        self.worker_service = ecs.FargateService(
            self,
            "WorkerService",
            cluster=self.cluster,
            task_definition=worker_task,
            desired_count=2,
            security_groups=[worker_sg],
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
            ),
            circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True),
            enable_execute_command=True,
            min_healthy_percent=100,
            max_healthy_percent=200,
        )

        # Auto-scaling: 2 -> 20 based on CPU
        scaling = self.worker_service.auto_scale_task_count(
            min_capacity=2,
            max_capacity=20,
        )
        scaling.scale_on_cpu_utilization(
            "CpuScaling",
            target_utilization_percent=60,
            scale_in_cooldown=Duration.seconds(300),
            scale_out_cooldown=Duration.seconds(60),
        )
        scaling.scale_on_memory_utilization(
            "MemoryScaling",
            target_utilization_percent=70,
            scale_in_cooldown=Duration.seconds(300),
            scale_out_cooldown=Duration.seconds(60),
        )

        # Allow Worker -> RDS
        self.db_sg.add_ingress_rule(worker_sg, ec2.Port.tcp(5432), "Worker -> RDS")
        # Allow Worker -> Redis
        self.redis_sg.add_ingress_rule(worker_sg, ec2.Port.tcp(6379), "Worker -> Redis")
        # Allow Worker -> Kafka
        self.kafka_sg.add_ingress_rule(worker_sg, ec2.Port.tcp(9094), "Worker -> Kafka TLS")

    # ------------------------------------------------------------------
    # 11. S3 + CloudFront — Dashboard static assets + CDN
    # ------------------------------------------------------------------
    def _create_s3_and_cloudfront(self) -> None:
        # Dashboard static assets bucket
        self.dashboard_bucket = s3.Bucket(
            self,
            "DashboardBucket",
            bucket_name=f"shieldops-dashboard-{self.account}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
            enforce_ssl=True,
        )

        # Backup bucket
        self.backup_bucket = s3.Bucket(
            self,
            "BackupBucket",
            bucket_name=f"shieldops-backups-{self.account}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
            enforce_ssl=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(30),
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90),
                        ),
                    ],
                    expiration=Duration.days(365),
                )
            ],
        )

        # CloudFront ACM certificate (must be in us-east-1 for CloudFront)
        self.cf_certificate = acm.Certificate(
            self,
            "CfCertificate",
            domain_name=f"app.{self.domain_name}",
            validation=acm.CertificateValidation.from_dns(),
        )

        # CloudFront distribution
        self.distribution = cloudfront.Distribution(
            self,
            "Distribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(
                    self.dashboard_bucket,
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                compress=True,
            ),
            additional_behaviors={
                "/api/*": cloudfront.BehaviorOptions(
                    origin=origins.LoadBalancerV2Origin(
                        self.alb,
                        protocol_policy=cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
                    ),
                    viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER,
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                ),
            },
            domain_names=[f"app.{self.domain_name}"],
            certificate=self.cf_certificate,
            default_root_object="index.html",
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=Duration.seconds(0),
                ),
            ],
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
        )

    # ------------------------------------------------------------------
    # 12. WAF — Rate limiting + IP blocking
    # ------------------------------------------------------------------
    def _create_waf(self) -> None:
        self.waf = wafv2.CfnWebACL(
            self,
            "Waf",
            name="shieldops-waf",
            scope="REGIONAL",  # for ALB; use CLOUDFRONT for CF
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="shieldops-waf",
                sampled_requests_enabled=True,
            ),
            rules=[
                # Rate limiting: 2000 requests per 5 minutes per IP
                wafv2.CfnWebACL.RuleProperty(
                    name="RateLimitRule",
                    priority=1,
                    action=wafv2.CfnWebACL.RuleActionProperty(block={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            limit=2000,
                            aggregate_key_type="IP",
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="RateLimitRule",
                        sampled_requests_enabled=True,
                    ),
                ),
                # AWS Managed Rules — Common Rule Set
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesCommonRuleSet",
                    priority=2,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesCommonRuleSet",
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWSManagedRulesCommonRuleSet",
                        sampled_requests_enabled=True,
                    ),
                ),
                # AWS Managed Rules — Known Bad Inputs
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesKnownBadInputsRuleSet",
                    priority=3,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesKnownBadInputsRuleSet",
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWSManagedRulesKnownBadInputsRuleSet",
                        sampled_requests_enabled=True,
                    ),
                ),
                # AWS Managed Rules — SQL Injection
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesSQLiRuleSet",
                    priority=4,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesSQLiRuleSet",
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWSManagedRulesSQLiRuleSet",
                        sampled_requests_enabled=True,
                    ),
                ),
                # IP-based blocking (empty IP set — populate as needed)
                wafv2.CfnWebACL.RuleProperty(
                    name="IPBlockList",
                    priority=0,
                    action=wafv2.CfnWebACL.RuleActionProperty(block={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        ip_set_reference_statement=wafv2.CfnWebACL.IPSetReferenceStatementProperty(
                            arn=self._create_ip_block_set().attr_arn,
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="IPBlockList",
                        sampled_requests_enabled=True,
                    ),
                ),
            ],
        )

        # Associate WAF with ALB
        wafv2.CfnWebACLAssociation(
            self,
            "WafAlbAssociation",
            resource_arn=self.alb.load_balancer_arn,
            web_acl_arn=self.waf.attr_arn,
        )

    def _create_ip_block_set(self) -> wafv2.CfnIPSet:
        return wafv2.CfnIPSet(
            self,
            "BlockedIPs",
            name="shieldops-blocked-ips",
            scope="REGIONAL",
            ip_address_version="IPV4",
            addresses=[],  # populate via console or API as needed
        )

    # ------------------------------------------------------------------
    # 13. CloudWatch — Log groups, dashboards, alarms
    # ------------------------------------------------------------------
    def _create_cloudwatch(self) -> None:
        # SNS topic for alarms
        self.alarm_topic = sns.Topic(
            self,
            "AlarmTopic",
            topic_name="shieldops-alarms",
            display_name="ShieldOps Production Alarms",
        )

        # ---- RDS Alarms ----
        cloudwatch.Alarm(
            self,
            "DbCpuAlarm",
            metric=self.db.metric_cpu_utilization(),
            threshold=80,
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_name="shieldops-rds-cpu-high",
            alarm_description="RDS CPU > 80% for 15 minutes",
            treat_missing_data=cloudwatch.TreatMissingData.BREACHING,
        ).add_alarm_action(cw_actions.SnsAction(self.alarm_topic))

        cloudwatch.Alarm(
            self,
            "DbFreeStorageAlarm",
            metric=self.db.metric_free_storage_space(),
            threshold=10 * 1024 * 1024 * 1024,  # 10 GB
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
            alarm_name="shieldops-rds-storage-low",
            alarm_description="RDS free storage < 10 GB",
        ).add_alarm_action(cw_actions.SnsAction(self.alarm_topic))

        cloudwatch.Alarm(
            self,
            "DbConnectionsAlarm",
            metric=self.db.metric_database_connections(),
            threshold=200,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_name="shieldops-rds-connections-high",
            alarm_description="RDS connections > 200",
        ).add_alarm_action(cw_actions.SnsAction(self.alarm_topic))

        # ---- ECS Alarms ----
        cloudwatch.Alarm(
            self,
            "ApiCpuAlarm",
            metric=self.api_service.metric_cpu_utilization(),
            threshold=75,
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_name="shieldops-api-cpu-high",
            alarm_description="API service CPU > 75%",
        ).add_alarm_action(cw_actions.SnsAction(self.alarm_topic))

        cloudwatch.Alarm(
            self,
            "WorkerCpuAlarm",
            metric=self.worker_service.metric_cpu_utilization(),
            threshold=75,
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_name="shieldops-worker-cpu-high",
            alarm_description="Worker service CPU > 75%",
        ).add_alarm_action(cw_actions.SnsAction(self.alarm_topic))

        # ---- ALB Alarms ----
        cloudwatch.Alarm(
            self,
            "Alb5xxAlarm",
            metric=self.alb.metric_http_code_elb(code=elbv2.HttpCodeElb.ELB_5XX_COUNT),
            threshold=50,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_name="shieldops-alb-5xx-high",
            alarm_description="ALB 5xx errors > 50 in 10 minutes",
        ).add_alarm_action(cw_actions.SnsAction(self.alarm_topic))

        cloudwatch.Alarm(
            self,
            "AlbLatencyAlarm",
            metric=self.alb.metric_target_response_time(),
            threshold=2,  # seconds
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_name="shieldops-alb-latency-high",
            alarm_description="ALB target response time > 2s",
        ).add_alarm_action(cw_actions.SnsAction(self.alarm_topic))

        # ---- CloudWatch Dashboard ----
        dashboard = cloudwatch.Dashboard(
            self,
            "Dashboard",
            dashboard_name="ShieldOps-Production",
        )

        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="API Service CPU & Memory",
                left=[
                    self.api_service.metric_cpu_utilization(),
                    self.api_service.metric_memory_utilization(),
                ],
                width=12,
            ),
            cloudwatch.GraphWidget(
                title="Worker Service CPU & Memory",
                left=[
                    self.worker_service.metric_cpu_utilization(),
                    self.worker_service.metric_memory_utilization(),
                ],
                width=12,
            ),
        )
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="RDS Performance",
                left=[
                    self.db.metric_cpu_utilization(),
                    self.db.metric_database_connections(),
                ],
                right=[
                    self.db.metric_free_storage_space(),
                ],
                width=12,
            ),
            cloudwatch.GraphWidget(
                title="ALB Requests & Latency",
                left=[self.alb.metric_request_count()],
                right=[self.alb.metric_target_response_time()],
                width=12,
            ),
        )

    # ------------------------------------------------------------------
    # 14. Route 53 — DNS records (optional, requires hosted zone)
    # ------------------------------------------------------------------
    def _create_dns(self) -> None:
        # Look up existing hosted zone (will fail gracefully if zone
        # doesn't exist yet — create it manually first)
        try:
            self.hosted_zone = route53.HostedZone.from_lookup(
                self,
                "HostedZone",
                domain_name=self.domain_name,
            )

            # api.shieldops.io -> ALB
            route53.ARecord(
                self,
                "ApiDns",
                zone=self.hosted_zone,
                record_name=f"api.{self.domain_name}",
                target=route53.RecordTarget.from_alias(targets.LoadBalancerTarget(self.alb)),
            )

            # app.shieldops.io -> CloudFront
            route53.ARecord(
                self,
                "AppDns",
                zone=self.hosted_zone,
                record_name=f"app.{self.domain_name}",
                target=route53.RecordTarget.from_alias(targets.CloudFrontTarget(self.distribution)),
            )
        except Exception:  # noqa: S110
            # Hosted zone not found — skip DNS records.
            # Create the zone manually and re-deploy.
            pass

    # ------------------------------------------------------------------
    # Stack outputs
    # ------------------------------------------------------------------
    def _outputs(self) -> None:
        cdk.CfnOutput(self, "AlbDns", value=self.alb.load_balancer_dns_name)
        cdk.CfnOutput(self, "CloudFrontDomain", value=self.distribution.distribution_domain_name)
        cdk.CfnOutput(self, "EcrApiUri", value=self.ecr_api.repository_uri)
        cdk.CfnOutput(self, "EcrWorkerUri", value=self.ecr_worker.repository_uri)
        cdk.CfnOutput(self, "EcrOpaUri", value=self.ecr_opa.repository_uri)
        cdk.CfnOutput(self, "DbEndpoint", value=self.db.db_instance_endpoint_address)
        cdk.CfnOutput(
            self,
            "RedisEndpoint",
            value=self.redis.attr_configuration_end_point_address,
        )
        cdk.CfnOutput(self, "KafkaBrokers", value=self.kafka.bootstrap_brokers_tls)
        cdk.CfnOutput(self, "DashboardBucket", value=self.dashboard_bucket.bucket_name)
        cdk.CfnOutput(self, "BackupBucket", value=self.backup_bucket.bucket_name)
        cdk.CfnOutput(self, "AlarmTopicArn", value=self.alarm_topic.topic_arn)
