terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0, < 7.0.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# The ECS cluster already exists; we only reference it.
data "aws_ecs_cluster" "this" {
  cluster_name = var.cluster_name
}

locals {
  container_name = var.name
  container_port = 8000

  # NUM_THREADS follows the allocated vCPUs so torch never guesses the host's
  # core count from inside the container.
  num_threads = max(1, floor(var.cpu / 1024))

  # Valid Fargate CPU/memory pairs (MiB). Anything else fails at plan time.
  fargate_memory_by_cpu = {
    "256"   = [512, 1024, 2048]
    "512"   = [for m in range(1024, 4097, 1024) : m]
    "1024"  = [for m in range(2048, 8193, 1024) : m]
    "2048"  = [for m in range(4096, 16385, 1024) : m]
    "4096"  = [for m in range(8192, 30721, 1024) : m]
    "8192"  = [for m in range(16384, 61441, 4096) : m]
    "16384" = [for m in range(32768, 122881, 8192) : m]
  }

  base_environment = merge(
    {
      NUM_THREADS = tostring(local.num_threads)
      LOG_LEVEL   = var.log_level
    },
    var.extra_environment
  )
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
}

# ---------------------------------------------------------------------------
# Security groups: internet -> ALB:443 only; ALB -> task:8000 only.
# ---------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "Public HTTPS into the PII detector ALB"
  vpc_id      = var.vpc_id

  ingress {
    description      = "HTTPS from anywhere"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    description     = "To service tasks only"
    from_port       = local.container_port
    to_port         = local.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.task.id]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "task" {
  name_prefix = "${var.name}-task-"
  description = "PII detector Fargate tasks; no direct public ingress"
  vpc_id      = var.vpc_id

  egress {
    description = "Outbound for ECR pull, CloudWatch Logs, Secrets Manager"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "task_from_alb" {
  type                     = "ingress"
  description              = "App traffic from the ALB only"
  security_group_id        = aws_security_group.task.id
  from_port                = local.container_port
  to_port                  = local.container_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
}

# ---------------------------------------------------------------------------
# Load balancer
# ---------------------------------------------------------------------------

resource "aws_lb" "this" {
  name               = "${var.name}-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "this" {
  name        = "${var.name}-tg"
  port        = local.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  deregistration_delay = 30

  health_check {
    path                = "/health"
    matcher             = "200" # the app returns 503 until the model is loaded
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# ---------------------------------------------------------------------------
# Task definition + service
# ---------------------------------------------------------------------------

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64" # build images with --platform linux/amd64
  }

  container_definitions = jsonencode([
    {
      name      = local.container_name
      image     = "${var.ecr_repository_url}:${var.image_tag}"
      essential = true

      portMappings = [
        {
          containerPort = local.container_port
          protocol      = "tcp"
        }
      ]

      environment = [for k, v in local.base_environment : { name = k, value = v }]

      # The API key is injected from Secrets Manager at container start. It must
      # never appear as a plain 'environment' value or anywhere in this file.
      secrets = [
        {
          name      = "API_KEY"
          valueFrom = aws_secretsmanager_secret.api_key.arn
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "app"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = contains(lookup(local.fargate_memory_by_cpu, tostring(var.cpu), []), var.memory)
      error_message = "cpu=${var.cpu} with memory=${var.memory} MiB is not a valid Fargate combination."
    }
  }
}

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = data.aws_ecs_cluster.this.arn
  task_definition = aws_ecs_task_definition.this.arn
  launch_type     = "FARGATE"
  desired_count   = var.desired_count

  # Cold start = image pull + model load; tune after measuring (see variable).
  health_check_grace_period_seconds = var.health_check_grace_period_seconds

  # With desired_count >= 2 this gives zero-downtime rolling deploys.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = var.assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = local.container_name
    container_port   = local.container_port
  }

  # Application Auto Scaling owns the live count after creation.
  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [aws_lb_listener.https]
}
