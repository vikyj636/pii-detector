variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "eu-west-1"
}

variable "name" {
  description = "Base name for all resources created by this stack."
  type        = string
  default     = "pii-detector"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}$", var.name))
    error_message = "name must be lowercase alphanumeric/dashes, max 20 chars (ALB name limits)."
  }
}

variable "cluster_name" {
  description = "Name of the EXISTING ECS cluster to deploy into. This stack never creates a cluster."
  type        = string
}

variable "ecr_repository_url" {
  description = "Full ECR repository URL, e.g. 123456789012.dkr.ecr.eu-west-1.amazonaws.com/pii-detector."
  type        = string
}

variable "ecr_repository_arn" {
  description = "ARN of the same ECR repository; scopes the execution role's pull permissions."
  type        = string
}

variable "image_tag" {
  description = "Image tag to deploy. Prefer immutable tags (git SHA) over 'latest'."
  type        = string
}

variable "cpu" {
  description = "Fargate task CPU units (1024 = 1 vCPU). Must form a valid Fargate pair with var.memory; checked at plan time."
  type        = number
  default     = 1024
  validation {
    condition     = contains([256, 512, 1024, 2048, 4096, 8192, 16384], var.cpu)
    error_message = "cpu must be one of 256, 512, 1024, 2048, 4096, 8192, 16384."
  }
}

variable "memory" {
  description = "Fargate task memory in MiB. Must form a valid Fargate pair with var.cpu; checked at plan time."
  type        = number
  default     = 4096
}

variable "desired_count" {
  description = "Steady-state task count. Keep >= 2 for zero-downtime rolling deploys. Also used as autoscaling min_capacity."
  type        = number
  default     = 2
  validation {
    condition     = var.desired_count >= 1
    error_message = "desired_count must be at least 1."
  }
}

variable "max_capacity" {
  description = "Upper bound for CPU target-tracking auto scaling."
  type        = number
  default     = 6
}

variable "health_check_grace_period_seconds" {
  description = <<-EOT
    How long ECS ignores failing ALB health checks after a task starts. Must
    cover model load on cold start. Start at 60, then measure the real boot
    time (the app logs 'NER model ready' with load_seconds; compare task
    startedAt vs target healthy time) and adjust.
  EOT
  type        = number
  default     = 60
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for the HTTPS listener."
  type        = string
}

variable "vpc_id" {
  description = "VPC to deploy into."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnets for the internet-facing ALB (>= 2 AZs)."
  type        = list(string)
}

variable "private_subnet_ids" {
  description = <<-EOT
    Subnets for the Fargate tasks. Use private subnets with NAT, or VPC
    endpoints for ECR/CloudWatch Logs/Secrets Manager, when available.

    If the account only has a default VPC (all-public subnets, no NAT), pass
    the SAME subnet ids as public_subnet_ids here and set assign_public_ip =
    true — the task security group (ALB-only ingress) is what actually
    controls exposure, not whether the subnet has a public route. This is a
    real, currently-running configuration, not a hypothetical fallback.
  EOT
  type        = list(string)
}

variable "execution_role_arn" {
  description = <<-EOT
    ARN of an EXISTING ECS task execution role (image pull, log write). This
    stack does not create one — see iam.tf for why. Most accounts already
    have a role named ecsTaskExecutionRole, auto-offered by the ECS console's
    task definition wizard the first time anyone uses it; check for that
    before creating anything new.
  EOT
  type        = string
}

variable "execution_role_name" {
  description = "Name (not ARN) of the same role as execution_role_arn — kept as a separate variable rather than parsed out of the ARN, since roles created under a custom /path/ make that parsing unreliable."
  type        = string
}

variable "assign_public_ip" {
  description = "Give tasks public IPs. Only set true if the task subnets are public and have no NAT/VPC endpoints for image pull."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "CloudWatch log retention for the service log group."
  type        = number
  default     = 30
  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.log_retention_days
    )
    error_message = "log_retention_days must be a retention value CloudWatch Logs supports."
  }
}

variable "api_key_secret_name" {
  description = "Secrets Manager secret name that will hold the service API key."
  type        = string
  default     = "pii-detector/api-key"
}

variable "log_level" {
  description = "Application log level."
  type        = string
  default     = "INFO"
}

variable "extra_environment" {
  description = "Additional NON-SECRET environment variables for the container, e.g. { INCLUDE_CRYPTO_WALLET_IN_DEFAULT_LABELS = \"true\" }. Secrets must go through Secrets Manager, never here."
  type        = map(string)
  default     = {}
}
