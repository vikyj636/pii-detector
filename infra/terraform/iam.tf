# ---------------------------------------------------------------------------
# Execution role: NOT created by this stack. It takes an EXISTING ECS task
# execution role as input (var.execution_role_arn / var.execution_role_name)
# instead of provisioning a new one.
#
# Why: in accounts locked down to PowerUserAccess-style permissions,
# iam:CreateRole — and even iam:PassRole on a role that already exists — are
# denied by design. Reusing a role most accounts already have (commonly named
# ecsTaskExecutionRole, auto-offered by the ECS console's task definition
# wizard) sidesteps CreateRole entirely. PassRole still has to be granted to
# whoever runs `terraform apply`; there's no way around that one.
#
# No task role is created or referenced at all: the app makes zero AWS API
# calls by design, and task_role_arn is optional for Fargate — omitting it
# entirely is the correct least-privilege posture here, not a placeholder.
# ---------------------------------------------------------------------------

# Most pre-existing execution roles already cover ECR pull + CloudWatch Logs
# write via the AWS-managed AmazonECSTaskExecutionRolePolicy. The one thing
# they typically lack is read access to THIS service's own secret, so that is
# the only permission this stack grants — an inline policy on the existing
# role, scoped to exactly one resource. (Attaching this requires
# iam:PutRolePolicy on that role, which — like PassRole above — is usually
# not covered by PowerUserAccess-style permissions; see the README.)
resource "aws_iam_role_policy" "execution_secrets_access" {
  name = "${var.name}-secrets-access"
  role = var.execution_role_name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "secretsmanager:GetSecretValue"
      Resource = aws_secretsmanager_secret.api_key.arn
    }]
  })
}
