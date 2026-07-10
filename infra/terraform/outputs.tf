output "alb_dns_name" {
  description = "Public DNS name of the ALB. Point a DNS record matching the ACM certificate at this."
  value       = aws_lb.this.dns_name
}

output "api_key_secret_arn" {
  description = "Secrets Manager secret that must hold the API key. Seed it after the first apply (see secrets.tf)."
  value       = aws_secretsmanager_secret.api_key.arn
}

output "seed_api_key_command" {
  description = "One-liner that generates and stores a random API key."
  value       = "aws secretsmanager put-secret-value --secret-id ${aws_secretsmanager_secret.api_key.arn} --secret-string \"$(openssl rand -hex 32)\" --region ${var.aws_region}"
}

output "ecs_service_name" {
  description = "Name of the ECS service."
  value       = aws_ecs_service.this.name
}

output "log_group_name" {
  description = "CloudWatch log group for the service (metadata-only logs)."
  value       = aws_cloudwatch_log_group.this.name
}
