# Holds the X-API-Key value the service requires. The secret VALUE is
# intentionally NOT managed by Terraform: putting it in .tf/.tfvars files would
# land it in code review and in state. Seed it once after `terraform apply`:
#
#   aws secretsmanager put-secret-value \
#     --secret-id "$(terraform output -raw api_key_secret_arn)" \
#     --secret-string "$(openssl rand -hex 32)" \
#     --region <region>
#
# Until the value exists, tasks fail to start with a ResourceInitializationError;
# ECS keeps retrying, so the service converges on its own once the value is set.
resource "aws_secretsmanager_secret" "api_key" {
  name        = var.api_key_secret_name
  description = "API key required in the X-API-Key header of POST /detect (pii-detector)."
}
