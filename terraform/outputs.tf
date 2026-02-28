# ======================================================================
# Serverless CSPM — Outputs
# ======================================================================

output "remediation_lambda_arn" {
  description = "ARN of the remediation Lambda function"
  value       = aws_lambda_function.remediation.arn
}

output "api_lambda_arn" {
  description = "ARN of the dashboard API Lambda function"
  value       = aws_lambda_function.api.arn
}

output "remediation_iam_role_arn" {
  description = "ARN of the remediation Lambda IAM role"
  value       = aws_iam_role.remediation_lambda_role.arn
}

output "api_iam_role_arn" {
  description = "ARN of the API Lambda IAM role"
  value       = aws_iam_role.api_lambda_role.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule for S3 config changes"
  value       = aws_cloudwatch_event_rule.s3_public_access_change.arn
}

output "dynamodb_table_name" {
  description = "Name of the DynamoDB table storing remediation events"
  value       = aws_dynamodb_table.remediation_events.name
}

output "api_gateway_url" {
  description = "URL of the API Gateway endpoint for the dashboard"
  value       = try(aws_apigatewayv2_api.dashboard_api[0].api_endpoint, "N/A (LocalStack — invoke API Lambda directly)")
}

output "dashboard_url" {
  description = "URL of the CSPM security dashboard"
  value       = try("http://${aws_s3_bucket_website_configuration.frontend[0].website_endpoint}", "N/A (LocalStack — open frontend/index.html locally)")
}
