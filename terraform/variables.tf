# ======================================================================
# Serverless CSPM — Input Variables
# ======================================================================

variable "use_localstack" {
  description = "Set to true to deploy against LocalStack (local Docker) instead of real AWS"
  type        = bool
  default     = false
}

variable "aws_region" {
  description = "AWS region to deploy all resources in"
  type        = string
  default     = "us-east-1"
}

variable "discord_webhook_url" {
  description = "Discord webhook URL for sending remediation notifications"
  type        = string
  sensitive   = true
}

variable "lambda_function_name" {
  description = "Base name for Lambda functions (suffixed with -remediation and -api)"
  type        = string
  default     = "cspm-s3-remediation"
}

variable "dynamodb_table_name" {
  description = "Name of the DynamoDB table for storing remediation events"
  type        = string
  default     = "cspm-remediation-events"
}

variable "frontend_bucket_name" {
  description = "Globally unique S3 bucket name for hosting the dashboard frontend"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.frontend_bucket_name))
    error_message = "Bucket name must be 3-63 characters, lowercase letters, numbers, hyphens, and periods only."
  }
}
