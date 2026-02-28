# ======================================================================
# Serverless CSPM — Terraform Configuration
# Deploys: Remediation Lambda, API Lambda, DynamoDB, EventBridge,
#          API Gateway, and S3 static website for the dashboard.
# ======================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

# ---------------------------------------------------------------------------
# AWS Provider — switches between real AWS and LocalStack based on variable
# ---------------------------------------------------------------------------
provider "aws" {
  region = var.aws_region

  # LocalStack-specific overrides (ignored when use_localstack = false)
  access_key = var.use_localstack ? "test" : null
  secret_key = var.use_localstack ? "test" : null

  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  s3_use_path_style = var.use_localstack

  dynamic "endpoints" {
    for_each = var.use_localstack ? [1] : []
    content {
      apigateway     = "http://localhost:4566"
      apigatewayv2   = "http://localhost:4566"
      cloudwatch     = "http://localhost:4566"
      cloudwatchlogs = "http://localhost:4566"
      dynamodb       = "http://localhost:4566"
      ec2            = "http://localhost:4566"
      events         = "http://localhost:4566"
      iam            = "http://localhost:4566"
      lambda         = "http://localhost:4566"
      s3             = "http://localhost:4566"
      sts            = "http://localhost:4566"
    }
  }
}

# ===================== DATA SOURCES ===================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Package Lambda source code into zip archives
data "archive_file" "remediation_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/remediation"
  output_path = "${path.module}/builds/remediation_lambda.zip"
}

data "archive_file" "api_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/api"
  output_path = "${path.module}/builds/api_lambda.zip"
}

# ===================== DYNAMODB TABLE =================================

resource "aws_dynamodb_table" "remediation_events" {
  name         = var.dynamodb_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  tags = {
    Project = "serverless-cspm"
  }
}

# ===================== IAM — REMEDIATION LAMBDA =======================

resource "aws_iam_role" "remediation_lambda_role" {
  name = "${var.lambda_function_name}-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Project = "serverless-cspm"
  }
}

resource "aws_iam_role_policy" "remediation_lambda_policy" {
  name = "${var.lambda_function_name}-remediation-policy"
  role = aws_iam_role.remediation_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3PublicAccessBlock"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock"
        ]
        Resource = "arn:aws:s3:::*"
      },
      {
        Sid    = "DynamoDBWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
        ]
        Resource = aws_dynamodb_table.remediation_events.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.lambda_function_name}-remediation:*"
      }
    ]
  })
}

# ===================== IAM — API LAMBDA ===============================

resource "aws_iam_role" "api_lambda_role" {
  name = "${var.lambda_function_name}-api-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Project = "serverless-cspm"
  }
}

resource "aws_iam_role_policy" "api_lambda_policy" {
  name = "${var.lambda_function_name}-api-policy"
  role = aws_iam_role.api_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBRead"
        Effect = "Allow"
        Action = [
          "dynamodb:Scan",
          "dynamodb:Query",
          "dynamodb:GetItem"
        ]
        Resource = aws_dynamodb_table.remediation_events.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.lambda_function_name}-api:*"
      }
    ]
  })
}

# ===================== LAMBDA FUNCTIONS ===============================

resource "aws_lambda_function" "remediation" {
  function_name    = "${var.lambda_function_name}-remediation"
  description      = "CSPM: Detects and remediates S3 public access misconfigurations"
  role             = aws_iam_role.remediation_lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 128
  filename         = data.archive_file.remediation_lambda.output_path
  source_code_hash = data.archive_file.remediation_lambda.output_base64sha256

  environment {
    variables = {
      DISCORD_WEBHOOK_URL = var.discord_webhook_url
      DYNAMODB_TABLE_NAME = aws_dynamodb_table.remediation_events.name
    }
  }

  tags = {
    Project = "serverless-cspm"
  }
}

resource "aws_lambda_function" "api" {
  function_name    = "${var.lambda_function_name}-api"
  description      = "CSPM: Dashboard API serving remediation events from DynamoDB"
  role             = aws_iam_role.api_lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 15
  memory_size      = 128
  filename         = data.archive_file.api_lambda.output_path
  source_code_hash = data.archive_file.api_lambda.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE_NAME = aws_dynamodb_table.remediation_events.name
      ALLOWED_ORIGIN      = "*"
    }
  }

  tags = {
    Project = "serverless-cspm"
  }
}

# ===================== CLOUDWATCH LOG GROUPS ==========================

resource "aws_cloudwatch_log_group" "remediation_logs" {
  name              = "/aws/lambda/${var.lambda_function_name}-remediation"
  retention_in_days = 14

  tags = {
    Project = "serverless-cspm"
  }
}

resource "aws_cloudwatch_log_group" "api_logs" {
  name              = "/aws/lambda/${var.lambda_function_name}-api"
  retention_in_days = 14

  tags = {
    Project = "serverless-cspm"
  }
}

# ===================== EVENTBRIDGE RULE ===============================

resource "aws_cloudwatch_event_rule" "s3_public_access_change" {
  name        = "${var.lambda_function_name}-s3-config-change"
  description = "Triggers on S3 CreateBucket or PutBucketPublicAccessBlock via CloudTrail"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["CreateBucket", "PutBucketPublicAccessBlock"]
    }
  })

  tags = {
    Project = "serverless-cspm"
  }
}

resource "aws_cloudwatch_event_target" "invoke_remediation_lambda" {
  rule      = aws_cloudwatch_event_rule.s3_public_access_change.name
  target_id = "cspm-remediation-target"
  arn       = aws_lambda_function.remediation.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_public_access_change.arn
}

# ===================== API GATEWAY (HTTP API) =========================
# NOTE: Skipped on LocalStack (Community Edition lacks apigatewayv2 support).
# On LocalStack, invoke the API Lambda directly via `aws lambda invoke`.

resource "aws_apigatewayv2_api" "dashboard_api" {
  count         = var.use_localstack ? 0 : 1
  name          = "${var.lambda_function_name}-dashboard-api"
  protocol_type = "HTTP"
  description   = "CSPM Dashboard API"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "OPTIONS"]
    allow_headers = ["Content-Type"]
    max_age       = 300
  }

  tags = {
    Project = "serverless-cspm"
  }
}

resource "aws_apigatewayv2_stage" "default" {
  count       = var.use_localstack ? 0 : 1
  api_id      = aws_apigatewayv2_api.dashboard_api[0].id
  name        = "$default"
  auto_deploy = true

  tags = {
    Project = "serverless-cspm"
  }
}

resource "aws_apigatewayv2_integration" "api_lambda_integration" {
  count                  = var.use_localstack ? 0 : 1
  api_id                 = aws_apigatewayv2_api.dashboard_api[0].id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "get_events" {
  count     = var.use_localstack ? 0 : 1
  api_id    = aws_apigatewayv2_api.dashboard_api[0].id
  route_key = "GET /events"
  target    = "integrations/${aws_apigatewayv2_integration.api_lambda_integration[0].id}"
}

resource "aws_apigatewayv2_route" "get_stats" {
  count     = var.use_localstack ? 0 : 1
  api_id    = aws_apigatewayv2_api.dashboard_api[0].id
  route_key = "GET /stats"
  target    = "integrations/${aws_apigatewayv2_integration.api_lambda_integration[0].id}"
}

resource "aws_lambda_permission" "allow_apigw" {
  count         = var.use_localstack ? 0 : 1
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.dashboard_api[0].execution_arn}/*/*"
}

# ===================== S3 FRONTEND HOSTING ============================
# On LocalStack: the frontend is simply opened from disk (frontend/index.html).
# On real AWS:   the frontend is served from S3 static website hosting.

resource "aws_s3_bucket" "frontend" {
  count  = var.use_localstack ? 0 : 1
  bucket = var.frontend_bucket_name

  tags = {
    Project = "serverless-cspm"
  }
}

resource "aws_s3_bucket_website_configuration" "frontend" {
  count  = var.use_localstack ? 0 : 1
  bucket = aws_s3_bucket.frontend[0].id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "index.html"
  }
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  count  = var.use_localstack ? 0 : 1
  bucket = aws_s3_bucket.frontend[0].id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "frontend" {
  count  = var.use_localstack ? 0 : 1
  bucket = aws_s3_bucket.frontend[0].id

  depends_on = [aws_s3_bucket_public_access_block.frontend]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.frontend[0].arn}/*"
      }
    ]
  })
}

# Upload frontend files
resource "aws_s3_object" "frontend_html" {
  count        = var.use_localstack ? 0 : 1
  bucket       = aws_s3_bucket.frontend[0].id
  key          = "index.html"
  source       = "${path.module}/../frontend/index.html"
  content_type = "text/html"
  etag         = filemd5("${path.module}/../frontend/index.html")
}

resource "aws_s3_object" "frontend_css" {
  count        = var.use_localstack ? 0 : 1
  bucket       = aws_s3_bucket.frontend[0].id
  key          = "style.css"
  source       = "${path.module}/../frontend/style.css"
  content_type = "text/css"
  etag         = filemd5("${path.module}/../frontend/style.css")
}

resource "aws_s3_object" "frontend_js" {
  count        = var.use_localstack ? 0 : 1
  bucket       = aws_s3_bucket.frontend[0].id
  key          = "app.js"
  source       = "${path.module}/../frontend/app.js"
  content_type = "application/javascript"
  etag         = filemd5("${path.module}/../frontend/app.js")
}
