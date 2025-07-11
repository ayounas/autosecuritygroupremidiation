# Lambda function for security group compliance scanning

# Create Lambda deployment package
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/../dist/compliance-scanner.zip"
  excludes    = ["__pycache__", "*.pyc", ".pytest_cache", "tests"]
}

# Lambda function
resource "aws_lambda_function" "compliance_scanner" {
  function_name    = local.lambda_function_name
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "lambda_handler.handler"
  runtime         = "python3.11"
  timeout         = var.lambda_timeout
  memory_size     = var.lambda_memory_size
  
  environment {
    variables = {
      ENVIRONMENT                    = var.environment
      DRY_RUN_MODE                  = var.dry_run_mode
      ENABLE_AUTOMATIC_REMEDIATION  = var.enable_automatic_remediation
      S3_BUCKET_NAME               = aws_s3_bucket.compliance_config.id
      SNS_TOPIC_ARN               = aws_sns_topic.compliance_alerts.arn
      KMS_KEY_ID                  = aws_kms_key.compliance_key.arn
      TARGET_ACCOUNTS             = jsonencode(var.target_accounts)
      CROSS_ACCOUNT_ROLE_NAME     = length(var.target_accounts) > 0 ? aws_iam_role.cross_account_role[0].name : ""
      EXTERNAL_ID                 = "${local.resource_prefix}-external-id"
      LOG_LEVEL                   = var.environment == "prod" ? "INFO" : "DEBUG"
    }
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.compliance_dlq.arn
  }
  
  vpc_config {
    subnet_ids         = []
    security_group_ids = []
  }
  
  tags = merge(local.common_tags, {
    Name    = local.lambda_function_name
    Purpose = "ComplianceScanner"
  })
  
  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic_execution,
    aws_iam_role_policy.compliance_scanner_policy,
    aws_cloudwatch_log_group.lambda_logs
  ]
}

# Lambda function invoke permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.compliance_schedule.arn
}

# SQS Dead Letter Queue for failed Lambda invocations
resource "aws_sqs_queue" "compliance_dlq" {
  name                      = "${local.resource_prefix}-compliance-dlq"
  message_retention_seconds = 1209600 # 14 days
  
  kms_master_key_id = aws_kms_key.compliance_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-compliance-dlq"
    Purpose = "DeadLetterQueue"
  })
}

# SQS Dead Letter Queue policy
resource "aws_sqs_queue_policy" "compliance_dlq_policy" {
  queue_url = aws_sqs_queue.compliance_dlq.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaAccess"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.compliance_dlq.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_lambda_function.compliance_scanner.arn
          }
        }
      }
    ]
  })
}
