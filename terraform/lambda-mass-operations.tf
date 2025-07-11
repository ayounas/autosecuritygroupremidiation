# Lambda function for mass operations detection
resource "aws_lambda_function" "mass_operations_detector" {
  filename         = "${path.module}/../dist/mass_operations_detector.zip"
  function_name    = "${local.resource_prefix}-mass-operations-detector"
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "mass_operations_handler.lambda_handler"
  runtime         = "python3.11"
  timeout         = 300
  memory_size     = 512
  
  # Use the same Lambda package for now, different handler
  source_code_hash = data.archive_file.lambda_deployment_package.output_base64sha256
  
  environment {
    variables = {
      S3_BUCKET_NAME           = aws_s3_bucket.compliance_bucket.bucket
      CONFIG_KEY               = var.config_key
      LOG_LEVEL               = var.log_level
      SNS_TOPIC_ARN           = aws_sns_topic.security_alerts.arn
      DYNAMODB_TABLE          = aws_dynamodb_table.mass_operations_tracking.name
      MAX_OPERATIONS_PER_MINUTE = var.max_operations_per_minute
      ALERT_THRESHOLD         = var.mass_operations_alert_threshold
      BLOCK_SUSPICIOUS_USERS  = var.block_suspicious_users
    }
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-mass-operations-detector"
    Purpose = "MassOperationsDetection"
  })
  
  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic_execution,
    aws_cloudwatch_log_group.mass_operations_detector_logs,
  ]
}

# CloudWatch Log Group for mass operations detector
resource "aws_cloudwatch_log_group" "mass_operations_detector_logs" {
  name              = "/aws/lambda/${local.resource_prefix}-mass-operations-detector"
  retention_in_days = var.log_retention_days
  kms_key_id       = aws_kms_key.compliance_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-mass-operations-logs"
    Purpose = "MassOperationsLogging"
  })
}

# DynamoDB table for tracking mass operations
resource "aws_dynamodb_table" "mass_operations_tracking" {
  name           = "${local.resource_prefix}-mass-operations-tracking"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "user_identity"
  range_key      = "time_window"
  
  attribute {
    name = "user_identity"
    type = "S"
  }
  
  attribute {
    name = "time_window"
    type = "S"
  }
  
  attribute {
    name = "ttl"
    type = "N"
  }
  
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
  
  global_secondary_index {
    name     = "TimeWindowIndex"
    hash_key = "time_window"
    
    projection_type = "ALL"
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.compliance_key.arn
  }
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-mass-operations-tracking"
    Purpose = "MassOperationsTracking"
  })
}

# CloudWatch alarm for mass operations
resource "aws_cloudwatch_metric_alarm" "mass_operations_alarm" {
  alarm_name          = "${local.resource_prefix}-mass-operations-detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "MassOperationsDetected"
  namespace           = "SecurityCompliance/MassOperations"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.mass_operations_alert_threshold
  alarm_description   = "Mass security group operations detected"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-mass-operations-alarm"
    Purpose = "MassOperationsAlerting"
  })
}

# IAM policy for mass operations detector
resource "aws_iam_role_policy" "mass_operations_detector_policy" {
  name = "${local.resource_prefix}-mass-operations-detector-policy"
  role = aws_iam_role.lambda_execution_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.mass_operations_tracking.arn,
          "${aws_dynamodb_table.mass_operations_tracking.arn}/index/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:ListUserPolicies",
          "iam:GetRole",
          "iam:ListRolePolicies"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "SecurityCompliance/MassOperations"
          }
        }
      }
    ]
  })
}
