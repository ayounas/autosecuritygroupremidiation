# SNS notifications for compliance alerts

# SNS topic for compliance alerts
resource "aws_sns_topic" "compliance_alerts" {
  name              = local.sns_topic_name
  display_name      = "Security Group Compliance Alerts"
  kms_master_key_id = aws_kms_key.compliance_key.arn
  
  tags = merge(local.common_tags, {
    Name    = local.sns_topic_name
    Purpose = "ComplianceNotifications"
  })
}

# SNS topic policy
resource "aws_sns_topic_policy" "compliance_alerts_policy" {
  arn = aws_sns_topic.compliance_alerts.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchAlarmsToPublish"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.compliance_alerts.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowLambdaToPublish"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_execution_role.arn
        }
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.compliance_alerts.arn
      }
    ]
  })
}

# SNS email subscription (conditional)
resource "aws_sns_topic_subscription" "email_notification" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.compliance_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
  
  depends_on = [aws_sns_topic.compliance_alerts]
}

# SNS subscription for SQS dead letter queue monitoring
resource "aws_sns_topic_subscription" "dlq_notification" {
  topic_arn = aws_sns_topic.compliance_alerts.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.compliance_dlq.arn
  
  depends_on = [aws_sns_topic.compliance_alerts]
}

# Additional SNS topic for critical violations
resource "aws_sns_topic" "critical_violations" {
  name              = "${local.resource_prefix}-critical-violations"
  display_name      = "Critical Security Group Violations"
  kms_master_key_id = aws_kms_key.compliance_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-critical-violations"
    Purpose = "CriticalViolationNotifications"
  })
}

# Critical violations topic policy
resource "aws_sns_topic_policy" "critical_violations_policy" {
  arn = aws_sns_topic.critical_violations.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaToPublish"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_execution_role.arn
        }
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.critical_violations.arn
      }
    ]
  })
}

# Critical violations email subscription
resource "aws_sns_topic_subscription" "critical_email_notification" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.critical_violations.arn
  protocol  = "email"
  endpoint  = var.notification_email
  
  depends_on = [aws_sns_topic.critical_violations]
}
