# CloudWatch resources for logging and monitoring

# CloudWatch Log Group for Lambda function
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  kms_key_id       = aws_kms_key.compliance_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-lambda-logs"
    Purpose = "LambdaLogging"
  })
}

# CloudWatch Log Group for compliance audit logs
resource "aws_cloudwatch_log_group" "compliance_audit_logs" {
  name              = "/aws/compliance/${local.resource_prefix}/audit"
  retention_in_days = 365 # Keep audit logs for 1 year
  kms_key_id       = aws_kms_key.compliance_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-audit-logs"
    Purpose = "ComplianceAudit"
  })
}

# CloudWatch Metric Filter for compliance violations
resource "aws_cloudwatch_log_metric_filter" "compliance_violations" {
  name           = "${local.resource_prefix}-compliance-violations"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  pattern        = "{ $.event_type = \"COMPLIANCE_VIOLATION\" }"
  
  metric_transformation {
    name      = "ComplianceViolations"
    namespace = "SecurityGroup/Compliance"
    value     = "1"
    
    default_value = "0"
  }
}

# CloudWatch Metric Filter for remediation actions
resource "aws_cloudwatch_log_metric_filter" "remediation_actions" {
  name           = "${local.resource_prefix}-remediation-actions"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  pattern        = "{ $.event_type = \"REMEDIATION_APPLIED\" }"
  
  metric_transformation {
    name      = "RemediationActions"
    namespace = "SecurityGroup/Compliance"
    value     = "1"
    
    default_value = "0"
  }
}

# CloudWatch Metric Filter for errors
resource "aws_cloudwatch_log_metric_filter" "lambda_errors" {
  name           = "${local.resource_prefix}-lambda-errors"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  pattern        = "{ $.level = \"ERROR\" }"
  
  metric_transformation {
    name      = "LambdaErrors"
    namespace = "SecurityGroup/Compliance"
    value     = "1"
    
    default_value = "0"
  }
}

# CloudWatch Alarm for compliance violations
resource "aws_cloudwatch_metric_alarm" "high_compliance_violations" {
  alarm_name          = "${local.resource_prefix}-high-compliance-violations"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ComplianceViolations"
  namespace           = "SecurityGroup/Compliance"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors high number of compliance violations"
  alarm_actions       = [aws_sns_topic.compliance_alerts.arn]
  ok_actions          = [aws_sns_topic.compliance_alerts.arn]
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-high-violations-alarm"
    Purpose = "ComplianceMonitoring"
  })
}

# CloudWatch Alarm for Lambda errors
resource "aws_cloudwatch_metric_alarm" "lambda_error_alarm" {
  alarm_name          = "${local.resource_prefix}-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "LambdaErrors"
  namespace           = "SecurityGroup/Compliance"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors Lambda function errors"
  alarm_actions       = [aws_sns_topic.compliance_alerts.arn]
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-lambda-error-alarm"
    Purpose = "ErrorMonitoring"
  })
}

# CloudWatch Alarm for Lambda duration
resource "aws_cloudwatch_metric_alarm" "lambda_duration_alarm" {
  alarm_name          = "${local.resource_prefix}-lambda-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "600000" # 10 minutes in milliseconds
  alarm_description   = "This metric monitors Lambda function duration"
  alarm_actions       = [aws_sns_topic.compliance_alerts.arn]
  
  dimensions = {
    FunctionName = aws_lambda_function.compliance_scanner.function_name
  }
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-lambda-duration-alarm"
    Purpose = "PerformanceMonitoring"
  })
}

# CloudWatch Dashboard for compliance monitoring
resource "aws_cloudwatch_dashboard" "compliance_dashboard" {
  dashboard_name = "${local.resource_prefix}-compliance-dashboard"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["SecurityGroup/Compliance", "ComplianceViolations"],
            [".", "RemediationActions"],
            [".", "LambdaErrors"]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Security Group Compliance Metrics"
          view   = "timeSeries"
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        
        properties = {
          query = "SOURCE '${aws_cloudwatch_log_group.lambda_logs.name}' | fields @timestamp, @message\n| filter @message like /COMPLIANCE_VIOLATION/\n| sort @timestamp desc\n| limit 100"
          region = data.aws_region.current.name
          title  = "Recent Compliance Violations"
          view   = "table"
        }
      }
    ]
  })
}
