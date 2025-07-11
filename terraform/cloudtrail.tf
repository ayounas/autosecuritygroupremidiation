# CloudTrail for Security Group API monitoring
resource "aws_cloudtrail" "security_group_monitoring" {
  count = var.enable_cloudtrail ? 1 : 0
  
  name           = "${local.resource_prefix}-sg-monitoring"
  s3_bucket_name = aws_s3_bucket.compliance_bucket.bucket
  s3_key_prefix  = "cloudtrail-logs"
  
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_logging               = true
  
  # Focus on EC2 security group events
  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []
    
    data_resource {
      type   = "AWS::EC2::SecurityGroup"
      values = ["arn:aws:ec2:*:*:security-group/*"]
    }
  }
  
  # Advanced event selectors for better granularity
  advanced_event_selector {
    name = "SecurityGroupOperations"
    
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
    
    field_selector {
      field  = "eventName"
      equals = [
        "CreateSecurityGroup",
        "DeleteSecurityGroup",
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
        "ModifySecurityGroupRules"
      ]
    }
  }
  
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail_logs[0].arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_role[0].arn
  
  kms_key_id = aws_kms_key.compliance_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-sg-monitoring"
    Purpose = "SecurityGroupMonitoring"
  })
  
  depends_on = [aws_s3_bucket_policy.compliance_bucket_policy]
}

# CloudWatch Log Group for CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail_logs" {
  count = var.enable_cloudtrail ? 1 : 0
  
  name              = "/aws/cloudtrail/${local.resource_prefix}-sg-monitoring"
  retention_in_days = var.log_retention_days
  kms_key_id       = aws_kms_key.compliance_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-cloudtrail-logs"
    Purpose = "CloudTrailLogging"
  })
}

# IAM role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_role" {
  count = var.enable_cloudtrail ? 1 : 0
  
  name = "${local.resource_prefix}-cloudtrail-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-cloudtrail-role"
    Purpose = "CloudTrailLogging"
  })
}

# IAM policy for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role_policy" "cloudtrail_logs_policy" {
  count = var.enable_cloudtrail ? 1 : 0
  
  name = "${local.resource_prefix}-cloudtrail-logs-policy"
  role = aws_iam_role.cloudtrail_role[0].id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail_logs[0].arn}:*"
      }
    ]
  })
}

# S3 bucket policy update for CloudTrail
resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  count = var.enable_cloudtrail ? 1 : 0
  
  bucket = aws_s3_bucket.compliance_bucket.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.compliance_bucket.arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.resource_prefix}-sg-monitoring"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.compliance_bucket.arn}/cloudtrail-logs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.resource_prefix}-sg-monitoring"
          }
        }
      }
    ]
  })
  
  depends_on = [aws_s3_bucket_public_access_block.compliance_bucket]
}

# CloudWatch metric filter for critical security group operations
resource "aws_cloudwatch_log_metric_filter" "critical_sg_operations" {
  count = var.enable_cloudtrail ? 1 : 0
  
  name           = "${local.resource_prefix}-critical-sg-operations"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_logs[0].name
  
  pattern = "{ ($.eventName = AuthorizeSecurityGroupIngress) && ($.requestParameters.cidrIp = \"0.0.0.0/0\" || $.requestParameters.cidrIp = \"::/0\") }"
  
  metric_transformation {
    name      = "CriticalSecurityGroupOperations"
    namespace = "SecurityCompliance/RealTime"
    value     = "1"
    
    default_value = "0"
  }
}

# CloudWatch alarm for critical operations
resource "aws_cloudwatch_metric_alarm" "critical_sg_operations_alarm" {
  count = var.enable_cloudtrail ? 1 : 0
  
  alarm_name          = "${local.resource_prefix}-critical-sg-operations"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CriticalSecurityGroupOperations"
  namespace           = "SecurityCompliance/RealTime"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Critical security group operations detected"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-critical-sg-alarm"
    Purpose = "RealTimeAlerting"
  })
}
