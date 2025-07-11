# Cross-account IAM roles for Security Group Compliance
# Deploy this in each target account to enable central compliance scanning

# Data source for central compliance account
data "aws_caller_identity" "central_account" {
  # This should be run in the central account to get the account ID
}

# Cross-account role for compliance scanning and remediation
resource "aws_iam_role" "security_group_compliance_cross_account_role" {
  name = "${var.resource_prefix}-cross-account-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.central_compliance_account_id}:role/${var.resource_prefix}-lambda-execution-role"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
          IpAddress = {
            "aws:SourceIp" = var.allowed_source_ips
          }
        }
      }
    ]
  })
  
  max_session_duration = 3600  # 1 hour
  
  tags = {
    Name        = "${var.resource_prefix}-cross-account-role"
    Purpose     = "SecurityGroupCompliance"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# IAM policy for security group operations
resource "aws_iam_policy" "security_group_compliance_policy" {
  name        = "${var.resource_prefix}-compliance-policy"
  description = "Policy for security group compliance scanning and remediation"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Security Group read permissions
      {
        Sid    = "SecurityGroupReadOperations"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupReferences",
          "ec2:DescribeSecurityGroupRules",
          "ec2:DescribeVpcs",
          "ec2:DescribeRegions"
        ]
        Resource = "*"
      },
      # Security Group modification permissions (conditional based on enforcement level)
      {
        Sid    = "SecurityGroupModificationOperations"
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:ModifySecurityGroupRules"
        ]
        Resource = [
          "arn:aws:ec2:*:*:security-group/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.allowed_regions
          }
          # Additional condition to prevent modification of critical SGs
          "ForAllValues:StringNotLike" = {
            "ec2:ResourceTag/Name" = [
              "*default*",
              "*critical*",
              "*protected*"
            ]
          }
        }
      },
      # Tagging permissions
      {
        Sid    = "SecurityGroupTaggingOperations"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeTags"
        ]
        Resource = [
          "arn:aws:ec2:*:*:security-group/*"
        ]
        Condition = {
          StringLike = {
            "ec2:CreateAction" = [
              "CreateTags"
            ]
          }
          "ForAllValues:StringLike" = {
            "aws:TagKeys" = [
              "COMPLIANCE_*",
              "SecurityGroup*",
              "Remediation*"
            ]
          }
        }
      },
      # CloudWatch metrics permissions
      {
        Sid    = "CloudWatchMetricsOperations"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = [
              "SecurityCompliance/SecurityGroups",
              "SecurityCompliance/CrossAccount"
            ]
          }
        }
      },
      # Systems Manager parameter access for configuration
      {
        Sid    = "SSMParameterAccess"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = [
          "arn:aws:ssm:*:*:parameter/${var.resource_prefix}/*"
        ]
      },
      # Account information
      {
        Sid    = "AccountInformation"
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity",
          "organizations:DescribeAccount"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "compliance_policy_attachment" {
  role       = aws_iam_role.security_group_compliance_cross_account_role.name
  policy_arn = aws_iam_policy.security_group_compliance_policy.arn
}

# Additional read-only policy for monitoring mode accounts
resource "aws_iam_policy" "security_group_read_only_policy" {
  count = var.enforcement_level == "monitor" ? 1 : 0
  
  name        = "${var.resource_prefix}-read-only-policy"
  description = "Read-only policy for security group monitoring"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityGroupReadOnlyOperations"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupReferences",
          "ec2:DescribeSecurityGroupRules",
          "ec2:DescribeVpcs",
          "ec2:DescribeRegions",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchReadOperations"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "SecurityCompliance/Monitoring"
          }
        }
      }
    ]
  })
}

# Attach read-only policy for monitoring accounts
resource "aws_iam_role_policy_attachment" "read_only_policy_attachment" {
  count = var.enforcement_level == "monitor" ? 1 : 0
  
  role       = aws_iam_role.security_group_compliance_cross_account_role.name
  policy_arn = aws_iam_policy.security_group_read_only_policy[0].arn
}

# IAM policy for emergency lockdown (only for enforce mode)
resource "aws_iam_policy" "emergency_lockdown_policy" {
  count = var.enforcement_level == "enforce" ? 1 : 0
  
  name        = "${var.resource_prefix}-emergency-lockdown-policy"
  description = "Policy for emergency security group lockdown"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EmergencyLockdownOperations"
        Effect = "Allow"
        Action = [
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress"  # Only for adding dummy rule
        ]
        Resource = [
          "arn:aws:ec2:*:*:security-group/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestTag/COMPLIANCE_EMERGENCY" = "true"
          }
        }
      }
    ]
  })
}

# Attach emergency policy for enforce mode
resource "aws_iam_role_policy_attachment" "emergency_policy_attachment" {
  count = var.enforcement_level == "enforce" ? 1 : 0
  
  role       = aws_iam_role.security_group_compliance_cross_account_role.name
  policy_arn = aws_iam_policy.emergency_lockdown_policy[0].arn
}

# CloudWatch log group for cross-account operations
resource "aws_cloudwatch_log_group" "cross_account_operations" {
  name              = "/aws/compliance/cross-account-operations"
  retention_in_days = var.log_retention_days
  
  tags = {
    Name        = "${var.resource_prefix}-cross-account-logs"
    Purpose     = "ComplianceLogging"
    Environment = var.environment
  }
}

# Output the role ARN for use in central account
output "cross_account_role_arn" {
  description = "ARN of the cross-account role for compliance scanning"
  value       = aws_iam_role.security_group_compliance_cross_account_role.arn
}

output "cross_account_role_name" {
  description = "Name of the cross-account role"
  value       = aws_iam_role.security_group_compliance_cross_account_role.name
}

output "external_id" {
  description = "External ID for cross-account role assumption"
  value       = var.external_id
  sensitive   = true
}
