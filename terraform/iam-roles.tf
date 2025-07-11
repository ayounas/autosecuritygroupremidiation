# IAM roles and policies for Security Group Compliance Framework

# Lambda execution role
resource "aws_iam_role" "lambda_execution_role" {
  name = "${local.resource_prefix}-lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Lambda basic execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Custom policy for security group compliance operations
resource "aws_iam_role_policy" "compliance_scanner_policy" {
  name = "${local.resource_prefix}-compliance-scanner-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2SecurityGroupReadPermissions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules"
        ]
        Resource = [
          "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:security-group/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = [var.aws_region]
          }
        }
      },
      {
        Sid    = "EC2GeneralReadOnlyPermissions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeTags",
          "ec2:DescribeVpcs",
          "ec2:DescribeNetworkInterfaces"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2SecurityGroupWritePermissions"
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = [
          "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:security-group/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = [var.aws_region]
          }
        }
      },
      {
        Sid    = "EC2TaggingPermissions"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = [
          "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:security-group/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = [var.aws_region]
            "ec2:CreateAction" = [
              "AuthorizeSecurityGroupIngress",
              "AuthorizeSecurityGroupEgress",
              "RevokeSecurityGroupIngress",
              "RevokeSecurityGroupEgress"
            ]
          }
        }
      },
      {
        Sid    = "CrossAccountAssumeRole"
        Effect = "Allow"
        Action = [
          "sts:AssumeRole"
        ]
        Resource = [
          for account_id in var.target_accounts :
          "arn:aws:iam::${account_id}:role/${local.resource_prefix}-cross-account-role"
        ]
      },
      {
        Sid    = "S3ConfigurationAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.compliance_config.arn,
          "${aws_s3_bucket.compliance_config.arn}/*"
        ]
      },
      {
        Sid    = "KMSDecryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = [
          aws_kms_key.compliance_key.arn
        ]
      },
      {
        Sid    = "SNSPublish"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.compliance_alerts.arn
        ]
      },
      {
        Sid    = "SSMParameterAccess"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:PutParameter",
          "ssm:GetParametersByPath"
        ]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${local.resource_prefix}/*"
        ]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${local.log_group_name}*"
        ]
      }
    ]
  })
}

# Cross-account role for target accounts (to be created in target accounts)
resource "aws_iam_role" "cross_account_role" {
  count = length(var.target_accounts) > 0 ? 1 : 0
  name  = "${local.resource_prefix}-cross-account-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_execution_role.arn
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "${local.resource_prefix}-external-id"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# Cross-account role policy
resource "aws_iam_role_policy" "cross_account_policy" {
  count = length(var.target_accounts) > 0 ? 1 : 0
  name  = "${local.resource_prefix}-cross-account-policy"
  role  = aws_iam_role.cross_account_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityGroupSpecificReadPermissions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules"
        ]
        Resource = [
          "arn:aws:ec2:*:*:security-group/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = [var.aws_region]
          }
        }
      },
      {
        Sid    = "GeneralReadOnlyPermissions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeTags",
          "ec2:DescribeVpcs",
          "ec2:DescribeNetworkInterfaces"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecurityGroupWritePermissions"
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = [
          "arn:aws:ec2:*:*:security-group/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = [var.aws_region]
          }
        }
      },
      {
        Sid    = "SecurityGroupTaggingPermissions"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = [
          "arn:aws:ec2:*:*:security-group/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = [var.aws_region]
            "ec2:CreateAction" = [
              "AuthorizeSecurityGroupIngress",
              "AuthorizeSecurityGroupEgress",
              "RevokeSecurityGroupIngress",
              "RevokeSecurityGroupEgress"
            ]
          }
        }
      }
    ]
  })
}

# EventBridge execution role
resource "aws_iam_role" "eventbridge_role" {
  name = "${local.resource_prefix}-eventbridge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# EventBridge Lambda invoke policy
resource "aws_iam_role_policy" "eventbridge_lambda_policy" {
  name = "${local.resource_prefix}-eventbridge-lambda-policy"
  role = aws_iam_role.eventbridge_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          aws_lambda_function.compliance_scanner.arn
        ]
      }
    ]
  })
}
