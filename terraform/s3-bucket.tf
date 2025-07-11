# S3 bucket for compliance configuration and audit logs

# S3 bucket for storing compliance policies and audit logs
resource "aws_s3_bucket" "compliance_config" {
  bucket        = local.bucket_name
  force_destroy = var.environment != "prod" # Only allow force destroy in non-prod
  
  tags = merge(local.common_tags, {
    Name        = "${local.resource_prefix}-compliance-config"
    Purpose     = "ComplianceConfiguration"
    DataClass   = "Sensitive"
  })
}

# S3 bucket versioning
resource "aws_s3_bucket_versioning" "compliance_config_versioning" {
  bucket = aws_s3_bucket.compliance_config.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "compliance_config_encryption" {
  bucket = aws_s3_bucket.compliance_config.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.compliance_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# S3 bucket public access block
resource "aws_s3_bucket_public_access_block" "compliance_config_pab" {
  bucket = aws_s3_bucket.compliance_config.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket policy
resource "aws_s3_bucket_policy" "compliance_config_policy" {
  bucket = aws_s3_bucket.compliance_config.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnSecureCommunications"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.compliance_config.arn,
          "${aws_s3_bucket.compliance_config.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowLambdaAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_execution_role.arn
        }
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
      }
    ]
  })
  
  depends_on = [aws_s3_bucket_public_access_block.compliance_config_pab]
}

# S3 bucket lifecycle configuration
resource "aws_s3_bucket_lifecycle_configuration" "compliance_config_lifecycle" {
  bucket = aws_s3_bucket.compliance_config.id
  
  rule {
    id     = "audit_logs_lifecycle"
    status = "Enabled"
    
    filter {
      prefix = "audit-logs/"
    }
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }
    
    expiration {
      days = 2555 # 7 years retention
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
  
  rule {
    id     = "config_files_lifecycle"
    status = "Enabled"
    
    filter {
      prefix = "config/"
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

# Upload default security policies configuration
resource "aws_s3_object" "default_security_policies" {
  bucket       = aws_s3_bucket.compliance_config.id
  key          = "config/security_policies.json"
  content      = file("${path.module}/../config/security_policies.json")
  content_type = "application/json"
  
  server_side_encryption = "aws:kms"
  kms_key_id            = aws_kms_key.compliance_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "default-security-policies"
    Purpose = "CompliancePolicies"
  })
  
  depends_on = [aws_s3_bucket_server_side_encryption_configuration.compliance_config_encryption]
}

# Upload Lambda deployment package placeholder
resource "aws_s3_object" "lambda_deployment_package" {
  bucket = aws_s3_bucket.compliance_config.id
  key    = "lambda/compliance-scanner.zip"
  source = data.archive_file.lambda_zip.output_path
  
  server_side_encryption = "aws:kms"
  kms_key_id            = aws_kms_key.compliance_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "lambda-deployment-package"
    Purpose = "LambdaCode"
  })
  
  depends_on = [
    aws_s3_bucket_server_side_encryption_configuration.compliance_config_encryption,
    data.archive_file.lambda_zip
  ]
}
