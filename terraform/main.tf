# Main Terraform configuration for AWS Security Group Compliance Framework

terraform {
  required_version = ">= 1.0"
  
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
  
  backend "s3" {
    # Configure with terraform init -backend-config="bucket=your-terraform-state-bucket"
    key            = "security-group-compliance/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    use_lockfile   = true
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = merge(var.tags, {
      Environment = var.environment
      Terraform   = "true"
    })
  }
}

# Data sources for current AWS account and region
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Generate unique resource names
locals {
  resource_prefix = "${var.project_name}-${var.environment}"
  
  # S3 bucket name with account ID to ensure uniqueness
  bucket_name = var.s3_bucket_name != "" ? var.s3_bucket_name : "${local.resource_prefix}-${data.aws_caller_identity.current.account_id}"
  
  # Common tags for all resources
  common_tags = merge(var.tags, {
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "Terraform"
    Purpose     = "SecurityGroupCompliance"
  })
  
  # Lambda function name
  lambda_function_name = "${local.resource_prefix}-compliance-scanner"
  
  # Resource naming
  kms_key_alias       = "alias/${local.resource_prefix}-compliance"
  sns_topic_name      = "${local.resource_prefix}-compliance-alerts"
  log_group_name      = "/aws/lambda/${local.lambda_function_name}"
  
  # EventBridge rule name
  eventbridge_rule_name = "${local.resource_prefix}-compliance-schedule"
}
