# Variables for AWS Security Group Compliance Framework

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
  default     = "sg-compliance"
}

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

variable "target_accounts" {
  description = "List of AWS account IDs to scan for security group compliance"
  type        = list(string)
  default     = []
}

variable "compliance_schedule" {
  description = "CloudWatch Events schedule expression for compliance scans"
  type        = string
  default     = "rate(24 hours)"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 900
  
  validation {
    condition     = var.lambda_timeout >= 60 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 60 and 900 seconds."
  }
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 512
  
  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory size must be between 128 and 10240 MB."
  }
}

variable "dry_run_mode" {
  description = "Enable dry run mode - scans and logs violations without making changes"
  type        = bool
  default     = true
}

variable "enable_automatic_remediation" {
  description = "Enable automatic remediation of non-compliant security groups"
  type        = bool
  default     = false
}

variable "notification_email" {
  description = "Email address for compliance violation notifications"
  type        = string
  default     = ""
}

variable "s3_bucket_name" {
  description = "S3 bucket name for storing compliance configurations and logs"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "SecurityGroupCompliance"
    ManagedBy   = "Terraform"
    Purpose     = "SecurityCompliance"
  }
}

variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 7
  
  validation {
    condition     = var.kms_key_deletion_window >= 7 && var.kms_key_deletion_window <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 30
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

variable "compliance_severity_levels" {
  description = "Severity levels for different types of compliance violations"
  type = object({
    critical = list(string)
    high     = list(string)
    medium   = list(string)
    low      = list(string)
  })
  default = {
    critical = ["0.0.0.0/0", "::/0"]
    high     = ["unrestricted_ports"]
    medium   = ["deprecated_protocols"]
    low      = ["missing_description"]
  }
}

# Mass operations detection variables
variable "max_operations_per_minute" {
  description = "Maximum allowed security group operations per minute per user"
  type        = number
  default     = 10
  
  validation {
    condition     = var.max_operations_per_minute > 0 && var.max_operations_per_minute <= 100
    error_message = "Max operations per minute must be between 1 and 100."
  }
}

variable "mass_operations_alert_threshold" {
  description = "Threshold for mass operations alarm"
  type        = number
  default     = 5
  
  validation {
    condition     = var.mass_operations_alert_threshold > 0
    error_message = "Mass operations alert threshold must be greater than 0."
  }
}

variable "block_suspicious_users" {
  description = "Whether to automatically block users performing suspicious mass operations"
  type        = bool
  default     = false
}

variable "real_time_scanning_enabled" {
  description = "Enable real-time scanning of new security groups and rule changes"
  type        = bool
  default     = true
}

variable "immediate_remediation_enabled" {
  description = "Enable immediate remediation for critical violations in real-time scanning"
  type        = bool
  default     = false
}

variable "violation_severity_threshold" {
  description = "Minimum violation severity that triggers immediate remediation"
  type        = string
  default     = "critical"
  
  validation {
    condition     = contains(["info", "low", "medium", "high", "critical"], var.violation_severity_threshold)
    error_message = "Violation severity threshold must be one of: info, low, medium, high, critical."
  }
}

# CloudTrail configuration
variable "enable_cloudtrail" {
  description = "Enable CloudTrail for security group API monitoring"
  type        = bool
  default     = true
}
