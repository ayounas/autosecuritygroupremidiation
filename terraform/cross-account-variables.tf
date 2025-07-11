# Cross-Account Role Variables
# These variables should be set when deploying cross-account roles in target accounts

variable "central_compliance_account_id" {
  description = "AWS account ID of the central compliance account"
  type        = string
  
  validation {
    condition     = can(regex("^[0-9]{12}$", var.central_compliance_account_id))
    error_message = "Central compliance account ID must be a 12-digit AWS account ID."
  }
}

variable "resource_prefix" {
  description = "Prefix for resource naming"
  type        = string
  default     = "sg-compliance"
  
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.resource_prefix))
    error_message = "Resource prefix must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "enforcement_level" {
  description = "Enforcement level for this account (enforce, warn, monitor, disabled)"
  type        = string
  
  validation {
    condition     = contains(["enforce", "warn", "monitor", "disabled"], var.enforcement_level)
    error_message = "Enforcement level must be one of: enforce, warn, monitor, disabled."
  }
}

variable "external_id" {
  description = "External ID for cross-account role assumption security"
  type        = string
  sensitive   = true
  
  validation {
    condition     = length(var.external_id) >= 8
    error_message = "External ID must be at least 8 characters long."
  }
}

variable "allowed_source_ips" {
  description = "List of IP addresses/ranges allowed to assume the cross-account role"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for ip in var.allowed_source_ips : can(cidrhost(ip, 0))
    ])
    error_message = "All allowed source IPs must be valid CIDR blocks."
  }
}

variable "allowed_regions" {
  description = "List of AWS regions where the role can operate"
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
  
  validation {
    condition     = length(var.allowed_regions) > 0
    error_message = "At least one region must be specified."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 30
  
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch Logs retention period."
  }
}

variable "account_name" {
  description = "Human-readable name for this account"
  type        = string
  default     = ""
}

variable "compliance_tags" {
  description = "Additional tags for compliance resources"
  type        = map(string)
  default     = {}
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Local values
locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  
  common_tags = merge(var.compliance_tags, {
    ManagedBy         = "Terraform"
    Purpose           = "SecurityGroupCompliance"
    Environment       = var.environment
    EnforcementLevel  = var.enforcement_level
    CentralAccount    = var.central_compliance_account_id
  })
}
