# SSM Parameters for configuration management

# SSM Parameter for compliance configuration
resource "aws_ssm_parameter" "compliance_config" {
  name        = "/${local.resource_prefix}/config/compliance"
  description = "Security Group Compliance Framework Configuration"
  type        = "SecureString"
  key_id      = aws_kms_key.compliance_key.arn
  tier        = "Standard"
  
  value = jsonencode({
    dry_run_mode                 = var.dry_run_mode
    enable_automatic_remediation = var.enable_automatic_remediation
    target_accounts             = var.target_accounts
    compliance_severity_levels  = var.compliance_severity_levels
    notification_settings = {
      email_notifications = var.notification_email != ""
      sns_topic_arn      = aws_sns_topic.compliance_alerts.arn
      critical_topic_arn = aws_sns_topic.critical_violations.arn
    }
    s3_config = {
      bucket_name         = aws_s3_bucket.compliance_config.id
      config_prefix      = "config/"
      audit_logs_prefix  = "audit-logs/"
    }
    remediation_settings = {
      backup_before_remediation = true
      add_compliance_tags      = true
      create_dummy_rule        = true
      notification_before_action = true
    }
  })
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-compliance-config"
    Purpose = "ComplianceConfiguration"
  })
}

# SSM Parameter for cross-account external ID
resource "aws_ssm_parameter" "external_id" {
  name        = "/${local.resource_prefix}/security/external-id"
  description = "External ID for cross-account role assumption"
  type        = "SecureString"
  key_id      = aws_kms_key.compliance_key.arn
  tier        = "Standard"
  value       = "${local.resource_prefix}-external-id"
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-external-id"
    Purpose = "CrossAccountSecurity"
  })
}

# SSM Parameter for framework version tracking
resource "aws_ssm_parameter" "framework_version" {
  name        = "/${local.resource_prefix}/metadata/version"
  description = "Security Group Compliance Framework Version"
  type        = "String"
  tier        = "Standard"
  value       = "1.0.0"
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-framework-version"
    Purpose = "VersionTracking"
  })
}

# SSM Parameter for last scan timestamp
resource "aws_ssm_parameter" "last_scan_timestamp" {
  name        = "/${local.resource_prefix}/metadata/last-scan"
  description = "Timestamp of last compliance scan"
  type        = "String"
  tier        = "Standard"
  value       = "never"
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-last-scan"
    Purpose = "ScanTracking"
  })
  
  lifecycle {
    ignore_changes = [value]
  }
}

# SSM Parameter for scan statistics
resource "aws_ssm_parameter" "scan_statistics" {
  name        = "/${local.resource_prefix}/metadata/scan-stats"
  description = "Statistics from compliance scans"
  type        = "String"
  tier        = "Standard"
  
  value = jsonencode({
    total_scans_performed     = 0
    total_violations_found    = 0
    total_remediations_applied = 0
    last_scan_duration_seconds = 0
    accounts_scanned          = []
    last_updated              = timestamp()
  })
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-scan-stats"
    Purpose = "ScanStatistics"
  })
  
  lifecycle {
    ignore_changes = [value]
  }
}
