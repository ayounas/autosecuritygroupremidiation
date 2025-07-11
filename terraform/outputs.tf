# Outputs for the Security Group Compliance Framework

output "lambda_function_name" {
  description = "Name of the compliance scanner Lambda function"
  value       = aws_lambda_function.compliance_scanner.function_name
}

output "lambda_function_arn" {
  description = "ARN of the compliance scanner Lambda function"
  value       = aws_lambda_function.compliance_scanner.arn
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for compliance configuration"
  value       = aws_s3_bucket.compliance_config.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket for compliance configuration"
  value       = aws_s3_bucket.compliance_config.arn
}

output "kms_key_id" {
  description = "ID of the KMS key used for encryption"
  value       = aws_kms_key.compliance_key.key_id
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for encryption"
  value       = aws_kms_key.compliance_key.arn
}

output "kms_key_alias" {
  description = "Alias of the KMS key used for encryption"
  value       = aws_kms_alias.compliance_key_alias.name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for compliance alerts"
  value       = aws_sns_topic.compliance_alerts.arn
}

output "critical_violations_topic_arn" {
  description = "ARN of the SNS topic for critical violations"
  value       = aws_sns_topic.critical_violations.arn
}

output "iam_lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_execution_role.arn
}

output "cross_account_role_arn" {
  description = "ARN of the cross-account role (if target accounts are specified)"
  value       = length(var.target_accounts) > 0 ? aws_iam_role.cross_account_role[0].arn : null
}

output "cross_account_role_name" {
  description = "Name of the cross-account role (if target accounts are specified)"
  value       = length(var.target_accounts) > 0 ? aws_iam_role.cross_account_role[0].name : null
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for Lambda logs"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "audit_log_group_name" {
  description = "Name of the CloudWatch log group for audit logs"
  value       = aws_cloudwatch_log_group.compliance_audit_logs.name
}

output "eventbridge_schedule_rule_arn" {
  description = "ARN of the EventBridge rule for scheduled scans"
  value       = aws_cloudwatch_event_rule.compliance_schedule.arn
}

output "eventbridge_manual_rule_arn" {
  description = "ARN of the EventBridge rule for manual scans"
  value       = aws_cloudwatch_event_rule.manual_compliance_scan.arn
}

output "eventbridge_sg_changes_rule_arn" {
  description = "ARN of the EventBridge rule for security group changes"
  value       = aws_cloudwatch_event_rule.security_group_changes.arn
}

output "dashboard_url" {
  description = "URL to the CloudWatch dashboard for compliance monitoring"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.compliance_dashboard.dashboard_name}"
}

output "dead_letter_queue_arn" {
  description = "ARN of the SQS dead letter queue"
  value       = aws_sqs_queue.compliance_dlq.arn
}

output "compliance_config_parameter_name" {
  description = "Name of the SSM parameter for compliance configuration"
  value       = aws_ssm_parameter.compliance_config.name
}

output "external_id_parameter_name" {
  description = "Name of the SSM parameter for external ID"
  value       = aws_ssm_parameter.external_id.name
}

output "framework_version" {
  description = "Version of the compliance framework"
  value       = aws_ssm_parameter.framework_version.value
}

output "deployment_region" {
  description = "AWS region where the framework is deployed"
  value       = data.aws_region.current.name
}

output "deployment_account_id" {
  description = "AWS account ID where the framework is deployed"
  value       = data.aws_caller_identity.current.account_id
}

output "target_accounts" {
  description = "List of target AWS accounts for compliance scanning"
  value       = var.target_accounts
}

output "dry_run_mode" {
  description = "Whether the framework is running in dry run mode"
  value       = var.dry_run_mode
}

output "automatic_remediation_enabled" {
  description = "Whether automatic remediation is enabled"
  value       = var.enable_automatic_remediation
}

output "compliance_schedule" {
  description = "Schedule expression for compliance scans"
  value       = var.compliance_schedule
}

# Output for manual trigger command
output "manual_trigger_command" {
  description = "AWS CLI command to manually trigger a compliance scan"
  value = "aws events put-events --entries 'Source=custom.security.compliance,DetailType=\"Manual Compliance Scan\",Detail=\"{\\\"scan_type\\\":\\\"manual\\\",\\\"triggered_by\\\":\\\"user\\\"}\"' --region ${data.aws_region.current.name}"
}

# Output for configuration update
output "config_s3_path" {
  description = "S3 path for the security policies configuration file"
  value       = "s3://${aws_s3_bucket.compliance_config.id}/config/security_policies.json"
}
