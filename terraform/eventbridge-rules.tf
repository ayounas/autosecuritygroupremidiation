# EventBridge rule for scheduled compliance scans

# EventBridge rule for scheduled compliance scanning
resource "aws_cloudwatch_event_rule" "compliance_schedule" {
  name                = local.eventbridge_rule_name
  description         = "Trigger compliance scanning on a schedule"
  schedule_expression = var.compliance_schedule
  state              = "ENABLED"
  
  tags = merge(local.common_tags, {
    Name    = local.eventbridge_rule_name
    Purpose = "ComplianceScheduling"
  })
}

# EventBridge target for Lambda function
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.compliance_schedule.name
  target_id = "ComplianceScannerLambdaTarget"
  arn       = aws_lambda_function.compliance_scanner.arn
  
  input = jsonencode({
    event_type = "scheduled_scan"
    scan_config = {
      dry_run                     = var.dry_run_mode
      enable_automatic_remediation = var.enable_automatic_remediation
      scan_all_accounts          = true
      severity_filter            = "all"
    }
    metadata = {
      triggered_by = "eventbridge"
      schedule     = var.compliance_schedule
      environment  = var.environment
    }
  })
}

# EventBridge rule for manual compliance scans (triggered by API calls)
resource "aws_cloudwatch_event_rule" "manual_compliance_scan" {
  name        = "${local.resource_prefix}-manual-scan"
  description = "Trigger manual compliance scanning"
  state       = "ENABLED"
  
  event_pattern = jsonencode({
    source      = ["custom.security.compliance"]
    detail-type = ["Manual Compliance Scan"]
  })
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-manual-scan"
    Purpose = "ManualComplianceScanning"
  })
}

# EventBridge target for manual scans
resource "aws_cloudwatch_event_target" "manual_lambda_target" {
  rule      = aws_cloudwatch_event_rule.manual_compliance_scan.name
  target_id = "ManualComplianceScannerLambdaTarget"
  arn       = aws_lambda_function.compliance_scanner.arn
}

# Lambda permission for manual scan EventBridge rule
resource "aws_lambda_permission" "allow_manual_eventbridge" {
  statement_id  = "AllowExecutionFromManualEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.manual_compliance_scan.arn
}

# EventBridge rule for security group changes (real-time compliance checking)
resource "aws_cloudwatch_event_rule" "security_group_changes" {
  name        = "${local.resource_prefix}-sg-changes"
  description = "Trigger compliance checking when security groups are modified"
  state       = "ENABLED"
  
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = [
      "AWS API Call via CloudTrail"
    ]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress", 
        "RevokeSecurityGroupEgress",
        "CreateSecurityGroup",
        "DeleteSecurityGroup"
      ]
    }
  })
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-sg-changes"
    Purpose = "RealTimeCompliance"
  })
}

# EventBridge target for security group changes
resource "aws_cloudwatch_event_target" "sg_changes_lambda_target" {
  rule      = aws_cloudwatch_event_rule.security_group_changes.name
  target_id = "SecurityGroupChangesLambdaTarget"
  arn       = aws_lambda_function.compliance_scanner.arn
}

# Lambda permission for security group changes EventBridge rule
resource "aws_lambda_permission" "allow_sg_changes_eventbridge" {
  statement_id  = "AllowExecutionFromSGChangesEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_group_changes.arn
}

# EventBridge rule for real-time security group creation detection
resource "aws_cloudwatch_event_rule" "new_security_group_detection" {
  name        = "${local.resource_prefix}-new-sg-detection"
  description = "Detect newly created security groups for immediate compliance checking"
  state       = "ENABLED"
  
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["CreateSecurityGroup"]
      errorCode   = { "exists": false }
    }
  })
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-new-sg-detection"
    Purpose = "RealTimeSecurityGroupDetection"
  })
}

# EventBridge target for new security group detection
resource "aws_cloudwatch_event_target" "new_sg_detection_target" {
  rule      = aws_cloudwatch_event_rule.new_security_group_detection.name
  target_id = "NewSecurityGroupDetectionTarget"
  arn       = aws_lambda_function.compliance_scanner.arn
  
  input_transformer {
    input_paths = {
      account     = "$.detail.recipientAccountId"
      region      = "$.detail.awsRegion"
      eventTime   = "$.detail.eventTime"
      sourceIP    = "$.detail.sourceIPAddress"
      userIdentity = "$.detail.userIdentity"
      groupId     = "$.detail.responseElements.groupId"
      groupName   = "$.detail.requestParameters.groupName"
    }
    
    input_template = jsonencode({
      event_type = "new_security_group_created"
      priority   = "high"
      scan_config = {
        immediate_scan        = true
        target_security_groups = ["<groupId>"]
        enable_automatic_remediation = true
        scan_scope           = "single_sg"
      }
      event_details = {
        account_id    = "<account>"
        region        = "<region>"
        event_time    = "<eventTime>"
        source_ip     = "<sourceIP>"
        user_identity = "<userIdentity>"
        group_id      = "<groupId>"
        group_name    = "<groupName>"
        detection_type = "new_creation"
      }
    })
  }
}

# Lambda permission for new security group detection
resource "aws_lambda_permission" "allow_new_sg_detection" {
  statement_id  = "AllowExecutionFromNewSGDetection"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.new_security_group_detection.arn
}

# EventBridge rule for detecting risky security group rule additions
resource "aws_cloudwatch_event_rule" "risky_sg_rule_detection" {
  name        = "${local.resource_prefix}-risky-rule-detection"
  description = "Detect risky security group rule additions for immediate action"
  state       = "ENABLED"
  
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress"
      ]
      errorCode = { "exists": false }
      requestParameters = {
        cidrIp = [
          { "prefix": "0.0.0.0/0" },
          { "prefix": "::/0" }
        ]
      }
    }
  })
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-risky-rule-detection"
    Purpose = "RealTimeRiskyRuleDetection"
  })
}

# EventBridge target for risky rule detection
resource "aws_cloudwatch_event_target" "risky_rule_detection_target" {
  rule      = aws_cloudwatch_event_rule.risky_sg_rule_detection.name
  target_id = "RiskyRuleDetectionTarget"
  arn       = aws_lambda_function.compliance_scanner.arn
  
  input_transformer {
    input_paths = {
      account      = "$.detail.recipientAccountId"
      region       = "$.detail.awsRegion"
      eventTime    = "$.detail.eventTime"
      sourceIP     = "$.detail.sourceIPAddress"
      userIdentity = "$.detail.userIdentity"
      groupId      = "$.detail.requestParameters.groupId"
      eventName    = "$.detail.eventName"
      ipPermissions = "$.detail.requestParameters.ipPermissions"
    }
    
    input_template = jsonencode({
      event_type = "risky_rule_added"
      priority   = "critical"
      scan_config = {
        immediate_scan        = true
        target_security_groups = ["<groupId>"]
        enable_automatic_remediation = true
        scan_scope           = "single_sg"
        violation_severity_threshold = "high"
      }
      event_details = {
        account_id     = "<account>"
        region         = "<region>"
        event_time     = "<eventTime>"
        source_ip      = "<sourceIP>"
        user_identity  = "<userIdentity>"
        group_id       = "<groupId>"
        event_name     = "<eventName>"
        ip_permissions = "<ipPermissions>"
        detection_type = "risky_rule_addition"
      }
    })
  }
}

# Lambda permission for risky rule detection
resource "aws_lambda_permission" "allow_risky_rule_detection" {
  statement_id  = "AllowExecutionFromRiskyRuleDetection"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.risky_sg_rule_detection.arn
}

# EventBridge rule for detecting mass security group operations
resource "aws_cloudwatch_event_rule" "mass_sg_operations_detection" {
  name        = "${local.resource_prefix}-mass-sg-operations"
  description = "Detect mass security group operations that might indicate attack or misconfiguration"
  state       = "ENABLED"
  
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = [
        "CreateSecurityGroup",
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress"
      ]
      errorCode = { "exists": false }
    }
  })
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-mass-sg-operations"
    Purpose = "MassOperationDetection"
  })
}

# EventBridge target for mass operations detection
resource "aws_cloudwatch_event_target" "mass_operations_detection_target" {
  rule      = aws_cloudwatch_event_rule.mass_sg_operations_detection.name
  target_id = "MassOperationsDetectionTarget"
  arn       = aws_lambda_function.mass_operations_detector.arn
}

# Lambda permission for mass operations detection
resource "aws_lambda_permission" "allow_mass_operations_detection" {
  statement_id  = "AllowExecutionFromMassOperationsDetection"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.mass_operations_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.mass_sg_operations_detection.arn
}
