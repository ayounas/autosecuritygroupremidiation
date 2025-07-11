# AWS Security Group Compliance Framework

A comprehensive Terraform-based framework for automatically scanning, flagging, and remediating security group vulnerabilities across multi-account AWS environments.

## Overview

This framework provides centralized security group compliance management with the following capabilities:

- **Multi-Account Scanning**: Scan security groups across all linked AWS accounts
- **Policy-Based Compliance**: Define security group principles in centralized configuration
- **Automated Remediation**: Flag non-compliant security groups and enforce default deny posture
- **Audit Logging**: Comprehensive logging of all actions and compliance violations
- **Safe Operations**: Idempotent and non-disruptive operations with clear warnings

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Config Store  │────│  Lambda Function │────│   CloudWatch    │
│   (S3/SSM)     │    │   (Compliance)   │    │    Logs         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Multi-Account Security Groups                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Account A  │  │  Account B  │  │  Account C  │    ...      │
│  │    SGs      │  │    SGs      │  │    SGs      │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Compliance Actions                        │
│  • Scan & Compare    • Flag Non-Compliant    • Log Violations  │
│  • Add Tags          • Remove Rules          • Send Alerts     │
│  • Add Dummy Rule    • Create Backups        • Generate Reports│
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
├── terraform/                 # Infrastructure as Code
│   ├── main.tf               # Main Terraform configuration
│   ├── variables.tf          # Input variables
│   ├── outputs.tf           # Output values
│   ├── iam-roles.tf         # IAM roles and policies
│   ├── lambda-function.tf   # Lambda function resources
│   ├── s3-bucket.tf         # S3 bucket for config and state
│   ├── cloudwatch-logs.tf   # CloudWatch logging
│   ├── eventbridge-rules.tf # EventBridge scheduling
│   ├── sns-notifications.tf # SNS notifications
│   ├── kms-key.tf          # KMS encryption
│   └── ssm-parameters.tf   # SSM parameter store
├── src/                     # Lambda function source code
│   ├── lambda_handler.py    # Main Lambda handler
│   ├── compliance_scanner.py # Security group scanner
│   ├── config_manager.py    # Configuration management
│   ├── sg_remediator.py     # Remediation engine
│   ├── requirements.txt     # Python dependencies
│   └── utils/              # Utility modules
│       ├── exceptions.py   # Custom exceptions
│       ├── logger.py       # Logging utilities
│       ├── metrics.py      # Metrics collection
│       └── helpers.py      # Helper functions
├── config/                  # Compliance policies
│   └── security_policies.json # Security group policies
├── deploy.sh               # Deployment script
└── README.md              # This file
```

## Features

### 1. Centralized Policy Management
- JSON-based security group compliance policies
- Easy to update, add, or remove principles
- Version controlled configuration
- Account-specific policy overrides
- Exemption management

### 2. Multi-Account Support
- Cross-account role assumption
- Centralized compliance management
- Account-specific policies support
- Automated credential management

### 3. Safe Remediation
- **Non-disruptive scanning**: Read-only operations by default
- **Clear warnings**: Comprehensive logging before any changes
- **Idempotent operations**: Safe to run multiple times
- **Backup and rollback**: Automatic backup before remediation
- **Graduated enforcement**: Warning → Tagging → Remediation

### 4. Compliance Actions
When violations are found, the framework:
- **Tags security groups** with compliance status and violation details
- **Removes all rules** from non-compliant security groups
- **Adds a dummy rule** explaining why rules were removed
- **Creates backups** of original configurations in S3
- **Sends notifications** via SNS for immediate alerts
- **Logs all actions** for audit trails

### 5. Comprehensive Monitoring
- Structured logging (JSON format)
- CloudWatch integration with custom metrics
- SNS notifications for violations
- CloudWatch dashboard for monitoring
- Audit trail of all actions

## Quick Start

### Prerequisites

- AWS CLI configured with appropriate permissions
- Terraform >= 1.0
- Python 3.11+
- Bash shell (for deployment script)

### 1. Clone and Configure

```bash
git clone <repository-url>
cd autosecuritygroupremidiation

# Copy and customize configuration
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Edit terraform.tfvars with your settings
```

### 2. Deploy Infrastructure

```bash
# For dry run (plan only)
./deploy.sh --dry-run

# Deploy to development
./deploy.sh --environment dev --region us-east-1

# Deploy to production with auto-approval
./deploy.sh --environment prod --region us-west-2 --auto-approve
```

### 3. Configure Cross-Account Access

For each target account, create the cross-account role:

```bash
# In each target account, create role with trust policy
aws iam create-role \
  --role-name sg-compliance-dev-cross-account-role \
  --assume-role-policy-document file://cross-account-trust-policy.json

# Attach policy for security group permissions
aws iam attach-role-policy \
  --role-name sg-compliance-dev-cross-account-role \
  --policy-arn arn:aws:iam::TARGET_ACCOUNT:policy/sg-compliance-policy
```

### 4. Test the Framework

```bash
# Manual trigger via AWS CLI
aws events put-events \
  --entries 'Source=custom.security.compliance,DetailType="Manual Compliance Scan",Detail="{\"scan_type\":\"manual\"}"'

# Check results in CloudWatch Logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/sg-compliance-dev-compliance-scanner \
  --filter-pattern "COMPLIANCE_VIOLATION"
```

## Configuration

### Security Policies

The framework uses a comprehensive JSON configuration file (`config/security_policies.json`) to define compliance rules:

#### Prohibited Rules
Rules that are strictly forbidden:
```json
{
  "prohibited_rules": {
    "inbound": [
      {
        "rule_id": "PROHIBIT_ALL_TRAFFIC_SSH",
        "description": "Prohibit SSH access from anywhere",
        "protocol": "tcp",
        "port_range": "22",
        "source": "0.0.0.0/0",
        "severity": "critical",
        "reason": "SSH access should be restricted to specific IP ranges"
      }
    ]
  }
}
```

#### Environment-Specific Rules
Different rules for different environments:
```json
{
  "environment_specific": {
    "production": {
      "additional_restrictions": [
        {
          "rule_id": "PROD_NO_EPHEMERAL_PORTS",
          "description": "Prohibit ephemeral port ranges in production",
          "protocol": "tcp",
          "prohibited_port_ranges": ["32768-65535"],
          "severity": "medium"
        }
      ]
    }
  }
}
```

#### Exemptions
Temporary or permanent exemptions:
```json
{
  "exemptions": {
    "security_group_exemptions": {
      "sg-12345678": {
        "reason": "Legacy system requiring special access",
        "exempted_rules": ["PROHIBIT_ALL_TRAFFIC_SSH"],
        "expiry_date": "2026-01-01T00:00:00Z",
        "approved_by": "security_team"
      }
    }
  }
}
```

### Terraform Variables

Key configuration options in `terraform.tfvars`:

```hcl
# Basic Configuration
environment = "dev"
project_name = "sg-compliance"
aws_region = "us-east-1"

# Target accounts to scan
target_accounts = ["123456789012", "987654321098"]

# Framework behavior
dry_run_mode = true                    # Safe mode - no changes
enable_automatic_remediation = false  # Require manual approval

# Scheduling
compliance_schedule = "rate(24 hours)" # Daily scans

# Notifications
notification_email = "security-team@example.com"
```

## Remediation Process

When violations are detected and remediation is enabled:

### 1. Backup Original Configuration
- Creates timestamped backup in S3
- Includes complete security group configuration
- Enables rollback capabilities

### 2. Apply Compliance Tags
- `COMPLIANCE_STATUS`: NON_COMPLIANT
- `COMPLIANCE_VIOLATION_COUNT`: Number of violations
- `COMPLIANCE_VIOLATION_REASON`: Primary violation reason
- `COMPLIANCE_REMEDIATED`: true

### 3. Remove All Rules
- Removes all inbound rules
- Removes all outbound rules (except default deny)
- Enforces default deny posture

### 4. Add Dummy Rule
Adds an explanatory rule:
```
Description: "ALL RULES REMOVED - Security Group failed compliance check. 
             Contact Security Team. Violation: [violation_reason]"
Protocol: TCP
Port: 65535
Source: 127.0.0.1/32
```

### 5. Send Notifications
- SNS alerts for immediate notification
- CloudWatch logs for audit trail
- Dashboard updates for monitoring

## Monitoring and Alerting

### CloudWatch Metrics

The framework publishes custom metrics:
- `SecurityGroup/Compliance/ComplianceViolations`
- `SecurityGroup/Compliance/RemediationActions`
- `SecurityGroup/Compliance/LambdaErrors`
- `SecurityGroup/Compliance/ScanDuration`

### CloudWatch Alarms

Automated alarms for:
- High violation counts (>10 violations)
- Lambda function errors
- Long scan durations (>10 minutes)

### Dashboard

Comprehensive CloudWatch dashboard showing:
- Real-time compliance violations
- Remediation actions taken
- Scan performance metrics
- Error rates and trends

### Notifications

SNS notifications for:
- Critical violations (immediate)
- High violations (within 1 hour)
- Remediation actions (immediate)
- System errors (immediate)

## 🚀 Real-Time Scanning & Response

The framework now includes **real-time scanning capabilities** that detect and respond to security group changes as they happen:

### Real-Time Detection Features

#### 1. **New Security Group Creation Detection**
- Automatically scans newly created security groups within 30 seconds
- Flags non-compliant groups immediately
- Optional automatic remediation for critical violations
- Comprehensive tagging for tracking

#### 2. **Risky Rule Addition Detection**
- Monitors for dangerous rule additions (0.0.0.0/0, ::/0)
- Immediate scanning within 15 seconds of rule creation
- Emergency lockdown for critical violations
- Real-time alerts to security teams

#### 3. **Mass Operations Detection**
- Detects suspicious bulk security group operations
- Tracks user activity patterns across time windows
- Alerts on unusual activity (default: >10 operations/minute)
- Optional user blocking for suspected attacks

### Emergency Response Capabilities

#### **Emergency Remediation Mode**
When critical violations are detected:
1. **Immediate Backup**: All rules backed up to S3
2. **Complete Lockdown**: ALL rules removed from security group
3. **Dummy Rule Addition**: Adds localhost-only rule with violation details
4. **Emergency Tagging**: Tags SG with emergency status and backup ID
5. **Instant Alerts**: Critical notifications sent to security team

#### **Real-Time Configuration**
```json
{
  "real_time_scanning": {
    "enabled": true,
    "detection_rules": {
      "new_security_group_created": {
        "immediate_scan": true,
        "scan_within_seconds": 30,
        "auto_remediate_critical": false
      },
      "risky_rule_added": {
        "immediate_scan": true,
        "scan_within_seconds": 15,
        "auto_remediate_critical": true
      }
    }
  }
}
```

### Event-Driven Architecture

The real-time system uses **CloudTrail + EventBridge** for immediate response:

```
CloudTrail → EventBridge → Lambda → Immediate Scan → Emergency Action
    ↓           ↓           ↓            ↓              ↓
  EC2 API   Rule Match   Scanner    Violations?    Lockdown
```

### Safety Features

- **Dry Run Mode**: Test without making changes
- **Grace Periods**: Configurable delays before remediation
- **Backup System**: All changes backed up before remediation
- **Severity Thresholds**: Only act on violations above configured severity
- **Manual Override**: Emergency exemptions supported

### Deployment Commands

```bash
# Deploy with real-time scanning enabled
terraform apply -var="real_time_scanning_enabled=true"

# Enable emergency remediation (use with caution!)
terraform apply -var="immediate_remediation_enabled=true"

# Configure CloudTrail for API monitoring
terraform apply -var="enable_cloudtrail=true"
```

### Monitoring & Alerting

Real-time metrics are sent to CloudWatch:
- `MassOperationsDetected`: Bulk operations detected
- `CriticalViolationsFound`: Critical security violations
- `EmergencyRemediationsPerformed`: Emergency lockdowns executed
- `RealTimeScanDuration`: Response time for real-time scans

---

## Security Considerations

### Least Privilege Access
- Lambda execution role has minimal required permissions
- Cross-account roles scoped to security group operations only
- KMS encryption for all sensitive data

### Audit Trail
- All actions logged to CloudWatch with structured JSON
- S3 audit logs with lifecycle policies
- SSM parameter tracking for configuration changes

### Safe Operations
- Dry run mode by default
- Backup before any changes
- Rollback capabilities
- Non-disruptive scanning

### Data Protection
- KMS encryption for S3, CloudWatch, SNS
- Secure parameter store for configuration
- No sensitive data in logs

## Troubleshooting

### Common Issues

#### 1. Cross-Account Access Denied
```bash
# Check if role exists in target account
aws iam get-role --role-name sg-compliance-dev-cross-account-role

# Verify trust policy includes correct external ID
aws iam get-role --role-name sg-compliance-dev-cross-account-role \
  --query 'Role.AssumeRolePolicyDocument'
```

#### 2. Lambda Timeout
```bash
# Check CloudWatch logs for timeout errors
aws logs filter-log-events \
  --log-group-name /aws/lambda/sg-compliance-dev-compliance-scanner \
  --filter-pattern "Task timed out"

# Increase timeout in terraform.tfvars
lambda_timeout = 900  # 15 minutes
```

#### 3. Configuration Not Loading
```bash
# Check S3 bucket permissions
aws s3 ls s3://your-compliance-bucket/config/

# Verify KMS key permissions
aws kms describe-key --key-id alias/sg-compliance-dev-compliance
```

### Debug Mode

Enable debug logging:
```bash
# Update SSM parameter
aws ssm put-parameter \
  --name "/sg-compliance-dev/config/log-level" \
  --value "DEBUG" \
  --overwrite
```

### Manual Testing

Test individual components:
```python
# Test compliance scanner
python3 -c "
from src.compliance_scanner import ComplianceScanner
from src.config_manager import ConfigManager

config_manager = ConfigManager('your-bucket-name')
scanner = ComplianceScanner(config_manager)
# Test scanning logic
"
```

## Advanced Configuration

### Custom Policy Rules

Add custom rules to `security_policies.json`:
```json
{
  "compliance_policies": {
    "prohibited_rules": {
      "inbound": [
        {
          "rule_id": "CUSTOM_RULE_DATABASE_PORTS",
          "description": "Prohibit database ports from internet",
          "protocol": "tcp",
          "port_ranges": ["3306", "5432", "1433"],
          "source": "0.0.0.0/0",
          "severity": "critical",
          "reason": "Database ports should not be accessible from internet"
        }
      ]
    }
  }
}
```

### Account-Specific Overrides

Configure different rules per account:
```json
{
  "account_specific_overrides": {
    "account_123456789012": {
      "description": "Production account with stricter rules",
      "inherit_global_rules": true,
      "additional_prohibited_rules": [
        {
          "rule_id": "PROD_NO_DEV_PORTS",
          "description": "Prohibit development ports in production",
          "protocol": "tcp",
          "port_ranges": ["8000-8999"],
          "source": "0.0.0.0/0",
          "severity": "high"
        }
      ]
    }
  }
}
```

### Custom Notifications

Add additional SNS topics:
```hcl
# In terraform/sns-notifications.tf
resource "aws_sns_topic" "custom_alerts" {
  name = "${local.resource_prefix}-custom-alerts"
  # ... configuration
}
```

## Cost Optimization

### Resource Costs

Estimated monthly costs (us-east-1):
- Lambda (500 invocations/month): ~$0.20
- CloudWatch Logs (1GB/month): ~$0.50
- S3 Storage (10GB): ~$0.23
- SNS (1000 notifications): ~$0.50
- KMS (1000 requests): ~$0.03

**Total: ~$1.50/month**

### Cost Reduction Tips

1. **Adjust scan frequency**: Use `rate(7 days)` instead of daily
2. **Reduce log retention**: Set to 7 days for non-production
3. **Use S3 lifecycle policies**: Move old backups to cheaper storage
4. **Optimize Lambda memory**: Start with 256MB if sufficient

## Contributing

### Development Setup

```bash
# Install dependencies
pip3 install -r src/requirements.txt

# Run tests
python3 -m pytest tests/

# Format code
black src/
flake8 src/
```

### Adding New Features

1. Create feature branch
2. Add tests for new functionality
3. Update documentation
4. Submit pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check troubleshooting section
2. Review CloudWatch logs
3. Create GitHub issue with detailed information
4. Include Terraform and Lambda logs
