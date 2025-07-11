"""
Security Group Remediator
Handles remediation of non-compliant security groups
"""

import json
import logging
import boto3
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from botocore.exceptions import ClientError

from utils.exceptions import ComplianceError, AWSServiceError, PolicyViolation
from config_manager import ConfigManager
from utils.helpers import get_ec2_client

class SecurityGroupRemediator:
    """Handles remediation of security group compliance violations"""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize SecurityGroupRemediator
        
        Args:
            config_manager: ConfigManager instance for loading policies
        """
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # AWS clients will be initialized per account
        self.ec2_client = None
        self.s3_client = boto3.client('s3')
        self.sns_client = boto3.client('sns')
        self.sts_client = boto3.client('sts')
        
        # Configuration
        import os
        self.cross_account_role_name = os.environ.get('CROSS_ACCOUNT_ROLE_NAME', '')
        self.external_id = os.environ.get('EXTERNAL_ID', '')
        self.s3_bucket = os.environ.get('S3_BUCKET_NAME', '')
        self.sns_topic_arn = os.environ.get('SNS_TOPIC_ARN', '')
        self.dry_run_mode = os.environ.get('DRY_RUN_MODE', 'true').lower() == 'true'

        # Load initial config
        self.config = self.config_manager.load_framework_config()
        self.settings = self.config_manager.load_framework_settings()
    
    def remediate_violations(
        self, 
        account_id: str, 
        violations: List[Dict[str, Any]], 
        policies: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Remediate compliance violations for an account
        
        Args:
            account_id: AWS account ID
            violations: List of violations to remediate
            policies: Security compliance policies
            
        Returns:
            Dictionary containing remediation results
        """
        self.logger.info(f"Starting remediation for account {account_id} with {len(violations)} violations")
        
        remediation_start_time = datetime.now(timezone.utc)
        
        try:
            # Assume role for cross-account access if needed
            self._assume_account_role(account_id)
            
            # Group violations by security group
            violations_by_sg = self._group_violations_by_sg(violations)
            
            remediation_results = []
            total_remediations = 0
            
            for sg_id, sg_violations in violations_by_sg.items():
                try:
                    self.logger.info(f"Remediating security group: {sg_id}")
                    
                    # Backup current security group state
                    backup_result = self._backup_security_group(account_id, sg_id)
                    
                    # Apply remediation
                    sg_remediation = self._remediate_security_group(
                        account_id, sg_id, sg_violations, policies
                    )
                    
                    sg_remediation['backup_location'] = backup_result.get('backup_location')
                    remediation_results.append(sg_remediation)
                    
                    if sg_remediation.get('status') == 'success':
                        total_remediations += 1
                        
                        # Log remediation action
                        self.logger.warning(
                            f"Applied remediation to security group {sg_id}",
                            extra={
                                'event_type': 'REMEDIATION_APPLIED',
                                'account_id': account_id,
                                'security_group_id': sg_id,
                                'violations_count': len(sg_violations),
                                'backup_location': backup_result.get('backup_location')
                            }
                        )
                    
                except Exception as e:
                    self.logger.error(f"Failed to remediate security group {sg_id}: {str(e)}")
                    remediation_results.append({
                        'security_group_id': sg_id,
                        'status': 'error',
                        'error_message': str(e),
                        'violations_count': len(sg_violations)
                    })
            
            # Calculate remediation duration
            remediation_duration = (datetime.now(timezone.utc) - remediation_start_time).total_seconds()
            
            # Send notifications
            self._send_remediation_notifications(account_id, remediation_results)
            
            return {
                'account_id': account_id,
                'remediation_timestamp': remediation_start_time.isoformat(),
                'remediation_duration_seconds': remediation_duration,
                'total_violations': len(violations),
                'remediations_applied': total_remediations,
                'remediation_results': remediation_results,
                'status': 'completed'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to remediate violations in account {account_id}: {str(e)}")
            return {
                'account_id': account_id,
                'remediation_timestamp': remediation_start_time.isoformat(),
                'status': 'error',
                'error_message': str(e),
                'remediations_applied': 0
            }
    
    def _remediate_security_group(
        self, 
        account_id: str, 
        sg_id: str, 
        violations: List[Dict[str, Any]], 
        policies: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Remediate a single security group
        
        Args:
            account_id: AWS account ID
            sg_id: Security group ID
            violations: List of violations for this security group
            policies: Security compliance policies
            
        Returns:
            Dictionary containing remediation results for the security group
        """
        try:
            # Get current security group details
            if not self.ec2_client:
                self.ec2_client = boto3.client('ec2')
            response = self.ec2_client.describe_security_groups(GroupIds=[sg_id])
            security_group = response['SecurityGroups'][0]
            
            self.logger.info(f"Starting remediation for security group {sg_id}")
            
            # Determine enforcement mode for account
            mode = self.config_manager.get_account_mode(account_id)

            # Apply compliance tags
            self._apply_compliance_tags(sg_id, violations)

            actions = ['applied_compliance_tags']

            if mode != 'monitor' and self.settings.get('remove_rules', True):
                # Remove all inbound rules
                self._remove_all_inbound_rules(sg_id, security_group)

                # Remove all outbound rules (except default)
                self._remove_all_outbound_rules(sg_id, security_group)
                actions.extend(['removed_all_inbound_rules', 'removed_all_outbound_rules'])

                if self.settings.get('add_dummy_rule', True):
                    # Add dummy rule with violation information
                    self._add_dummy_violation_rule(sg_id, violations, policies)
                    actions.append('added_dummy_violation_rule')

            status = 'success' if mode != 'monitor' else 'monitored'

            return {
                'security_group_id': sg_id,
                'status': status,
                'actions_taken': actions,
                'violations_count': len(violations),
                'remediation_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except ClientError as e:
            self.logger.error(f"AWS error remediating security group {sg_id}: {str(e)}")
            return {
                'security_group_id': sg_id,
                'status': 'error',
                'error_message': f"AWS error: {str(e)}",
                'violations_count': len(violations)
            }
        except Exception as e:
            self.logger.error(f"Unexpected error remediating security group {sg_id}: {str(e)}")
            return {
                'security_group_id': sg_id,
                'status': 'error',
                'error_message': f"Unexpected error: {str(e)}",
                'violations_count': len(violations)
            }
    
    def emergency_remediate_security_group(self, security_group: Dict[str, Any], 
                                          violations: List[PolicyViolation], 
                                          backup_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Emergency remediation - remove ALL rules and add dummy rule for critical violations.
        This is more aggressive than regular remediation.
        """
        try:
            group_id = security_group['GroupId']
            self.logger.warning(f"EMERGENCY remediation on security group {group_id}")
            
            remediation_summary = {
                'group_id': group_id,
                'emergency_action': True,
                'violations_found': len(violations),
                'actions_taken': [],
                'errors': []
            }
            
            if self.dry_run_mode:
                self.logger.info(f"DRY RUN: Would perform emergency remediation on {group_id}")
                remediation_summary['dry_run'] = True
                remediation_summary['actions_taken'].append('DRY RUN: Emergency remediation would remove ALL rules')
                return remediation_summary
            
            ec2_client = self._get_ec2_client(security_group.get('Region', 'us-east-1'))
            
            # Remove ALL inbound rules
            if security_group.get('IpPermissions'):
                try:
                    ec2_client.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=security_group['IpPermissions']
                    )
                    remediation_summary['actions_taken'].append(f"Removed ALL {len(security_group['IpPermissions'])} inbound rules")
                    self.logger.warning(f"EMERGENCY: Removed ALL inbound rules from {group_id}")
                except Exception as e:
                    error_msg = f"Failed to remove inbound rules: {str(e)}"
                    remediation_summary['errors'].append(error_msg)
                    self.logger.error(error_msg)
            
            # Remove ALL outbound rules (except default allow-all for VPC SGs)
            if security_group.get('IpPermissionsEgress'):
                # Keep only the default VPC rule if it exists
                default_vpc_rule = None
                rules_to_remove = []
                
                for rule in security_group['IpPermissionsEgress']:
                    # Check if this is the default VPC outbound rule
                    if (rule.get('IpProtocol') == '-1' and 
                        rule.get('IpRanges') and 
                        len(rule['IpRanges']) == 1 and 
                        rule['IpRanges'][0].get('CidrIp') == '0.0.0.0/0'):
                        default_vpc_rule = rule
                    else:
                        rules_to_remove.append(rule)
                
                if rules_to_remove:
                    try:
                        ec2_client.revoke_security_group_egress(
                            GroupId=group_id,
                            IpPermissions=rules_to_remove
                        )
                        remediation_summary['actions_taken'].append(f"Removed {len(rules_to_remove)} outbound rules")
                        self.logger.warning(f"EMERGENCY: Removed {len(rules_to_remove)} outbound rules from {group_id}")
                    except Exception as e:
                        error_msg = f"Failed to remove outbound rules: {str(e)}"
                        remediation_summary['errors'].append(error_msg)
                        self.logger.error(error_msg)
            
            # Add emergency dummy rule
            dummy_rule_config = self.config.get('compliance_policies', {}).get(
                'compliance_actions', {}
            ).get('violation_handling', {}).get('dummy_rule_config', {})
            
            violation_reasons = [v.rule_id for v in violations]
            emergency_description = (
                f"🚨 EMERGENCY LOCKDOWN - CRITICAL VIOLATIONS DETECTED 🚨 "
                f"ALL rules removed due to: {', '.join(violation_reasons[:3])}. "
                f"Contact Security Team IMMEDIATELY. "
                f"Original rules backed up with ID: {backup_result.get('backup_id', 'unknown')}"
            )[:255]  # EC2 description limit
            
            dummy_rule = {
                'IpPermissions': [{
                    'IpProtocol': dummy_rule_config.get('protocol', 'tcp'),
                    'FromPort': dummy_rule_config.get('from_port', 65535),
                    'ToPort': dummy_rule_config.get('to_port', 65535),
                    'IpRanges': [{'CidrIp': '127.0.0.1/32', 'Description': emergency_description}]
                }]
            }
            
            try:
                ec2_client.authorize_security_group_ingress(
                    GroupId=group_id,
                    **dummy_rule
                )
                remediation_summary['actions_taken'].append("Added emergency lockdown dummy rule")
                self.logger.warning(f"EMERGENCY: Added lockdown dummy rule to {group_id}")
            except Exception as e:
                error_msg = f"Failed to add emergency dummy rule: {str(e)}"
                remediation_summary['errors'].append(error_msg)
                self.logger.error(error_msg)
            
            # Tag the security group with emergency status
            try:
                emergency_tags = [
                    {
                        'Key': 'COMPLIANCE_STATUS',
                        'Value': 'EMERGENCY_LOCKDOWN'
                    },
                    {
                        'Key': 'EMERGENCY_REASON',
                        'Value': f"Critical violations: {', '.join(violation_reasons[:3])}"[:255]
                    },
                    {
                        'Key': 'EMERGENCY_TIMESTAMP',
                        'Value': datetime.utcnow().isoformat()
                    },
                    {
                        'Key': 'BACKUP_ID',
                        'Value': backup_result.get('backup_id', 'unknown')
                    }
                ]
                
                ec2_client.create_tags(
                    Resources=[group_id],
                    Tags=emergency_tags
                )
                remediation_summary['actions_taken'].append("Tagged with emergency lockdown status")
                
            except Exception as e:
                error_msg = f"Failed to tag security group: {str(e)}"
                remediation_summary['errors'].append(error_msg)
                self.logger.error(error_msg)
            
            # Send critical metrics
            self._send_remediation_metrics(group_id, len(violations), 'emergency', remediation_summary)
            
            self.logger.warning(f"EMERGENCY remediation completed for {group_id}: {remediation_summary}")
            return remediation_summary
            
        except Exception as e:
            self.logger.error(f"CRITICAL ERROR in emergency remediation for {security_group.get('GroupId')}: {str(e)}")
            raise ComplianceError(f"Emergency remediation failed: {str(e)}")
    
    def _apply_compliance_tags(self, sg_id: str, violations: List[Dict[str, Any]]) -> None:
        """Apply compliance tags to the security group"""
        try:
            # Prepare tags
            status_key = self.settings.get('non_compliant_tag_key', 'COMPLIANCE_STATUS')
            reason_key = self.settings.get('violation_reason_tag_key', 'COMPLIANCE_VIOLATION_REASON')

            compliance_tags = [
                {
                    'Key': status_key,
                    'Value': 'NON_COMPLIANT'
                },
                {
                    'Key': 'COMPLIANCE_VIOLATION_COUNT',
                    'Value': str(len(violations))
                },
                {
                    'Key': 'COMPLIANCE_LAST_SCAN',
                    'Value': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                },
                {
                    'Key': 'COMPLIANCE_REMEDIATED',
                    'Value': 'true'
                },
                {
                    'Key': reason_key,
                    'Value': self._get_primary_violation_reason(violations)
                }
            ]
            
            # Apply tags
            if not self.ec2_client:
                self.ec2_client = boto3.client('ec2')
            self.ec2_client.create_tags(
                Resources=[sg_id],
                Tags=compliance_tags
            )
            
            self.logger.info(f"Applied compliance tags to security group {sg_id}")
            
        except ClientError as e:
            self.logger.error(f"Failed to apply compliance tags to {sg_id}: {str(e)}")
            raise
    
    def _remove_all_inbound_rules(self, sg_id: str, security_group: Dict[str, Any]) -> None:
        """Remove all inbound rules from the security group"""
        try:
            inbound_rules = security_group.get('IpPermissions', [])
            
            if inbound_rules:
                if not self.ec2_client:
                    self.ec2_client = boto3.client('ec2')
                self.ec2_client.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=inbound_rules
                )
                
                self.logger.info(f"Removed {len(inbound_rules)} inbound rules from {sg_id}")
            else:
                self.logger.info(f"No inbound rules to remove from {sg_id}")
                
        except ClientError as e:
            self.logger.error(f"Failed to remove inbound rules from {sg_id}: {str(e)}")
            raise
    
    def _remove_all_outbound_rules(self, sg_id: str, security_group: Dict[str, Any]) -> None:
        """Remove all outbound rules from the security group (except default deny)"""
        try:
            outbound_rules = security_group.get('IpPermissionsEgress', [])
            
            # Filter out the default deny rule (if it exists)
            rules_to_remove = [
                rule for rule in outbound_rules
                if not self._is_default_deny_rule(rule)
            ]
            
            if rules_to_remove:
                if not self.ec2_client:
                    self.ec2_client = boto3.client('ec2')
                self.ec2_client.revoke_security_group_egress(
                    GroupId=sg_id,
                    IpPermissions=rules_to_remove
                )
                
                self.logger.info(f"Removed {len(rules_to_remove)} outbound rules from {sg_id}")
            else:
                self.logger.info(f"No outbound rules to remove from {sg_id}")
                
        except ClientError as e:
            self.logger.error(f"Failed to remove outbound rules from {sg_id}: {str(e)}")
            raise
    
    def _add_dummy_violation_rule(
        self, 
        sg_id: str, 
        violations: List[Dict[str, Any]], 
        policies: Dict[str, Any]
    ) -> None:
        """Add a dummy rule explaining why all rules were removed"""
        try:
            # Get dummy rule configuration from policies
            dummy_rule_config = policies['compliance_policies']['compliance_actions']['violation_handling']['dummy_rule_config']
            
            # Format violation reason
            violation_reasons = [v.get('reason', 'Policy violation') for v in violations]
            violation_reason = '; '.join(list(set(violation_reasons))[:3])  # Limit to first 3 unique reasons
            
            description = dummy_rule_config['description'].format(violation_reason=violation_reason)
            prefix = self.settings.get('dummy_rule_prefix')
            if prefix:
                description = f"{prefix} {description}"
            
            # Truncate description if too long (EC2 limit is 255 characters)
            if len(description) > 255:
                description = description[:252] + "..."
            
            # Add the dummy inbound rule
            dummy_rule = {
                'IpProtocol': dummy_rule_config['protocol'],
                'FromPort': dummy_rule_config['from_port'],
                'ToPort': dummy_rule_config['to_port'],
                'IpRanges': [
                    {
                        'CidrIp': dummy_rule_config['cidr_blocks'][0],
                        'Description': description
                    }
                ]
            }
            
            if not self.ec2_client:
                self.ec2_client = boto3.client('ec2')
            self.ec2_client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[dummy_rule]
            )
            
            self.logger.info(f"Added dummy violation rule to {sg_id}")
            
        except ClientError as e:
            self.logger.error(f"Failed to add dummy rule to {sg_id}: {str(e)}")
            # Don't raise here - this is not critical for remediation
    
    def _backup_security_group(self, account_id: str, sg_id: str) -> Dict[str, Any]:
        """Create a backup of the security group configuration"""
        try:
            # Get current security group configuration
            if not self.ec2_client:
                self.ec2_client = boto3.client('ec2')
            response = self.ec2_client.describe_security_groups(GroupIds=[sg_id])
            security_group = response['SecurityGroups'][0]
            
            # Prepare backup data
            backup_data = {
                'backup_timestamp': datetime.now(timezone.utc).isoformat(),
                'account_id': account_id,
                'security_group': security_group,
                'backup_reason': 'compliance_remediation'
            }
            
            # Save to S3
            timestamp = datetime.now(timezone.utc).strftime('%Y/%m/%d/%H')
            s3_key = f"backups/{account_id}/{timestamp}/{sg_id}_backup.json"
            
            self.s3_client.put_object(
                Bucket=self.s3_bucket,
                Key=s3_key,
                Body=json.dumps(backup_data, indent=2, default=str),
                ContentType='application/json',
                Metadata={
                    'backup-type': 'security-group',
                    'account-id': account_id,
                    'security-group-id': sg_id,
                    'backup-reason': 'compliance-remediation'
                }
            )
            
            self.logger.info(f"Created backup for security group {sg_id} at s3://{self.s3_bucket}/{s3_key}")
            
            return {
                'status': 'success',
                'backup_location': f"s3://{self.s3_bucket}/{s3_key}",
                's3_key': s3_key
            }
            
        except Exception as e:
            self.logger.error(f"Failed to backup security group {sg_id}: {str(e)}")
            return {
                'status': 'error',
                'error_message': str(e)
            }
    
    def _group_violations_by_sg(self, violations: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group violations by security group ID"""
        violations_by_sg = {}
        
        for violation in violations:
            sg_id = violation.get('security_group_id')
            if sg_id:
                if sg_id not in violations_by_sg:
                    violations_by_sg[sg_id] = []
                violations_by_sg[sg_id].append(violation)
        
        return violations_by_sg
    
    def _get_primary_violation_reason(self, violations: List[Dict[str, Any]]) -> str:
        """Get the primary violation reason for tagging"""
        if not violations:
            return "Unknown violation"
        
        # Get the highest severity violation reason
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        
        sorted_violations = sorted(
            violations,
            key=lambda v: severity_order.get(v.get('severity', 'low'), 3)
        )
        
        primary_violation = sorted_violations[0]
        reason = primary_violation.get('reason', primary_violation.get('description', 'Policy violation'))
        
        # Truncate if too long for tag value (256 character limit)
        if len(reason) > 256:
            reason = reason[:253] + "..."
        
        return reason
    
    def _is_default_deny_rule(self, rule: Dict[str, Any]) -> bool:
        """Check if a rule is the default deny rule"""
        # Default deny rule typically allows all traffic to 0.0.0.0/0
        # We want to keep this if it exists
        return (
            rule.get('IpProtocol') == '-1' and
            any(
                ip_range.get('CidrIp') == '0.0.0.0/0'
                for ip_range in rule.get('IpRanges', [])
            )
        )
    
    def _send_remediation_notifications(self, account_id: str, remediation_results: List[Dict[str, Any]]) -> None:
        """Send notifications about remediation actions"""
        try:
            if not self.sns_topic_arn:
                self.logger.warning("No SNS topic configured for remediation notifications")
                return
            
            successful_remediations = [r for r in remediation_results if r.get('status') == 'success']
            failed_remediations = [r for r in remediation_results if r.get('status') == 'error']
            
            message = {
                'event_type': 'REMEDIATION_COMPLETED',
                'account_id': account_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'summary': {
                    'total_security_groups': len(remediation_results),
                    'successful_remediations': len(successful_remediations),
                    'failed_remediations': len(failed_remediations)
                },
                'successful_remediations': [
                    {
                        'security_group_id': r['security_group_id'],
                        'violations_count': r['violations_count'],
                        'backup_location': r.get('backup_location')
                    }
                    for r in successful_remediations
                ],
                'failed_remediations': [
                    {
                        'security_group_id': r['security_group_id'],
                        'error_message': r['error_message']
                    }
                    for r in failed_remediations
                ]
            }
            
            self.sns_client.publish(
                TopicArn=self.sns_topic_arn,
                Subject=f"Security Group Remediation Completed - Account {account_id}",
                Message=json.dumps(message, indent=2, default=str)
            )
            
            self.logger.info(f"Sent remediation notification for account {account_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to send remediation notifications: {str(e)}")
    
    def _assume_account_role(self, account_id: str) -> None:
        """Assume cross-account role and initialize the EC2 client."""
        try:
            if not self.cross_account_role_name:
                self.ec2_client = get_ec2_client(account_id, 'us-east-1')
            else:
                session_name = f"ComplianceRemediator-{account_id}"
                self.ec2_client = get_ec2_client(
                    account_id,
                    'us-east-1',
                    role_name=self.cross_account_role_name,
                    session_name=session_name,
                    external_id=self.external_id,
                )
            self.logger.info(f"Successfully assumed role for remediation in account {account_id}")
        except Exception as e:
            self.logger.error(f"Error assuming role for account {account_id}: {e}")
            raise AWSServiceError(f"Failed to assume role: {e}")
    
    def _get_ec2_client(self, region: str = 'us-east-1'):
        """Get EC2 client for the specified region"""
        if not self.ec2_client:
            self.ec2_client = boto3.client('ec2', region_name=region)
        return self.ec2_client
    
    def _send_remediation_metrics(self, group_id: str, violation_count: int, action_type: str, summary: Dict[str, Any]):
        """Send remediation metrics to CloudWatch"""
        try:
            # This would integrate with your metrics system
            self.logger.info(f"Remediation metrics: {group_id}, violations: {violation_count}, action: {action_type}")
        except Exception as e:
            self.logger.error(f"Error sending remediation metrics: {e}")
