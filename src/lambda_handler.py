"""
AWS Security Group Compliance Scanner Lambda Handler
Enhanced version with real-time scanning capabilities
"""

import json
import logging
import os
import boto3
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Import our modules
from compliance_scanner import ComplianceScanner
from config_manager import ConfigManager
from sg_remediator import SecurityGroupRemediator
from utils.logger import setup_logger
from utils.metrics import MetricsCollector
from utils.exceptions import ComplianceError
from utils.helpers import get_ec2_client, assume_role

# Setup module-level logger
logger = setup_logger('compliance_scanner', os.environ.get('LOG_LEVEL', 'INFO'))


class SecurityGroupComplianceHandler:
    """Main handler for Security Group Compliance operations."""
    
    def __init__(self):
        """Initialize the compliance handler."""
        self.config_manager = ConfigManager(
            s3_bucket=os.environ.get('S3_BUCKET_NAME', '')
        )
        self.scanner = ComplianceScanner(self.config_manager)
        self.remediator = SecurityGroupRemediator(self.config_manager)
        self.metrics = MetricsCollector()
        
        # AWS clients
        self.sts_client = boto3.client('sts')
        self.sns_client = boto3.client('sns')
        
        # Configuration
        self.sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        self.dry_run_mode = os.environ.get('DRY_RUN_MODE', 'true').lower() == 'true'
        self.cross_account_role_name = os.environ.get('CROSS_ACCOUNT_ROLE_NAME', 'SecurityGroupComplianceRole')
    
    def handle_real_time_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle real-time events from EventBridge for immediate scanning."""
        try:
            event_type = event.get('event_type')
            priority = event.get('priority', 'medium')
            scan_config = event.get('scan_config', {})
            event_details = event.get('event_details', {})
            
            logger.info(f"Processing real-time event: {event_type} with priority {priority}")
            
            if event_type == 'new_security_group_created':
                return self._handle_new_security_group(scan_config, event_details)
            elif event_type == 'risky_rule_added':
                return self._handle_risky_rule_addition(scan_config, event_details)
            else:
                logger.warning(f"Unknown real-time event type: {event_type}")
                return {
                    'statusCode': 400,
                    'body': {'error': f'Unknown event type: {event_type}'}
                }
                
        except Exception as e:
            logger.error(f"Error handling real-time event: {str(e)}")
            raise
    
    def _handle_new_security_group(self, scan_config: Dict[str, Any], 
                                  event_details: Dict[str, Any]) -> Dict[str, Any]:
        """Handle newly created security group."""
        try:
            account_id = event_details.get('account_id')
            region = event_details.get('region')
            group_id = event_details.get('group_id')
            group_name = event_details.get('group_name')
            
            # Validate required parameters
            if not account_id or not region or not group_id:
                return {
                    'statusCode': 400,
                    'body': {'error': 'Missing required parameters: account_id, region, or group_id'}
                }
            
            # Ensure parameters are strings
            account_id = str(account_id)
            region = str(region)
            group_id = str(group_id)
            group_name = str(group_name) if group_name else ''
            
            logger.info(f"Scanning newly created security group: {group_id} in {account_id}/{region}")
            
            # Get the security group details
            ec2_client = self._get_ec2_client(account_id, region)
            
            try:
                response = ec2_client.describe_security_groups(GroupIds=[group_id])
                security_groups = response['SecurityGroups']
                
                if not security_groups:
                    logger.warning(f"Security group {group_id} not found")
                    return {
                        'statusCode': 404,
                        'body': {'error': f'Security group {group_id} not found'}
                    }
                
                sg = security_groups[0]
                
                # Scan for violations
                policies = self.config_manager.load_security_policies()
                account_config = self.config_manager.get_account_specific_config(account_id)
                exemptions = self.config_manager.get_exemptions(account_id, sg['GroupId'])
                scan_config_params = {'regions': [region], 'account_id': account_id}
                violations = self.scanner._scan_security_group(sg, policies, account_config, exemptions, scan_config_params)
                
                if violations:
                    logger.warning(f"New security group {group_id} has {len(violations)} violations")
                    
                    # Tag as non-compliant
                    self._tag_non_compliant_sg(ec2_client, group_id, violations)
                    
                    # Check if immediate remediation is enabled
                    if scan_config.get('enable_automatic_remediation', False):
                        remediation_result = self._perform_immediate_remediation(
                            ec2_client, sg, violations, event_details
                        )
                        
                        return {
                            'statusCode': 200,
                            'body': {
                                'message': 'New security group scanned and remediated',
                                'group_id': group_id,
                                'violations_found': len(violations),
                                'violations': violations,
                                'remediation_result': remediation_result
                            }
                        }
                    else:
                        # Send alert for manual review
                        self._send_new_sg_alert(group_id, group_name, violations, event_details)
                        
                        return {
                            'statusCode': 200,
                            'body': {
                                'message': 'New security group violations detected, alert sent',
                                'group_id': group_id,
                                'violations_found': len(violations),
                                'violations': violations
                            }
                        }
                else:
                    logger.info(f"New security group {group_id} is compliant")
                    return {
                        'statusCode': 200,
                        'body': {
                            'message': 'New security group is compliant',
                            'group_id': group_id
                        }
                    }
                    
            except Exception as e:
                logger.error(f"Error scanning new security group {group_id}: {e}")
                raise
                
        except Exception as e:
            logger.error(f"Error handling new security group: {e}")
            raise
    
    def _handle_risky_rule_addition(self, scan_config: Dict[str, Any], 
                                   event_details: Dict[str, Any]) -> Dict[str, Any]:
        """Handle risky rule addition to security group."""
        try:
            account_id = event_details.get('account_id')
            region = event_details.get('region')
            group_id = event_details.get('group_id')
            
            # Validate required parameters
            if not account_id or not region or not group_id:
                return {
                    'statusCode': 400,
                    'body': {'error': 'Missing required parameters: account_id, region, or group_id'}
                }
            
            # Ensure parameters are strings
            account_id = str(account_id)
            region = str(region)
            group_id = str(group_id)
            
            logger.warning(f"Risky rule detected in security group: {group_id} in {account_id}/{region}")
            
            # Get the security group details
            ec2_client = self._get_ec2_client(account_id, region)
            
            try:
                response = ec2_client.describe_security_groups(GroupIds=[group_id])
                security_groups = response['SecurityGroups']
                
                if not security_groups:
                    logger.warning(f"Security group {group_id} not found")
                    return {
                        'statusCode': 404,
                        'body': {'error': f'Security group {group_id} not found'}
                    }
                
                sg = security_groups[0]
                
                # Scan for violations with focus on critical ones
                policies = self.config_manager.load_security_policies()
                account_config = self.config_manager.get_account_specific_config(account_id)
                exemptions = self.config_manager.get_exemptions(account_id, sg['GroupId'])
                scan_config_params = {'regions': [region], 'account_id': account_id}
                violations = self.scanner._scan_security_group(sg, policies, account_config, exemptions, scan_config_params)
                critical_violations = [v for v in violations if v.get('severity') == 'critical']
                
                if critical_violations:
                    logger.error(f"Critical violations found in security group {group_id}")
                    
                    # Immediate action for critical violations
                    if scan_config.get('enable_automatic_remediation', False):
                        remediation_result = self._perform_emergency_remediation(
                            ec2_client, sg, critical_violations, event_details
                        )
                        
                        return {
                            'statusCode': 200,
                            'body': {
                                'message': 'Critical violations remediated immediately',
                                'group_id': group_id,
                                'critical_violations': len(critical_violations),
                                'remediation_result': remediation_result
                            }
                        }
                    else:
                        # Send immediate alert
                        self._send_critical_violation_alert(group_id, critical_violations, event_details)
                        
                        return {
                            'statusCode': 200,
                            'body': {
                                'message': 'Critical violations detected, immediate alert sent',
                                'group_id': group_id,
                                'critical_violations': len(critical_violations),
                                'violations': critical_violations
                            }
                        }
                else:
                    logger.info(f"No critical violations found in security group {group_id}")
                    return {
                        'statusCode': 200,
                        'body': {
                            'message': 'No critical violations found',
                            'group_id': group_id,
                            'total_violations': len(violations)
                        }
                    }
                    
            except Exception as e:
                logger.error(f"Error scanning security group {group_id}: {e}")
                raise
                
        except Exception as e:
            logger.error(f"Error handling risky rule addition: {e}")
            raise
    
    def scan_all_accounts(self) -> Dict[str, Any]:
        """Scan all configured accounts for compliance."""
        try:
            scan_start_time = datetime.now(timezone.utc)
            
            # Load configuration
            framework_config = self.config_manager.load_framework_config()
            accounts_config = framework_config.get('accounts_config', [])
            
            total_violations = 0
            total_security_groups = 0
            scan_results = {}
            
            for account_config in accounts_config:
                account_id = account_config.get('account_id')
                regions = account_config.get('regions', ['us-east-1'])
                
                logger.info(f"Scanning account {account_id} in regions: {regions}")
                
                account_result = self.scan_single_account(account_id, regions)
                scan_results[account_id] = account_result
                
                total_violations += account_result.get('total_violations', 0)
                total_security_groups += account_result.get('total_security_groups', 0)
            
            scan_duration = (datetime.now(timezone.utc) - scan_start_time).total_seconds()
            
            # Send metrics
            self.metrics.record_scan_metrics({
                'total_violations_found': total_violations,
                'security_groups_scanned': total_security_groups,
                'scan_duration_seconds': scan_duration,
                'accounts_scanned': len(accounts_config),
                'account_results': list(scan_results.values())
            })
            
            return {
                'statusCode': 200,
                'body': {
                    'message': 'Multi-account compliance scan completed',
                    'scan_summary': {
                        'total_accounts_scanned': len(accounts_config),
                        'total_security_groups': total_security_groups,
                        'total_violations': total_violations,
                        'scan_duration_seconds': scan_duration
                    },
                    'account_results': scan_results
                }
            }
            
        except Exception as e:
            logger.error(f"Error in multi-account scan: {e}")
            raise
    
    def scan_single_account(self, account_id: str, regions: List[str]) -> Dict[str, Any]:
        """Scan a single account for compliance."""
        try:
            # Assume role in target account if different from current
            current_account = self.sts_client.get_caller_identity()['Account']
            
            if account_id != current_account:
                assumed_role_credentials = self._assume_role(account_id)
            else:
                assumed_role_credentials = None
            
            account_violations = 0
            account_security_groups = 0
            region_results = {}
            
            for region in regions:
                logger.info(f"Scanning region {region} in account {account_id}")
                
                region_result = self._scan_region(account_id, region, assumed_role_credentials)
                region_results[region] = region_result
                
                account_violations += region_result.get('violations_count', 0)
                account_security_groups += region_result.get('security_groups_count', 0)
            
            return {
                'account_id': account_id,
                'total_violations': account_violations,
                'total_security_groups': account_security_groups,
                'region_results': region_results
            }
            
        except Exception as e:
            logger.error(f"Error scanning account {account_id}: {e}")
            raise
    
    def _assume_role(self, account_id: str) -> Dict[str, Any]:
        """Assume cross-account role."""
        try:
            session_name = f"SecurityGroupCompliance-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            return assume_role(
                account_id,
                self.cross_account_role_name,
                session_name,
            )
        except Exception as e:
            logger.error(f"Error assuming role in account {account_id}: {e}")
            raise
    
    def _get_ec2_client(self, account_id: str, region: str):
        """Get EC2 client for the specified account and region."""
        return get_ec2_client(
            account_id,
            region,
            role_name=self.cross_account_role_name,
            session_name=f"SecurityGroupCompliance-{account_id}",
        )
    
    def _scan_region(self, account_id: str, region: str, assumed_role_credentials: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan all security groups in a region."""
        try:
            if assumed_role_credentials:
                ec2_client = boto3.client(
                    'ec2',
                    region_name=region,
                    aws_access_key_id=assumed_role_credentials['AccessKeyId'],
                    aws_secret_access_key=assumed_role_credentials['SecretAccessKey'],
                    aws_session_token=assumed_role_credentials['SessionToken']
                )
            else:
                ec2_client = boto3.client('ec2', region_name=region)
            
            # Get all security groups
            paginator = ec2_client.get_paginator('describe_security_groups')
            
            violations_count = 0
            security_groups_count = 0
            violating_groups = []
            
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    security_groups_count += 1
                    
                    # Scan security group
                    policies = self.config_manager.load_security_policies()
                    account_config = self.config_manager.get_account_specific_config(account_id)
                    exemptions = self.config_manager.get_exemptions(account_id, sg['GroupId'])
                    scan_config_params = {'regions': [region], 'account_id': account_id}
                    violations = self.scanner._scan_security_group(sg, policies, account_config, exemptions, scan_config_params)
                    
                    if violations:
                        violations_count += len(violations)
                        violating_groups.append({
                            'group_id': sg['GroupId'],
                            'group_name': sg.get('GroupName', ''),
                            'violations': violations
                        })
                        
                        # Tag as non-compliant
                        if not self.dry_run_mode:
                            self._tag_non_compliant_sg(ec2_client, sg['GroupId'], violations)
            
            return {
                'region': region,
                'security_groups_count': security_groups_count,
                'violations_count': violations_count,
                'violating_groups': violating_groups
            }
            
        except Exception as e:
            logger.error(f"Error scanning region {region} in account {account_id}: {e}")
            raise
    
    def _tag_non_compliant_sg(self, ec2_client, group_id: str, violations: List) -> None:
        """Tag security group as non-compliant."""
        try:
            violation_summary = f"{len(violations)} violations: " + ", ".join([
                f"{v.rule_id}({v.severity})" for v in violations[:3]
            ])
            if len(violations) > 3:
                violation_summary += f" +{len(violations) - 3} more"
            
            tags = [
                {
                    'Key': 'COMPLIANCE_STATUS',
                    'Value': 'NON_COMPLIANT'
                },
                {
                    'Key': 'COMPLIANCE_VIOLATIONS',
                    'Value': violation_summary[:255]  # AWS tag value limit
                },
                {
                    'Key': 'COMPLIANCE_CHECK_TIME',
                    'Value': datetime.utcnow().isoformat()
                }
            ]
            
            ec2_client.create_tags(
                Resources=[group_id],
                Tags=tags
            )
            
            logger.info(f"Tagged security group {group_id} as non-compliant")
            
        except Exception as e:
            logger.error(f"Error tagging security group {group_id}: {e}")
    
    def _perform_immediate_remediation(self, ec2_client, sg: Dict[str, Any], 
                                     violations: List, event_details: Dict[str, Any]) -> Dict[str, Any]:
        """Perform immediate remediation on newly created security group."""
        try:
            # Check severity threshold
            severity_threshold = os.getenv('VIOLATION_SEVERITY_THRESHOLD', 'critical')
            critical_violations = [
                v for v in violations 
                if self._is_severity_above_threshold(v.get('severity', 'low'), severity_threshold)
            ]
            
            if not critical_violations:
                return {
                    'action': 'no_immediate_action',
                    'reason': f'No violations above {severity_threshold} threshold'
                }
            
            # Get account_id and load policies
            account_id = event_details.get('account_id', '')
            policies = self.config_manager.load_security_policies()
            
            # Backup and remediate
            backup_result = self.remediator._backup_security_group(str(account_id), sg['GroupId'])
            remediation_result = self.remediator._remediate_security_group(
                str(account_id), sg['GroupId'], critical_violations, policies
            )
            
            # Send notification
            self._send_immediate_remediation_alert(sg, critical_violations, event_details)
            
            return {
                'action': 'immediate_remediation_completed',
                'violations_remediated': len(critical_violations),
                'backup_id': backup_result.get('backup_id'),
                'remediation_details': remediation_result
            }
            
        except Exception as e:
            logger.error(f"Error in immediate remediation: {e}")
            return {
                'action': 'immediate_remediation_failed',
                'error': str(e)
            }
    
    def _perform_emergency_remediation(self, ec2_client, sg: Dict[str, Any], 
                                     critical_violations: List, event_details: Dict[str, Any]) -> Dict[str, Any]:
        """Perform emergency remediation for critical violations."""
        try:
            # This is more aggressive - immediately remove all violating rules
            logger.warning(f"Performing emergency remediation on {sg['GroupId']}")
            
            # Get account_id
            account_id = event_details.get('account_id', '')
            
            # Backup first
            backup_result = self.remediator._backup_security_group(str(account_id), sg['GroupId'])
            
            # Remove all rules and add dummy rule
            remediation_result = self.remediator.emergency_remediate_security_group(
                sg, critical_violations, backup_result
            )
            
            # Remove all rules and add dummy rule
            remediation_result = self.remediator.emergency_remediate_security_group(
                sg, critical_violations, backup_result
            )
            
            # Send emergency alert
            self._send_emergency_remediation_alert(sg, critical_violations, event_details)
            
            return {
                'action': 'emergency_remediation_completed',
                'critical_violations_found': len(critical_violations),
                'backup_id': backup_result.get('backup_id'),
                'remediation_details': remediation_result
            }
            
        except Exception as e:
            logger.error(f"Error in emergency remediation: {e}")
            return {
                'action': 'emergency_remediation_failed',
                'error': str(e)
            }
    
    def _is_severity_above_threshold(self, severity: str, threshold: str) -> bool:
        """Check if severity is above threshold."""
        severity_levels = {
            'info': 1, 'low': 2, 'medium': 3, 'high': 4, 'critical': 5
        }
        return severity_levels.get(severity, 0) >= severity_levels.get(threshold, 5)
    
    def _send_new_sg_alert(self, group_id: str, group_name: str, violations: List, 
                          event_details: Dict[str, Any]) -> None:
        """Send alert for new security group violations."""
        try:
            alert_message = {
                'alert_type': 'new_security_group_violations',
                'severity': 'HIGH',
                'timestamp': datetime.utcnow().isoformat(),
                'security_group_id': group_id,
                'security_group_name': group_name,
                'violations_count': len(violations),
                'violations': violations,
                'event_details': event_details,
                'description': f"Newly created security group {group_id} has {len(violations)} compliance violations"
            }
            
            if self.sns_topic_arn:
                self.sns_client.publish(
                    TopicArn=self.sns_topic_arn,
                    Subject=f"🚨 NEW SECURITY GROUP VIOLATIONS - {group_id}",
                    Message=json.dumps(alert_message, indent=2, default=str)
                )
                
        except Exception as e:
            logger.error(f"Error sending new SG alert: {e}")
    
    def _send_critical_violation_alert(self, group_id: str, critical_violations: List, 
                                     event_details: Dict[str, Any]) -> None:
        """Send alert for critical violations."""
        try:
            alert_message = {
                'alert_type': 'critical_security_violations',
                'severity': 'CRITICAL',
                'timestamp': datetime.utcnow().isoformat(),
                'security_group_id': group_id,
                'critical_violations_count': len(critical_violations),
                'violations': critical_violations,
                'event_details': event_details,
                'description': f"CRITICAL security violations detected in {group_id}"
            }
            
            if self.sns_topic_arn:
                self.sns_client.publish(
                    TopicArn=self.sns_topic_arn,
                    Subject=f"🚨🚨 CRITICAL SECURITY VIOLATIONS - {group_id}",
                    Message=json.dumps(alert_message, indent=2, default=str)
                )
                
        except Exception as e:
            logger.error(f"Error sending critical violation alert: {e}")
    
    def _send_immediate_remediation_alert(self, sg: Dict[str, Any], violations: List, 
                                        event_details: Dict[str, Any]) -> None:
        """Send alert for immediate remediation action."""
        try:
            alert_message = {
                'alert_type': 'immediate_remediation_performed',
                'severity': 'HIGH',
                'timestamp': datetime.utcnow().isoformat(),
                'security_group_id': sg['GroupId'],
                'violations_remediated': len(violations),
                'event_details': event_details,
                'description': f"Immediate remediation performed on {sg['GroupId']}"
            }
            
            if self.sns_topic_arn:
                self.sns_client.publish(
                    TopicArn=self.sns_topic_arn,
                    Subject=f"⚡ IMMEDIATE REMEDIATION - {sg['GroupId']}",
                    Message=json.dumps(alert_message, indent=2, default=str)
                )
                
        except Exception as e:
            logger.error(f"Error sending immediate remediation alert: {e}")
    
    def _send_emergency_remediation_alert(self, sg: Dict[str, Any], critical_violations: List, 
                                        event_details: Dict[str, Any]) -> None:
        """Send alert for emergency remediation action."""
        try:
            alert_message = {
                'alert_type': 'emergency_remediation_performed',
                'severity': 'CRITICAL',
                'timestamp': datetime.utcnow().isoformat(),
                'security_group_id': sg['GroupId'],
                'critical_violations_found': len(critical_violations),
                'event_details': event_details,
                'description': f"EMERGENCY remediation performed on {sg['GroupId']}"
            }
            
            if self.sns_topic_arn:
                self.sns_client.publish(
                    TopicArn=self.sns_topic_arn,
                    Subject=f"🚨🚨 EMERGENCY REMEDIATION - {sg['GroupId']}",
                    Message=json.dumps(alert_message, indent=2, default=str)
                )
                
        except Exception as e:
            logger.error(f"Error sending emergency remediation alert: {e}")
    
    def _send_error_notification(self, error_message: str, event: Dict[str, Any]) -> None:
        """Send error notification."""
        try:
            if self.sns_topic_arn:
                self.sns_client.publish(
                    TopicArn=self.sns_topic_arn,
                    Subject="❌ Security Group Compliance Framework Error",
                    Message=json.dumps({
                        'alert_type': 'lambda_error',
                        'severity': 'HIGH',
                        'timestamp': datetime.utcnow().isoformat(),
                        'error_message': error_message,
                        'event': event
                    }, indent=2, default=str)
                )
        except Exception as e:
            logger.error(f"Error sending error notification: {e}")


def lambda_handler(event, context):
    """
    AWS Lambda handler for Security Group Compliance Framework.
    Enhanced with real-time scanning capabilities.
    """
    try:
        logger.info(f"Lambda invoked with event: {json.dumps(event, default=str)}")
        
        # Initialize the handler
        handler = SecurityGroupComplianceHandler()
        
        # Check if this is a real-time event from EventBridge
        if 'event_type' in event:
            # This is a real-time event (new SG created, risky rule added, etc.)
            result = handler.handle_real_time_event(event)
        elif 'source' in event and event['source'] == 'aws.events':
            # This is a scheduled event
            result = handler.scan_all_accounts()
        else:
            # This might be a manual invocation or test event
            if 'scan_config' in event:
                # Custom scan configuration provided
                scan_config = event['scan_config']
                if scan_config.get('scan_scope') == 'single_account':
                    result = handler.scan_single_account(
                        scan_config.get('account_id'),
                        scan_config.get('regions', [])
                    )
                else:
                    result = handler.scan_all_accounts()
            else:
                # Default to full scan
                result = handler.scan_all_accounts()
        
        logger.info(f"Lambda execution completed successfully")
        return result
        
    except Exception as e:
        logger.error(f"Lambda execution failed: {str(e)}")
        
        # Send error notification
        try:
            handler = SecurityGroupComplianceHandler()
            handler._send_error_notification(str(e), event)
        except Exception as notification_error:
            logger.error(f"Failed to send error notification: {notification_error}")
        
        raise e


# Backward compatibility
handler = lambda_handler
