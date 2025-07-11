"""
Security Group Compliance Scanner
Handles scanning security groups across AWS accounts for compliance violations
"""

import json
import logging
import boto3
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from botocore.exceptions import ClientError

from utils.exceptions import ComplianceError, AWSServiceError
from config_manager import ConfigManager
from utils.helpers import get_ec2_client

class ComplianceScanner:
    """Scans security groups for compliance violations"""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize ComplianceScanner
        
        Args:
            config_manager: ConfigManager instance for loading policies
        """
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # AWS clients will be initialized per account
        self.ec2_client = None
        self.sts_client = boto3.client('sts')
        
        # Cross-account role configuration
        import os
        self.cross_account_role_name = os.environ.get('CROSS_ACCOUNT_ROLE_NAME', '')
        self.external_id = os.environ.get('EXTERNAL_ID', '')
    
    def scan_account(self, account_id: str, policies: Dict[str, Any], scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan a specific AWS account for security group compliance violations
        
        Args:
            account_id: AWS account ID to scan
            policies: Security compliance policies
            scan_config: Scan configuration
            
        Returns:
            Dictionary containing scan results for the account
        """
        self.logger.info(f"Starting compliance scan for account: {account_id}")
        
        scan_start_time = datetime.now(timezone.utc)
        
        try:
            # Assume role for cross-account access if needed
            self._assume_account_role(account_id)
            
            # Get all security groups in the account
            security_groups = self._get_security_groups(scan_config)
            
            self.logger.info(f"Found {len(security_groups)} security groups in account {account_id}")
            
            # Load account-specific configuration
            account_config = self.config_manager.get_account_specific_config(account_id)
            
            # Scan each security group
            violations = []
            scanned_groups = []
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                
                try:
                    # Get exemptions for this security group
                    exemptions = self.config_manager.get_exemptions(account_id, sg_id)
                    
                    # Scan security group for violations
                    sg_violations = self._scan_security_group(
                        sg, policies, account_config, exemptions, scan_config
                    )
                    
                    if sg_violations:
                        violations.extend(sg_violations)
                    
                    scanned_groups.append({
                        'group_id': sg_id,
                        'group_name': sg.get('GroupName', ''),
                        'vpc_id': sg.get('VpcId', ''),
                        'violations_count': len(sg_violations),
                        'status': 'scanned'
                    })
                    
                except Exception as e:
                    self.logger.error(f"Error scanning security group {sg_id}: {str(e)}")
                    scanned_groups.append({
                        'group_id': sg_id,
                        'group_name': sg.get('GroupName', ''),
                        'vpc_id': sg.get('VpcId', ''),
                        'violations_count': 0,
                        'status': 'error',
                        'error_message': str(e)
                    })
            
            # Calculate scan duration
            scan_duration = (datetime.now(timezone.utc) - scan_start_time).total_seconds()
            
            # Prepare results
            results = {
                'account_id': account_id,
                'scan_timestamp': scan_start_time.isoformat(),
                'scan_duration_seconds': scan_duration,
                'security_groups_scanned': len(scanned_groups),
                'violations_count': len(violations),
                'violations': violations,
                'security_groups': scanned_groups,
                'status': 'completed'
            }
            
            # Log violations by severity
            self._log_violation_summary(violations, account_id)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to scan account {account_id}: {str(e)}")
            return {
                'account_id': account_id,
                'scan_timestamp': scan_start_time.isoformat(),
                'status': 'error',
                'error_message': str(e),
                'violations_count': 0
            }
    
    def _scan_security_group(
        self, 
        security_group: Dict[str, Any], 
        policies: Dict[str, Any],
        account_config: Dict[str, Any],
        exemptions: Dict[str, Any],
        scan_config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Scan a single security group for compliance violations
        
        Args:
            security_group: Security group data from AWS API
            policies: Compliance policies
            account_config: Account-specific configuration
            exemptions: Applicable exemptions
            scan_config: Scan configuration
            
        Returns:
            List of violations found in the security group
        """
        violations = []
        sg_id = security_group['GroupId']
        sg_name = security_group.get('GroupName', '')
        
        self.logger.debug(f"Scanning security group: {sg_id} ({sg_name})")
        
        # Check inbound rules
        inbound_violations = self._check_inbound_rules(
            security_group, policies, account_config, exemptions
        )
        violations.extend(inbound_violations)
        
        # Check outbound rules
        outbound_violations = self._check_outbound_rules(
            security_group, policies, account_config, exemptions
        )
        violations.extend(outbound_violations)
        
        # Check global rules (tagging, descriptions, etc.)
        global_violations = self._check_global_rules(
            security_group, policies, account_config, exemptions
        )
        violations.extend(global_violations)
        
        return violations
    
    def _check_inbound_rules(
        self, 
        security_group: Dict[str, Any], 
        policies: Dict[str, Any],
        account_config: Dict[str, Any],
        exemptions: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check inbound rules for violations"""
        violations = []
        sg_id = security_group['GroupId']
        inbound_rules = security_group.get('IpPermissions', [])
        
        prohibited_rules = policies['compliance_policies']['prohibited_rules']['inbound']
        
        for rule in inbound_rules:
            for prohibited_rule in prohibited_rules:
                violation = self._check_rule_against_policy(
                    rule, prohibited_rule, sg_id, 'inbound', exemptions
                )
                if violation:
                    violations.append(violation)
        
        return violations
    
    def _check_outbound_rules(
        self, 
        security_group: Dict[str, Any], 
        policies: Dict[str, Any],
        account_config: Dict[str, Any],
        exemptions: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check outbound rules for violations"""
        violations = []
        sg_id = security_group['GroupId']
        outbound_rules = security_group.get('IpPermissionsEgress', [])
        
        prohibited_rules = policies['compliance_policies']['prohibited_rules']['outbound']
        
        for rule in outbound_rules:
            for prohibited_rule in prohibited_rules:
                violation = self._check_rule_against_policy(
                    rule, prohibited_rule, sg_id, 'outbound', exemptions
                )
                if violation:
                    violations.append(violation)
        
        return violations
    
    def _check_global_rules(
        self, 
        security_group: Dict[str, Any], 
        policies: Dict[str, Any],
        account_config: Dict[str, Any],
        exemptions: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check global rules (tagging, descriptions, etc.)"""
        violations = []
        sg_id = security_group['GroupId']
        
        global_rules = policies['compliance_policies']['global_rules']
        
        # Check required tags
        if global_rules.get('enforce_tagging', False):
            required_tags = global_rules.get('required_tags', [])
            sg_tags = {tag['Key']: tag['Value'] for tag in security_group.get('Tags', [])}
            
            for required_tag in required_tags:
                if required_tag not in sg_tags:
                    violations.append({
                        'violation_id': f"{sg_id}_MISSING_TAG_{required_tag}",
                        'security_group_id': sg_id,
                        'violation_type': 'missing_required_tag',
                        'severity': 'medium',
                        'rule_id': 'GLOBAL_REQUIRED_TAGS',
                        'description': f"Security group missing required tag: {required_tag}",
                        'details': {
                            'missing_tag': required_tag,
                            'current_tags': list(sg_tags.keys())
                        }
                    })
        
        # Check description requirements
        if global_rules.get('require_descriptions', False):
            description = security_group.get('Description', '')
            min_length = global_rules.get('min_description_length', 10)
            
            if not description or len(description) < min_length:
                violations.append({
                    'violation_id': f"{sg_id}_INSUFFICIENT_DESCRIPTION",
                    'security_group_id': sg_id,
                    'violation_type': 'insufficient_description',
                    'severity': 'low',
                    'rule_id': 'GLOBAL_REQUIRE_DESCRIPTIONS',
                    'description': f"Security group description is too short (minimum {min_length} characters)",
                    'details': {
                        'current_description': description,
                        'current_length': len(description),
                        'required_length': min_length
                    }
                })
        
        return violations
    
    def _check_rule_against_policy(
        self, 
        rule: Dict[str, Any], 
        policy_rule: Dict[str, Any],
        sg_id: str,
        direction: str,
        exemptions: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Check if a security group rule violates a policy rule
        
        Args:
            rule: Security group rule from AWS API
            policy_rule: Policy rule definition
            sg_id: Security group ID
            direction: 'inbound' or 'outbound'
            exemptions: Applicable exemptions
            
        Returns:
            Violation dictionary if rule violates policy, None otherwise
        """
        # Check if this rule is exempted
        if self._is_rule_exempted(policy_rule['rule_id'], exemptions):
            return None
        
        # Check protocol match
        rule_protocol = rule.get('IpProtocol', '')
        policy_protocol = policy_rule.get('protocol', '')
        
        if policy_protocol != '-1' and rule_protocol != policy_protocol:
            return None
        
        # Check port range match
        if not self._check_port_match(rule, policy_rule):
            return None
        
        # Check source/destination match
        if not self._check_source_destination_match(rule, policy_rule, direction):
            return None
        
        # If we get here, it's a violation
        violation_id = f"{sg_id}_{policy_rule['rule_id']}_{direction}_{datetime.now().strftime('%s')}"
        
        return {
            'violation_id': violation_id,
            'security_group_id': sg_id,
            'violation_type': 'prohibited_rule',
            'severity': policy_rule.get('severity', 'medium'),
            'rule_id': policy_rule['rule_id'],
            'description': policy_rule.get('description', 'Policy violation'),
            'reason': policy_rule.get('reason', 'Rule violates security policy'),
            'direction': direction,
            'details': {
                'violating_rule': rule,
                'policy_rule': policy_rule
            }
        }
    
    def _check_port_match(self, rule: Dict[str, Any], policy_rule: Dict[str, Any]) -> bool:
        """Check if rule port matches policy port specification"""
        policy_port_range = policy_rule.get('port_range', '')
        
        if not policy_port_range:
            return True  # No port restriction in policy
        
        rule_from_port = rule.get('FromPort')
        rule_to_port = rule.get('ToPort')
        
        # Handle different port range formats
        if '-' in policy_port_range:
            policy_from, policy_to = map(int, policy_port_range.split('-'))
        else:
            policy_from = policy_to = int(policy_port_range)
        
        # Check if rule ports overlap with policy ports
        if rule_from_port is not None and rule_to_port is not None:
            return (rule_from_port <= policy_to and rule_to_port >= policy_from)
        
        return False
    
    def _check_source_destination_match(
        self, 
        rule: Dict[str, Any], 
        policy_rule: Dict[str, Any],
        direction: str
    ) -> bool:
        """Check if rule source/destination matches policy specification"""
        if direction == 'inbound':
            # Check IP ranges
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')
                if cidr == policy_rule.get('source'):
                    return True
            
            # Check IPv6 ranges
            for ipv6_range in rule.get('Ipv6Ranges', []):
                cidr = ipv6_range.get('CidrIpv6')
                if cidr == policy_rule.get('source'):
                    return True
        
        else:  # outbound
            # Check IP ranges
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')
                if cidr == policy_rule.get('destination'):
                    return True
            
            # Check IPv6 ranges
            for ipv6_range in rule.get('Ipv6Ranges', []):
                cidr = ipv6_range.get('CidrIpv6')
                if cidr == policy_rule.get('destination'):
                    return True
        
        return False
    
    def _is_rule_exempted(self, rule_id: str, exemptions: Dict[str, Any]) -> bool:
        """Check if a rule is exempted from compliance checking"""
        for exemption_type, exemption_data in exemptions.items():
            exempted_rules = exemption_data.get('exempted_rules', [])
            if rule_id in exempted_rules:
                self.logger.info(f"Rule {rule_id} is exempted ({exemption_type})")
                return True
        
        return False
    
    def _get_security_groups(self, scan_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get all security groups to scan"""
        try:
            # Check if scanning specific security groups
            target_sgs = scan_config.get('target_security_groups', [])
            
            if target_sgs:
                # Scan specific security groups
                response = self.ec2_client.describe_security_groups(GroupIds=target_sgs)
            else:
                # Scan all security groups
                response = self.ec2_client.describe_security_groups()
            
            return response['SecurityGroups']
            
        except ClientError as e:
            raise AWSServiceError(f"Failed to describe security groups: {str(e)}")
    
    def _assume_account_role(self, account_id: str) -> None:
        """Assume cross-account role and initialize the EC2 client."""
        try:
            if not self.cross_account_role_name:
                self.ec2_client = get_ec2_client(account_id, 'us-east-1')
            else:
                session_name = f"ComplianceScanner-{account_id}"
                self.ec2_client = get_ec2_client(
                    account_id,
                    'us-east-1',
                    role_name=self.cross_account_role_name,
                    session_name=session_name,
                    external_id=self.external_id,
                )
            self.logger.info(f"Successfully assumed role for account {account_id}")
        except ClientError as e:
            raise ComplianceError(f"Failed to assume role for account {account_id}: {str(e)}")
    
    def _log_violation_summary(self, violations: List[Dict[str, Any]], account_id: str) -> None:
        """Log summary of violations found"""
        if not violations:
            self.logger.info(f"No violations found in account {account_id}")
            return
        
        # Count violations by severity
        severity_counts = {}
        for violation in violations:
            severity = violation.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        self.logger.warning(
            f"Found {len(violations)} violations in account {account_id}",
            extra={
                'event_type': 'COMPLIANCE_VIOLATION',
                'account_id': account_id,
                'total_violations': len(violations),
                'severity_breakdown': severity_counts
            }
        )
