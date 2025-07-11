"""
Utility functions for the Security Group Compliance Framework
"""

import json
import re
import boto3
from typing import Dict, Any, List, Optional
from ipaddress import ip_network, AddressValueError

def validate_cidr(cidr: str) -> bool:
    """
    Validate CIDR notation
    
    Args:
        cidr: CIDR string to validate
        
    Returns:
        True if valid CIDR, False otherwise
    """
    try:
        ip_network(cidr, strict=False)
        return True
    except (AddressValueError, ValueError):
        return False

def is_public_cidr(cidr: str) -> bool:
    """
    Check if CIDR represents public IP ranges
    
    Args:
        cidr: CIDR string to check
        
    Returns:
        True if public CIDR, False otherwise
    """
    try:
        network = ip_network(cidr, strict=False)
        return not network.is_private
    except (AddressValueError, ValueError):
        return False

def normalize_port_range(port_range: str) -> tuple:
    """
    Normalize port range to (from_port, to_port) tuple
    
    Args:
        port_range: Port range string (e.g., "80", "80-443", "1024-65535")
        
    Returns:
        Tuple of (from_port, to_port)
    """
    if '-' in port_range:
        from_port, to_port = map(int, port_range.split('-', 1))
        return (from_port, to_port)
    else:
        port = int(port_range)
        return (port, port)

def port_ranges_overlap(range1: str, range2: str) -> bool:
    """
    Check if two port ranges overlap
    
    Args:
        range1: First port range
        range2: Second port range
        
    Returns:
        True if ranges overlap, False otherwise
    """
    try:
        from_port1, to_port1 = normalize_port_range(range1)
        from_port2, to_port2 = normalize_port_range(range2)
        
        return (from_port1 <= to_port2 and to_port1 >= from_port2)
    except (ValueError, TypeError):
        return False

def format_security_group_name(sg_name: str, violation_reason: str) -> str:
    """
    Format security group name for compliance tagging
    
    Args:
        sg_name: Original security group name
        violation_reason: Reason for violation
        
    Returns:
        Formatted name with compliance prefix
    """
    # Clean violation reason for use in name
    clean_reason = re.sub(r'[^a-zA-Z0-9\-_]', '_', violation_reason)[:50]
    
    # Create new name with prefix
    new_name = f"NON_COMPLIANT_{clean_reason}_{sg_name}"
    
    # Ensure name doesn't exceed AWS limits (255 characters)
    if len(new_name) > 255:
        # Truncate original name to fit
        max_original_length = 255 - len(f"NON_COMPLIANT_{clean_reason}_")
        truncated_name = sg_name[:max_original_length]
        new_name = f"NON_COMPLIANT_{clean_reason}_{truncated_name}"
    
    return new_name

def extract_account_id_from_arn(arn: str) -> Optional[str]:
    """
    Extract AWS account ID from ARN
    
    Args:
        arn: AWS ARN string
        
    Returns:
        Account ID if found, None otherwise
    """
    try:
        # ARN format: arn:partition:service:region:account-id:resource
        parts = arn.split(':')
        if len(parts) >= 5:
            return parts[4]
    except:
        pass
    return None

def sanitize_tag_value(value: str) -> str:
    """
    Sanitize value for use as AWS tag value
    
    Args:
        value: Original value
        
    Returns:
        Sanitized value suitable for AWS tags
    """
    # AWS tag values can be up to 256 characters
    # Remove or replace invalid characters
    sanitized = re.sub(r'[^\w\s\-_\.:/@+=]', '_', value)
    
    # Truncate if too long
    if len(sanitized) > 256:
        sanitized = sanitized[:253] + "..."
    
    return sanitized

def create_compliance_tag_map(
    violation_count: int,
    primary_violation: str,
    scan_timestamp: str,
    framework_version: str = "1.0.0"
) -> Dict[str, str]:
    """
    Create standardized compliance tag map
    
    Args:
        violation_count: Number of violations found
        primary_violation: Primary violation reason
        scan_timestamp: When the scan was performed
        framework_version: Version of compliance framework
        
    Returns:
        Dictionary of tags for compliance marking
    """
    return {
        'COMPLIANCE_STATUS': 'NON_COMPLIANT',
        'COMPLIANCE_VIOLATION_COUNT': str(violation_count),
        'COMPLIANCE_PRIMARY_VIOLATION': sanitize_tag_value(primary_violation),
        'COMPLIANCE_SCAN_TIMESTAMP': scan_timestamp,
        'COMPLIANCE_FRAMEWORK_VERSION': framework_version,
        'COMPLIANCE_REMEDIATION_REQUIRED': 'true'
    }

def parse_security_group_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse and normalize security group rule
    
    Args:
        rule: Raw security group rule from AWS API
        
    Returns:
        Normalized rule dictionary
    """
    parsed_rule = {
        'protocol': rule.get('IpProtocol', ''),
        'from_port': rule.get('FromPort'),
        'to_port': rule.get('ToPort'),
        'ip_ranges': [],
        'ipv6_ranges': [],
        'security_groups': [],
        'prefix_lists': []
    }
    
    # Parse IP ranges
    for ip_range in rule.get('IpRanges', []):
        parsed_rule['ip_ranges'].append({
            'cidr': ip_range.get('CidrIp'),
            'description': ip_range.get('Description', '')
        })
    
    # Parse IPv6 ranges
    for ipv6_range in rule.get('Ipv6Ranges', []):
        parsed_rule['ipv6_ranges'].append({
            'cidr': ipv6_range.get('CidrIpv6'),
            'description': ipv6_range.get('Description', '')
        })
    
    # Parse security group references
    for sg_ref in rule.get('UserIdGroupPairs', []):
        parsed_rule['security_groups'].append({
            'group_id': sg_ref.get('GroupId'),
            'group_name': sg_ref.get('GroupName'),
            'user_id': sg_ref.get('UserId'),
            'description': sg_ref.get('Description', '')
        })
    
    # Parse prefix lists
    for prefix_list in rule.get('PrefixListIds', []):
        parsed_rule['prefix_lists'].append({
            'prefix_list_id': prefix_list.get('PrefixListId'),
            'description': prefix_list.get('Description', '')
        })
    
    return parsed_rule

def generate_violation_id(
    security_group_id: str,
    rule_id: str,
    direction: str,
    suffix: str = ""
) -> str:
    """
    Generate unique violation ID
    
    Args:
        security_group_id: Security group ID
        rule_id: Policy rule ID
        direction: inbound or outbound
        suffix: Optional suffix for uniqueness
        
    Returns:
        Unique violation ID
    """
    base_id = f"{security_group_id}_{rule_id}_{direction}"
    if suffix:
        return f"{base_id}_{suffix}"
    return base_id

def calculate_risk_score(violations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate risk score based on violations
    
    Args:
        violations: List of violations
        
    Returns:
        Risk score details
    """
    # Risk scoring weights
    severity_weights = {
        'critical': 10,
        'high': 5,
        'medium': 2,
        'low': 1
    }
    
    total_risk_score = 0
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for violation in violations:
        severity = violation.get('severity', 'low')
        if severity in severity_counts:
            severity_counts[severity] += 1
            total_risk_score += severity_weights.get(severity, 1)
    
    # Determine risk level
    if total_risk_score >= 50:
        risk_level = 'very_high'
    elif total_risk_score >= 20:
        risk_level = 'high'
    elif total_risk_score >= 10:
        risk_level = 'medium'
    elif total_risk_score > 0:
        risk_level = 'low'
    else:
        risk_level = 'none'
    
    return {
        'total_risk_score': total_risk_score,
        'risk_level': risk_level,
        'severity_breakdown': severity_counts,
        'total_violations': len(violations)
    }

def mask_sensitive_data(data: Dict[str, Any], sensitive_keys: List[str] = None) -> Dict[str, Any]:
    """
    Mask sensitive data in dictionaries for logging
    
    Args:
        data: Data dictionary to mask
        sensitive_keys: List of keys to mask (default: common sensitive keys)
        
    Returns:
        Dictionary with sensitive values masked
    """
    if sensitive_keys is None:
        sensitive_keys = [
            'password', 'secret', 'key', 'token', 'credential',
            'AccessKeyId', 'SecretAccessKey', 'SessionToken'
        ]
    
    masked_data = {}
    
    for key, value in data.items():
        if any(sensitive_key.lower() in key.lower() for sensitive_key in sensitive_keys):
            masked_data[key] = "***MASKED***"
        elif isinstance(value, dict):
            masked_data[key] = mask_sensitive_data(value, sensitive_keys)
        elif isinstance(value, list):
            masked_data[key] = [
                mask_sensitive_data(item, sensitive_keys) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            masked_data[key] = value
    
    return masked_data

def validate_aws_account_id(account_id: str) -> bool:
    """
    Validate AWS account ID format
    
    Args:
        account_id: Account ID to validate
        
    Returns:
        True if valid format, False otherwise
    """
    # AWS account IDs are 12-digit numbers
    return bool(re.match(r'^\d{12}$', account_id))

def validate_security_group_id(sg_id: str) -> bool:
    """
    Validate security group ID format
    
    Args:
        sg_id: Security group ID to validate
        
    Returns:
        True if valid format, False otherwise
    """
    # Security group IDs start with 'sg-' followed by 8 or 17 hexadecimal characters
    return bool(re.match(r'^sg-[0-9a-f]{8}([0-9a-f]{9})?$', sg_id))

def assume_role(account_id: str, role_name: str, session_name: str, external_id: str = "", sts_client=None) -> Dict[str, Any]:
    """Assume an IAM role and return temporary credentials."""
    if sts_client is None:
        sts_client = boto3.client('sts')
    params = {
        'RoleArn': f"arn:aws:iam::{account_id}:role/{role_name}",
        'RoleSessionName': session_name,
    }
    if external_id:
        params['ExternalId'] = external_id
    response = sts_client.assume_role(**params)
    return response['Credentials']


def get_ec2_client(account_id: str, region: str, role_name: str = "", session_name: str = "", external_id: str = ""):
    """Return an EC2 client for the given account and region."""
    sts_client = boto3.client('sts')
    current_account = sts_client.get_caller_identity()['Account']
    if account_id == current_account or not role_name:
        return boto3.client('ec2', region_name=region)

    credentials = assume_role(account_id, role_name, session_name or f"EC2Access-{account_id}", external_id, sts_client)
    return boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
