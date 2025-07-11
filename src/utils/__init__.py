"""
Initialize utils package
"""

from .exceptions import (
    ComplianceError,
    ConfigurationError,
    AWSServiceError,
    RemediationError,
    ValidationError
)

from .logger import (
    setup_logger,
    JSONFormatter,
    ComplianceLogger,
    create_audit_log_entry
)

from .metrics import (
    MetricsCollector,
    ComplianceScoreCalculator
)

from .helpers import (
    validate_cidr,
    is_public_cidr,
    normalize_port_range,
    port_ranges_overlap,
    format_security_group_name,
    extract_account_id_from_arn,
    sanitize_tag_value,
    create_compliance_tag_map,
    parse_security_group_rule,
    generate_violation_id,
    calculate_risk_score,
    mask_sensitive_data,
    validate_aws_account_id,
    validate_security_group_id
)

__all__ = [
    # Exceptions
    'ComplianceError',
    'ConfigurationError', 
    'AWSServiceError',
    'RemediationError',
    'ValidationError',
    
    # Logging
    'setup_logger',
    'JSONFormatter',
    'ComplianceLogger',
    'create_audit_log_entry',
    
    # Metrics
    'MetricsCollector',
    'ComplianceScoreCalculator',
    
    # Helpers
    'validate_cidr',
    'is_public_cidr',
    'normalize_port_range',
    'port_ranges_overlap',
    'format_security_group_name',
    'extract_account_id_from_arn',
    'sanitize_tag_value',
    'create_compliance_tag_map',
    'parse_security_group_rule',
    'generate_violation_id',
    'calculate_risk_score',
    'mask_sensitive_data',
    'validate_aws_account_id',
    'validate_security_group_id'
]
