"""
Custom exceptions for the Security Group Compliance Framework
"""

class ComplianceError(Exception):
    """Base exception for compliance-related errors"""
    pass

class ConfigurationError(ComplianceError):
    """Exception raised for configuration-related errors"""
    pass

class AWSServiceError(ComplianceError):
    """Exception raised for AWS service-related errors"""
    pass

class RemediationError(ComplianceError):
    """Exception raised for remediation-related errors"""
    pass

class ValidationError(ComplianceError):
    """Exception raised for validation-related errors"""
    pass

class PolicyViolation:
    """Represents a policy violation found during compliance scanning"""
    
    def __init__(self, rule_id: str, severity: str, message: str, 
                 security_group_id: str, account_id: str = "", **kwargs):
        self.rule_id = rule_id
        self.severity = severity
        self.message = message
        self.security_group_id = security_group_id
        self.account_id = account_id
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self):
        """Convert violation to dictionary"""
        return {
            'rule_id': self.rule_id,
            'severity': self.severity,
            'message': self.message,
            'security_group_id': self.security_group_id,
            'account_id': self.account_id
        }
