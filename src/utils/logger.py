"""
Logging utilities for the Security Group Compliance Framework
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        
        # Create base log entry
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add AWS Lambda context if available
        if hasattr(record, 'aws_request_id'):
            log_entry['aws_request_id'] = record.aws_request_id
        
        # Add extra fields from the record
        if hasattr(record, '__dict__'):
            for key, value in record.__dict__.items():
                if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                              'pathname', 'filename', 'module', 'exc_info', 
                              'exc_text', 'stack_info', 'lineno', 'funcName', 
                              'created', 'msecs', 'relativeCreated', 'thread', 
                              'threadName', 'processName', 'process', 'getMessage']:
                    if not key.startswith('_'):
                        log_entry[key] = value
        
        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'traceback': self.formatException(record.exc_info) if record.exc_info else None
            }
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)

def setup_logger(name: str, level: str = 'INFO') -> logging.Logger:
    """
    Set up a logger with JSON formatting for the compliance framework
    
    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Configured logger instance
    """
    
    # Create logger
    logger = logging.getLogger(name)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Set log level
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    
    # Create JSON formatter
    formatter = JSONFormatter()
    handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(handler)
    
    # Prevent duplicate logs
    logger.propagate = False
    
    return logger

def create_audit_log_entry(
    event_type: str,
    account_id: str,
    security_group_id: str,
    action: str,
    details: Dict[str, Any],
    user_identity: str = 'system'
) -> Dict[str, Any]:
    """
    Create a standardized audit log entry
    
    Args:
        event_type: Type of event (e.g., 'COMPLIANCE_SCAN', 'REMEDIATION')
        account_id: AWS account ID
        security_group_id: Security group ID
        action: Action performed
        details: Additional details about the action
        user_identity: User or system that performed the action
        
    Returns:
        Structured audit log entry
    """
    
    return {
        'audit_timestamp': datetime.now(timezone.utc).isoformat(),
        'event_type': event_type,
        'account_id': account_id,
        'security_group_id': security_group_id,
        'action': action,
        'user_identity': user_identity,
        'details': details,
        'framework_version': '1.0.0',
        'compliance_framework': 'SecurityGroupCompliance'
    }

class ComplianceLogger:
    """Specialized logger for compliance events"""
    
    def __init__(self, logger_name: str):
        self.logger = logging.getLogger(logger_name)
    
    def log_scan_started(self, account_id: str, config: Dict[str, Any]) -> None:
        """Log compliance scan start"""
        self.logger.info(
            f"Compliance scan started for account {account_id}",
            extra={
                'event_type': 'SCAN_STARTED',
                'account_id': account_id,
                'scan_config': config
            }
        )
    
    def log_scan_completed(self, account_id: str, results: Dict[str, Any]) -> None:
        """Log compliance scan completion"""
        self.logger.info(
            f"Compliance scan completed for account {account_id}",
            extra={
                'event_type': 'SCAN_COMPLETED',
                'account_id': account_id,
                'violations_found': results.get('violations_count', 0),
                'scan_duration': results.get('scan_duration_seconds', 0)
            }
        )
    
    def log_violation_found(
        self, 
        account_id: str, 
        security_group_id: str, 
        violation: Dict[str, Any]
    ) -> None:
        """Log compliance violation"""
        self.logger.warning(
            f"Compliance violation found in {security_group_id}",
            extra={
                'event_type': 'COMPLIANCE_VIOLATION',
                'account_id': account_id,
                'security_group_id': security_group_id,
                'violation_type': violation.get('violation_type'),
                'severity': violation.get('severity'),
                'rule_id': violation.get('rule_id')
            }
        )
    
    def log_remediation_applied(
        self, 
        account_id: str, 
        security_group_id: str, 
        actions: list
    ) -> None:
        """Log remediation action"""
        self.logger.warning(
            f"Remediation applied to {security_group_id}",
            extra={
                'event_type': 'REMEDIATION_APPLIED',
                'account_id': account_id,
                'security_group_id': security_group_id,
                'actions_taken': actions
            }
        )
    
    def log_exemption_applied(
        self, 
        account_id: str, 
        security_group_id: str, 
        exemption: Dict[str, Any]
    ) -> None:
        """Log exemption application"""
        self.logger.info(
            f"Exemption applied to {security_group_id}",
            extra={
                'event_type': 'EXEMPTION_APPLIED',
                'account_id': account_id,
                'security_group_id': security_group_id,
                'exemption_reason': exemption.get('reason'),
                'exempted_rules': exemption.get('exempted_rules', [])
            }
        )
    
    def log_error(
        self, 
        error_type: str, 
        error_message: str, 
        context: Dict[str, Any] = None
    ) -> None:
        """Log error with context"""
        self.logger.error(
            f"{error_type}: {error_message}",
            extra={
                'event_type': 'ERROR',
                'error_type': error_type,
                'error_message': error_message,
                'context': context or {}
            }
        )
