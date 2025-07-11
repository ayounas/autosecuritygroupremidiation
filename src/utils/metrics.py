"""
Metrics collection utilities for the Security Group Compliance Framework
"""

import json
import boto3
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List
from botocore.exceptions import ClientError

class MetricsCollector:
    """Collects and publishes metrics for the compliance framework"""
    
    def __init__(self):
        """Initialize MetricsCollector"""
        self.cloudwatch = boto3.client('cloudwatch')
        self.logger = logging.getLogger(__name__)
    
    def record_scan_metrics(self, scan_results: Dict[str, Any]) -> None:
        """
        Record metrics from a compliance scan
        
        Args:
            scan_results: Results from compliance scan
        """
        try:
            # Extract metrics from scan results
            metrics_data = []
            
            # Basic scan metrics
            metrics_data.extend([
                {
                    'MetricName': 'AccountsScanned',
                    'Value': scan_results.get('accounts_scanned', 0),
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'TotalViolationsFound',
                    'Value': scan_results.get('total_violations_found', 0),
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'RemediationsApplied',
                    'Value': scan_results.get('total_remediations_applied', 0),
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'ScanDuration',
                    'Value': scan_results.get('scan_duration_seconds', 0),
                    'Unit': 'Seconds'
                }
            ])
            
            # Violations by severity
            severity_counts = self._calculate_severity_counts(scan_results)
            for severity, count in severity_counts.items():
                metrics_data.append({
                    'MetricName': f'Violations{severity.title()}',
                    'Value': count,
                    'Unit': 'Count',
                    'Dimensions': [
                        {
                            'Name': 'Severity',
                            'Value': severity
                        }
                    ]
                })
            
            # Account-specific metrics
            for account_result in scan_results.get('account_results', []):
                if account_result.get('status') == 'completed':
                    metrics_data.extend([
                        {
                            'MetricName': 'AccountViolations',
                            'Value': account_result.get('violations_count', 0),
                            'Unit': 'Count',
                            'Dimensions': [
                                {
                                    'Name': 'AccountId',
                                    'Value': account_result.get('account_id', 'unknown')
                                }
                            ]
                        },
                        {
                            'MetricName': 'AccountSecurityGroups',
                            'Value': account_result.get('security_groups_scanned', 0),
                            'Unit': 'Count',
                            'Dimensions': [
                                {
                                    'Name': 'AccountId',
                                    'Value': account_result.get('account_id', 'unknown')
                                }
                            ]
                        }
                    ])
            
            # Publish metrics to CloudWatch
            self._publish_metrics(metrics_data)
            
        except Exception as e:
            self.logger.error(f"Failed to record scan metrics: {str(e)}")
    
    def record_remediation_metrics(self, remediation_results: Dict[str, Any]) -> None:
        """
        Record metrics from remediation actions
        
        Args:
            remediation_results: Results from remediation actions
        """
        try:
            metrics_data = []
            
            # Basic remediation metrics
            metrics_data.extend([
                {
                    'MetricName': 'RemediationDuration',
                    'Value': remediation_results.get('remediation_duration_seconds', 0),
                    'Unit': 'Seconds'
                },
                {
                    'MetricName': 'SuccessfulRemediations',
                    'Value': remediation_results.get('remediations_applied', 0),
                    'Unit': 'Count'
                }
            ])
            
            # Account-specific remediation metrics
            account_id = remediation_results.get('account_id', 'unknown')
            metrics_data.append({
                'MetricName': 'AccountRemediations',
                'Value': remediation_results.get('remediations_applied', 0),
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'AccountId',
                        'Value': account_id
                    }
                ]
            })
            
            # Publish metrics
            self._publish_metrics(metrics_data)
            
        except Exception as e:
            self.logger.error(f"Failed to record remediation metrics: {str(e)}")
    
    def record_error_metrics(self, error_type: str, context: Dict[str, Any] = None) -> None:
        """
        Record error metrics
        
        Args:
            error_type: Type of error
            context: Additional context
        """
        try:
            metrics_data = [
                {
                    'MetricName': 'Errors',
                    'Value': 1,
                    'Unit': 'Count',
                    'Dimensions': [
                        {
                            'Name': 'ErrorType',
                            'Value': error_type
                        }
                    ]
                }
            ]
            
            # Add context dimensions if available
            if context:
                if 'account_id' in context:
                    metrics_data[0]['Dimensions'].append({
                        'Name': 'AccountId',
                        'Value': context['account_id']
                    })
            
            self._publish_metrics(metrics_data)
            
        except Exception as e:
            self.logger.error(f"Failed to record error metrics: {str(e)}")
    
    def _calculate_severity_counts(self, scan_results: Dict[str, Any]) -> Dict[str, int]:
        """Calculate violation counts by severity"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for account_result in scan_results.get('account_results', []):
            for violation in account_result.get('violations', []):
                severity = violation.get('severity', 'unknown')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        return severity_counts
    
    def _publish_metrics(self, metrics_data: List[Dict[str, Any]]) -> None:
        """
        Publish metrics to CloudWatch
        
        Args:
            metrics_data: List of metric data points
        """
        try:
            # CloudWatch has a limit of 20 metrics per put_metric_data call
            batch_size = 20
            
            for i in range(0, len(metrics_data), batch_size):
                batch = metrics_data[i:i + batch_size]
                
                # Prepare metric data for CloudWatch
                metric_data = []
                for metric in batch:
                    metric_point = {
                        'MetricName': metric['MetricName'],
                        'Value': float(metric['Value']),
                        'Unit': metric.get('Unit', 'None'),
                        'Timestamp': datetime.now(timezone.utc)
                    }
                    
                    if 'Dimensions' in metric:
                        metric_point['Dimensions'] = metric['Dimensions']
                    
                    metric_data.append(metric_point)
                
                # Publish to CloudWatch
                self.cloudwatch.put_metric_data(
                    Namespace='SecurityGroup/Compliance',
                    MetricData=metric_data
                )
            
            self.logger.debug(f"Published {len(metrics_data)} metrics to CloudWatch")
            
        except ClientError as e:
            self.logger.error(f"Failed to publish metrics to CloudWatch: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error publishing metrics: {str(e)}")

class ComplianceScoreCalculator:
    """Calculates compliance scores based on violations"""
    
    def __init__(self, policies: Dict[str, Any]):
        """
        Initialize ComplianceScoreCalculator
        
        Args:
            policies: Security compliance policies
        """
        self.policies = policies
        self.score_config = policies.get('reporting', {}).get('compliance_score_calculation', {})
        self.logger = logging.getLogger(__name__)
    
    def calculate_account_score(self, violations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate compliance score for an account
        
        Args:
            violations: List of violations for the account
            
        Returns:
            Dictionary containing score details
        """
        total_points = self.score_config.get('total_possible_points', 100)
        deductions = self.score_config.get('deductions', {})
        
        total_deductions = 0
        severity_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for violation in violations:
            severity = violation.get('severity', 'low')
            if severity in severity_breakdown:
                severity_breakdown[severity] += 1
            
            deduction = deductions.get(f'{severity}_violation', 0)
            total_deductions += deduction
        
        # Calculate final score
        final_score = max(0, total_points - total_deductions)
        
        # Determine compliance level
        if final_score >= 90:
            compliance_level = 'excellent'
        elif final_score >= 80:
            compliance_level = 'good'
        elif final_score >= 70:
            compliance_level = 'acceptable'
        elif final_score >= 60:
            compliance_level = 'needs_improvement'
        else:
            compliance_level = 'poor'
        
        return {
            'compliance_score': final_score,
            'max_possible_score': total_points,
            'total_deductions': total_deductions,
            'compliance_level': compliance_level,
            'violations_by_severity': severity_breakdown,
            'total_violations': len(violations)
        }
    
    def calculate_overall_score(self, account_scores: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate overall compliance score across all accounts
        
        Args:
            account_scores: List of account compliance scores
            
        Returns:
            Dictionary containing overall score details
        """
        if not account_scores:
            return {
                'overall_compliance_score': 0,
                'accounts_evaluated': 0,
                'compliance_distribution': {}
            }
        
        # Calculate weighted average (all accounts weighted equally)
        total_score = sum(score['compliance_score'] for score in account_scores)
        average_score = total_score / len(account_scores)
        
        # Calculate compliance level distribution
        compliance_distribution = {}
        for score in account_scores:
            level = score['compliance_level']
            compliance_distribution[level] = compliance_distribution.get(level, 0) + 1
        
        return {
            'overall_compliance_score': round(average_score, 2),
            'accounts_evaluated': len(account_scores),
            'compliance_distribution': compliance_distribution,
            'score_range': {
                'highest': max(score['compliance_score'] for score in account_scores),
                'lowest': min(score['compliance_score'] for score in account_scores)
            }
        }
