"""
AWS Security Group Mass Operations Detector
Detects and responds to suspicious mass security group operations that might indicate attacks.
"""

import json
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from decimal import Decimal
import hashlib
import os

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO'))

class MassOperationsDetector:
    """Detects and responds to mass security group operations."""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.sns = boto3.client('sns')
        self.cloudwatch = boto3.client('cloudwatch')
        self.iam = boto3.client('iam')
        
        self.table_name = os.getenv('DYNAMODB_TABLE')
        self.sns_topic_arn = os.getenv('SNS_TOPIC_ARN')
        self.max_operations_per_minute = int(os.getenv('MAX_OPERATIONS_PER_MINUTE', '10'))
        self.alert_threshold = int(os.getenv('ALERT_THRESHOLD', '5'))
        self.block_suspicious_users = os.getenv('BLOCK_SUSPICIOUS_USERS', 'false').lower() == 'true'
        
        if self.table_name:
            self.table = self.dynamodb.Table(self.table_name)
    
    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process CloudTrail event for mass operations detection."""
        try:
            # Extract event details
            detail = event.get('detail', {})
            event_name = detail.get('eventName')
            event_time = detail.get('eventTime')
            user_identity = detail.get('userIdentity', {})
            source_ip = detail.get('sourceIPAddress')
            account_id = detail.get('recipientAccountId')
            region = detail.get('awsRegion')
            
            # Create user identifier
            user_id = self._create_user_identifier(user_identity)
            
            # Get current time window (1-minute buckets)
            time_window = self._get_time_window(event_time)
            
            # Track the operation
            operation_count = self._track_operation(
                user_id, time_window, event_name, source_ip, account_id, region
            )
            
            # Check if this exceeds thresholds
            if operation_count > self.max_operations_per_minute:
                return self._handle_mass_operations_detected(
                    user_id, user_identity, operation_count, time_window, 
                    source_ip, account_id, region
                )
            
            return {
                'statusCode': 200,
                'body': {
                    'message': 'Operation tracked successfully',
                    'user_id': user_id,
                    'operation_count': operation_count,
                    'time_window': time_window
                }
            }
            
        except Exception as e:
            logger.error(f"Error processing mass operations event: {str(e)}")
            raise
    
    def _create_user_identifier(self, user_identity: Dict[str, Any]) -> str:
        """Create a consistent user identifier from user identity."""
        user_type = user_identity.get('type', 'Unknown')
        
        if user_type == 'IAMUser':
            return f"user:{user_identity.get('userName', 'unknown')}"
        elif user_type == 'AssumedRole':
            arn = user_identity.get('arn', '')
            # Extract role name from ARN
            if 'assumed-role' in arn:
                parts = arn.split('/')
                if len(parts) >= 2:
                    return f"role:{parts[1]}"
            return f"role:{user_identity.get('sessionName', 'unknown')}"
        elif user_type == 'Root':
            return f"root:{user_identity.get('accountId', 'unknown')}"
        else:
            # For other types, create a hash of the identity
            identity_str = json.dumps(user_identity, sort_keys=True)
            user_hash = hashlib.md5(identity_str.encode()).hexdigest()[:8]
            return f"{user_type.lower()}:{user_hash}"
    
    def _get_time_window(self, event_time: str) -> str:
        """Get 1-minute time window for the event."""
        try:
            dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            # Round down to the nearest minute
            dt = dt.replace(second=0, microsecond=0)
            return dt.isoformat()
        except Exception as e:
            logger.warning(f"Error parsing event time {event_time}: {e}")
            # Use current time rounded to minute
            dt = datetime.utcnow().replace(second=0, microsecond=0)
            return dt.isoformat()
    
    def _track_operation(self, user_id: str, time_window: str, event_name: str, 
                        source_ip: str, account_id: str, region: str) -> int:
        """Track the operation in DynamoDB and return current count."""
        try:
            # Calculate TTL (keep records for 24 hours)
            ttl = int((datetime.utcnow() + timedelta(hours=24)).timestamp())
            
            # Update the operation count
            response = self.table.update_item(
                Key={
                    'user_identity': user_id,
                    'time_window': time_window
                },
                UpdateExpression='ADD operation_count :inc SET #ttl = :ttl, last_event_name = :event_name, '
                               'last_source_ip = :source_ip, account_id = :account_id, #region = :region, '
                               'last_updated = :timestamp',
                ExpressionAttributeNames={
                    '#ttl': 'ttl',
                    '#region': 'region'
                },
                ExpressionAttributeValues={
                    ':inc': 1,
                    ':ttl': ttl,
                    ':event_name': event_name,
                    ':source_ip': source_ip,
                    ':account_id': account_id,
                    ':region': region,
                    ':timestamp': datetime.utcnow().isoformat()
                },
                ReturnValues='ALL_NEW'
            )
            
            return int(response['Attributes']['operation_count'])
            
        except Exception as e:
            logger.error(f"Error tracking operation in DynamoDB: {e}")
            # Return a high number to trigger alert
            return self.max_operations_per_minute + 1
    
    def _handle_mass_operations_detected(self, user_id: str, user_identity: Dict[str, Any], 
                                       operation_count: int, time_window: str, 
                                       source_ip: str, account_id: str, region: str) -> Dict[str, Any]:
        """Handle detected mass operations."""
        try:
            # Send CloudWatch metric
            self._send_cloudwatch_metric(operation_count, user_id, account_id, region)
            
            # Get user details
            user_details = self._get_user_details(user_identity)
            
            # Create alert message
            alert_message = self._create_alert_message(
                user_id, user_identity, user_details, operation_count, 
                time_window, source_ip, account_id, region
            )
            
            # Send SNS alert
            self._send_sns_alert(alert_message)
            
            # Block user if configured
            if self.block_suspicious_users:
                block_result = self._block_suspicious_user(user_identity, user_details)
                alert_message['blocking_action'] = block_result
            
            logger.warning(f"Mass operations detected: {alert_message}")
            
            return {
                'statusCode': 200,
                'body': {
                    'message': 'Mass operations detected and alert sent',
                    'alert_details': alert_message
                }
            }
            
        except Exception as e:
            logger.error(f"Error handling mass operations detection: {e}")
            raise
    
    def _send_cloudwatch_metric(self, operation_count: int, user_id: str, 
                              account_id: str, region: str) -> None:
        """Send metric to CloudWatch."""
        try:
            self.cloudwatch.put_metric_data(
                Namespace='SecurityCompliance/MassOperations',
                MetricData=[
                    {
                        'MetricName': 'MassOperationsDetected',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {'Name': 'UserID', 'Value': user_id},
                            {'Name': 'AccountID', 'Value': account_id},
                            {'Name': 'Region', 'Value': region}
                        ]
                    },
                    {
                        'MetricName': 'OperationCount',
                        'Value': operation_count,
                        'Unit': 'Count',
                        'Dimensions': [
                            {'Name': 'UserID', 'Value': user_id},
                            {'Name': 'AccountID', 'Value': account_id},
                            {'Name': 'Region', 'Value': region}
                        ]
                    }
                ]
            )
        except Exception as e:
            logger.error(f"Error sending CloudWatch metrics: {e}")
    
    def _get_user_details(self, user_identity: Dict[str, Any]) -> Dict[str, Any]:
        """Get additional details about the user."""
        try:
            user_type = user_identity.get('type')
            details = {'type': user_type}
            
            if user_type == 'IAMUser':
                user_name = user_identity.get('userName')
                if user_name:
                    try:
                        response = self.iam.get_user(UserName=user_name)
                        details['user_info'] = {
                            'creation_date': response['User']['CreateDate'].isoformat(),
                            'path': response['User']['Path'],
                            'user_id': response['User']['UserId']
                        }
                        # Get user policies
                        policies = self.iam.list_user_policies(UserName=user_name)
                        details['attached_policies'] = policies['PolicyNames']
                    except Exception as e:
                        logger.warning(f"Could not get user details for {user_name}: {e}")
                        details['error'] = str(e)
            
            elif user_type == 'AssumedRole':
                arn = user_identity.get('arn', '')
                if 'assumed-role' in arn:
                    role_name = arn.split('/')[1] if '/' in arn else 'unknown'
                    try:
                        response = self.iam.get_role(RoleName=role_name)
                        details['role_info'] = {
                            'creation_date': response['Role']['CreateDate'].isoformat(),
                            'path': response['Role']['Path'],
                            'role_id': response['Role']['RoleId']
                        }
                    except Exception as e:
                        logger.warning(f"Could not get role details for {role_name}: {e}")
                        details['error'] = str(e)
            
            return details
            
        except Exception as e:
            logger.error(f"Error getting user details: {e}")
            return {'type': user_identity.get('type', 'Unknown'), 'error': str(e)}
    
    def _create_alert_message(self, user_id: str, user_identity: Dict[str, Any], 
                            user_details: Dict[str, Any], operation_count: int, 
                            time_window: str, source_ip: str, account_id: str, 
                            region: str) -> Dict[str, Any]:
        """Create alert message for mass operations."""
        return {
            'alert_type': 'mass_operations_detected',
            'severity': 'HIGH',
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'user_identity': user_identity,
            'user_details': user_details,
            'operation_count': operation_count,
            'threshold': self.max_operations_per_minute,
            'time_window': time_window,
            'source_ip': source_ip,
            'account_id': account_id,
            'region': region,
            'description': f"User {user_id} performed {operation_count} security group operations "
                         f"in 1 minute (threshold: {self.max_operations_per_minute})",
            'recommended_actions': [
                "Investigate the user's activities immediately",
                "Check if this is legitimate bulk operation or potential attack",
                "Review security group changes made by this user",
                "Consider temporarily restricting user permissions",
                "Check for compromised credentials"
            ]
        }
    
    def _send_sns_alert(self, alert_message: Dict[str, Any]) -> None:
        """Send alert via SNS."""
        try:
            if self.sns_topic_arn:
                self.sns.publish(
                    TopicArn=self.sns_topic_arn,
                    Subject=f"🚨 MASS OPERATIONS DETECTED - {alert_message['user_id']}",
                    Message=json.dumps(alert_message, indent=2, default=str)
                )
        except Exception as e:
            logger.error(f"Error sending SNS alert: {e}")
    
    def _block_suspicious_user(self, user_identity: Dict[str, Any], 
                              user_details: Dict[str, Any]) -> Dict[str, Any]:
        """Block suspicious user (if configured and possible)."""
        try:
            # This is a placeholder for user blocking logic
            # In practice, you might:
            # 1. Attach a deny policy to the user
            # 2. Disable the user's access keys
            # 3. Remove user from groups
            # 4. Send to security team for manual review
            
            logger.warning("Suspicious user blocking is configured but not implemented in this demo")
            return {
                'action': 'block_configured_but_not_implemented',
                'reason': 'Feature requires careful implementation with proper safeguards'
            }
            
        except Exception as e:
            logger.error(f"Error blocking suspicious user: {e}")
            return {
                'action': 'block_failed',
                'error': str(e)
            }


def lambda_handler(event, context):
    """Lambda handler for mass operations detection."""
    try:
        logger.info(f"Processing mass operations detection event: {json.dumps(event)}")
        
        detector = MassOperationsDetector()
        result = detector.process_event(event)
        
        logger.info(f"Mass operations detection completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error in mass operations detection Lambda: {str(e)}")
        raise
