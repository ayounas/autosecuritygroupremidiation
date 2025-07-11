"""
Configuration Manager for Security Group Compliance Framework
Handles loading and caching of security policies and configuration
"""

import json
import logging
import boto3
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from botocore.exceptions import ClientError

from utils.exceptions import ConfigurationError

class ConfigManager:
    """Manages configuration loading and caching for the compliance framework"""
    
    def __init__(self, s3_bucket: str, kms_key_id: Optional[str] = None):
        """
        Initialize ConfigManager
        
        Args:
            s3_bucket: S3 bucket name for configuration storage
            kms_key_id: KMS key ID for decryption (optional)
        """
        self.s3_bucket = s3_bucket
        self.kms_key_id = kms_key_id
        self.s3_client = boto3.client('s3')
        self.ssm_client = boto3.client('ssm')
        
        # Cache for loaded configurations
        self._policy_cache = {}
        self._cache_timestamp = None
        self._cache_ttl_seconds = 300  # 5 minutes
        
        self.logger = logging.getLogger(__name__)
    
    def load_security_policies(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Load security policies from S3
        
        Args:
            force_refresh: Force refresh from S3 instead of using cache
            
        Returns:
            Dictionary containing security policies
        """
        # Check cache first
        if not force_refresh and self._is_cache_valid():
            self.logger.debug("Using cached security policies")
            return self._policy_cache
        
        try:
            self.logger.info("Loading security policies from S3")
            
            # Load main policies file
            policies = self._load_s3_json('config/security_policies.json')
            
            # Load any account-specific overrides
            account_overrides = self._load_account_overrides()
            if account_overrides:
                policies = self._merge_account_overrides(policies, account_overrides)
            
            # Validate policies structure
            self._validate_policies(policies)
            
            # Update cache
            self._policy_cache = policies
            self._cache_timestamp = datetime.now(timezone.utc)
            
            self.logger.info(f"Successfully loaded security policies (version: {policies.get('version', 'unknown')})")
            return policies
            
        except Exception as e:
            self.logger.error(f"Failed to load security policies: {str(e)}")
            raise ConfigurationError(f"Could not load security policies: {str(e)}")
    
    def load_framework_config(self) -> Dict[str, Any]:
        """
        Load framework configuration from SSM Parameter Store
        
        Returns:
            Dictionary containing framework configuration
        """
        try:
            parameter_name = self._get_ssm_parameter_name('config/compliance')
            
            response = self.ssm_client.get_parameter(
                Name=parameter_name,
                WithDecryption=True
            )
            
            config = json.loads(response['Parameter']['Value'])
            self.logger.debug("Loaded framework configuration from SSM")
            return config
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ParameterNotFound':
                self.logger.warning(f"Framework config parameter not found: {parameter_name}")
                return self._get_default_framework_config()
            else:
                raise ConfigurationError(f"Failed to load framework config: {str(e)}")
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in framework config: {str(e)}")
    
    def save_compliance_report(self, report_data: Dict[str, Any], report_id: str) -> str:
        """
        Save compliance report to S3
        
        Args:
            report_data: Report data to save
            report_id: Unique identifier for the report
            
        Returns:
            S3 key where report was saved
        """
        try:
            timestamp = datetime.now(timezone.utc).strftime('%Y/%m/%d')
            s3_key = f"audit-logs/{timestamp}/compliance-report-{report_id}.json"
            
            self.logger.info(f"Saving compliance report to S3: {s3_key}")
            
            # Add metadata to report
            report_with_metadata = {
                'report_id': report_id,
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'framework_version': self._get_framework_version(),
                'data': report_data
            }
            
            # Upload to S3
            self.s3_client.put_object(
                Bucket=self.s3_bucket,
                Key=s3_key,
                Body=json.dumps(report_with_metadata, indent=2, default=str),
                ContentType='application/json',
                ServerSideEncryption='aws:kms' if self.kms_key_id else 'AES256',
                SSEKMSKeyId=self.kms_key_id if self.kms_key_id else None,
                Metadata={
                    'report-type': 'compliance-scan',
                    'report-id': report_id,
                    'generated-by': 'security-group-compliance-framework'
                }
            )
            
            self.logger.info(f"Successfully saved compliance report: {s3_key}")
            return s3_key
            
        except Exception as e:
            self.logger.error(f"Failed to save compliance report: {str(e)}")
            raise ConfigurationError(f"Could not save compliance report: {str(e)}")
    
    def get_account_specific_config(self, account_id: str) -> Dict[str, Any]:
        """
        Get account-specific configuration overrides
        
        Args:
            account_id: AWS account ID
            
        Returns:
            Account-specific configuration
        """
        try:
            policies = self.load_security_policies()
            account_overrides = policies.get('account_specific_overrides', {})
            
            # Look for account-specific config
            account_config = account_overrides.get(f"account_{account_id}", {})
            
            if not account_config:
                # Check for pattern-based configs
                for key, config in account_overrides.items():
                    if key.startswith('pattern_') and self._matches_account_pattern(account_id, config):
                        account_config = config
                        break
            
            self.logger.debug(f"Account-specific config for {account_id}: {bool(account_config)}")
            return account_config
            
        except Exception as e:
            self.logger.warning(f"Could not load account-specific config for {account_id}: {str(e)}")
            return {}
    
    def get_exemptions(self, account_id: str, security_group_id: str) -> Dict[str, Any]:
        """
        Get exemptions for a specific security group
        
        Args:
            account_id: AWS account ID
            security_group_id: Security group ID
            
        Returns:
            Dictionary containing applicable exemptions
        """
        try:
            policies = self.load_security_policies()
            exemptions = policies.get('exemptions', {})
            
            applicable_exemptions = {}
            
            # Check security group specific exemptions
            sg_exemptions = exemptions.get('security_group_exemptions', {})
            if security_group_id in sg_exemptions:
                sg_exemption = sg_exemptions[security_group_id]
                if self._is_exemption_valid(sg_exemption):
                    applicable_exemptions['security_group'] = sg_exemption
            
            # Check account-wide exemptions
            account_exemptions = exemptions.get('account_exemptions', {})
            if account_id in account_exemptions:
                account_exemption = account_exemptions[account_id]
                if self._is_exemption_valid(account_exemption):
                    applicable_exemptions['account'] = account_exemption
            
            return applicable_exemptions
            
        except Exception as e:
            self.logger.warning(f"Could not load exemptions for {account_id}/{security_group_id}: {str(e)}")
            return {}
    
    def _load_s3_json(self, s3_key: str) -> Dict[str, Any]:
        """Load JSON file from S3"""
        try:
            response = self.s3_client.get_object(Bucket=self.s3_bucket, Key=s3_key)
            content = response['Body'].read().decode('utf-8')
            return json.loads(content)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                raise ConfigurationError(f"Configuration file not found: {s3_key}")
            else:
                raise ConfigurationError(f"Failed to load S3 file {s3_key}: {str(e)}")
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in {s3_key}: {str(e)}")
    
    def _load_account_overrides(self) -> Optional[Dict[str, Any]]:
        """Load account-specific override files"""
        try:
            # List all account override files
            response = self.s3_client.list_objects_v2(
                Bucket=self.s3_bucket,
                Prefix='config/accounts/'
            )
            
            if 'Contents' not in response:
                return None
            
            overrides = {}
            for obj in response['Contents']:
                if obj['Key'].endswith('.json'):
                    account_config = self._load_s3_json(obj['Key'])
                    account_id = obj['Key'].split('/')[-1].replace('.json', '')
                    overrides[account_id] = account_config
            
            return overrides if overrides else None
            
        except Exception as e:
            self.logger.warning(f"Could not load account overrides: {str(e)}")
            return None
    
    def _merge_account_overrides(self, base_policies: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
        """Merge account-specific overrides with base policies"""
        # This is a simplified merge - in production, you might want more sophisticated merging
        merged = base_policies.copy()
        
        if 'account_specific_overrides' not in merged:
            merged['account_specific_overrides'] = {}
        
        merged['account_specific_overrides'].update(overrides)
        return merged
    
    def _validate_policies(self, policies: Dict[str, Any]) -> None:
        """Validate the structure of loaded policies"""
        required_sections = ['compliance_policies', 'version']
        
        for section in required_sections:
            if section not in policies:
                raise ConfigurationError(f"Missing required policy section: {section}")
        
        # Validate compliance policies structure
        compliance_policies = policies['compliance_policies']
        required_policy_sections = ['prohibited_rules', 'global_rules']
        
        for section in required_policy_sections:
            if section not in compliance_policies:
                raise ConfigurationError(f"Missing required compliance policy section: {section}")
    
    def _is_cache_valid(self) -> bool:
        """Check if cached policies are still valid"""
        if not self._policy_cache or not self._cache_timestamp:
            return False
        
        cache_age = (datetime.now(timezone.utc) - self._cache_timestamp).total_seconds()
        return cache_age < self._cache_ttl_seconds
    
    def _get_ssm_parameter_name(self, suffix: str) -> str:
        """Get full SSM parameter name"""
        import os
        project_name = os.environ.get('PROJECT_NAME', 'sg-compliance')
        environment = os.environ.get('ENVIRONMENT', 'dev')
        return f"/{project_name}-{environment}/{suffix}"
    
    def _get_framework_version(self) -> str:
        """Get framework version from SSM"""
        try:
            parameter_name = self._get_ssm_parameter_name('metadata/version')
            response = self.ssm_client.get_parameter(Name=parameter_name)
            return response['Parameter']['Value']
        except:
            return 'unknown'
    
    def _get_default_framework_config(self) -> Dict[str, Any]:
        """Get default framework configuration"""
        import os
        return {
            'dry_run_mode': os.environ.get('DRY_RUN_MODE', 'true').lower() == 'true',
            'enable_automatic_remediation': os.environ.get('ENABLE_AUTOMATIC_REMEDIATION', 'false').lower() == 'true',
            'notification_settings': {
                'email_notifications': False,
                'sns_topic_arn': os.environ.get('SNS_TOPIC_ARN', '')
            }
        }
    
    def _matches_account_pattern(self, account_id: str, config: Dict[str, Any]) -> bool:
        """Check if account ID matches a pattern-based configuration"""
        # Implement pattern matching logic as needed
        # This is a placeholder for pattern-based account matching
        return False
    
    def _is_exemption_valid(self, exemption: Dict[str, Any]) -> bool:
        """Check if an exemption is still valid"""
        expiry_date = exemption.get('expiry_date')
        if not expiry_date or expiry_date == 'permanent':
            return True
        
        try:
            expiry = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
            return datetime.now(timezone.utc) < expiry
        except:
            self.logger.warning(f"Invalid expiry date format: {expiry_date}")
            return False
