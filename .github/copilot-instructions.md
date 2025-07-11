<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# AWS Security Group Remediation Framework - Copilot Instructions

This is a Terraform-based AWS infrastructure project for automatically remediating security group vulnerabilities and managing security compliance.

## Project Context
- Infrastructure as Code using Terraform
- Focus on automated security remediation
- AWS-native security monitoring and response
- Event-driven architecture for real-time remediation


## Terraform Standards
- Use Terraform best practices and create separate .tf files per resource type
- Follow consistent file naming: `<service>-<resource-type>.tf` (e.g., `ec2-security-groups.tf`)
- Follow AWS naming conventions with consistent prefixes
- Tag every resource using a comprehensive tag map with required tags
- Use data sources where appropriate to avoid hardcoding
- Include comprehensive variable descriptions with type constraints
- Add output values for all important resources and their ARNs
- Use locals block for computed values and complex expressions
- Implement proper module structure when code becomes reusable
- Use terraform fmt and terraform validate before commits
- Document resources with inline comments explaining business logic

## Variable Management
- Use `variables.tf` for all input variables
- Use `terraform.tfvars.example` to document expected variables
- Implement variable validation rules where applicable
- Use sensitive = true for sensitive variables
- Group related variables logically with clear descriptions

## AWS Services Used
- **IAM** for permissions and role management
- **EC2 Security Groups** for network access control
- **CloudWatch** for monitoring and alerting
- **Lambda** for automated remediation functions
- **EventBridge** for event-driven architecture
- **S3** for terraform state and logging storage
- **SNS** for notifications
- **Systems Manager** for parameter storage
- **CloudTrail** for audit logging

## Security Considerations
- Use least privilege IAM policies
- Encrypt sensitive parameters using AWS Systems Manager Parameter Store (SecureString)
- Secure S3 bucket access with bucket policies and ACLs
- Ensure all S3 buckets are private by default
- Avoid using wildcards (*) in IAM policies - fetch specific resource ARNs from data sources, outputs, or construct dynamically
- Implement proper security group rules with specific ports and sources
- Use Terraform's sensitive variables for handling secrets
- Implement S3-based state locking with `use_lockfile = true`
- Enable encryption at rest for all storage services
- Use KMS keys for encryption with proper key rotation
- Implement VPC flow logs for network monitoring
- Enable CloudTrail for all API calls

## Error Handling & Monitoring
- Implement comprehensive error handling in Lambda functions
- Use CloudWatch alarms for critical metrics
- Set up SNS notifications for failures
- Include retry logic with exponential backoff
- Log all remediation actions for audit trails
- Use structured logging (JSON format)
- Implement dead letter queues for failed events


## Development Guidelines
When suggesting code changes or new features, consider:
1. **Code Quality**: Ensure readability, maintainability, and proper documentation
2. **Security First**: All security considerations must be implemented by default
3. **Environment Separation**: Support for multiple environments (dev/staging/prod)
4. **Error Handling**: Comprehensive error handling and graceful failure recovery
5. **Logging & Monitoring**: Structured logging and proper observability
6. **Backward Compatibility**: Do not change functionality of existing code when making changes
7. **Testing**: Include unit tests for Lambda functions and integration tests for infrastructure
8. **Performance**: Consider cost optimization and resource efficiency
9. **Compliance**: Ensure all solutions meet security and compliance requirements
10. **Documentation**: Include inline comments and README updates for complex logic
 