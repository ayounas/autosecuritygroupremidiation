#!/bin/bash

# Security Group Compliance Framework Deployment Script
# This script deploys the infrastructure and Lambda function

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="dev"
AWS_REGION="us-east-1"
S3_BACKEND_BUCKET=""
TERRAFORM_DIR="terraform"
DRY_RUN=false
AUTO_APPROVE=false

# Function to print colored output
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    print_message $BLUE "Checking prerequisites..."
    
    # Check if terraform is installed
    if ! command -v terraform &> /dev/null; then
        print_message $RED "ERROR: Terraform is not installed or not in PATH"
        exit 1
    fi
    
    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        print_message $RED "ERROR: AWS CLI is not installed or not in PATH"
        exit 1
    fi
    
    # Check if AWS credentials are configured
    if ! aws sts get-caller-identity &> /dev/null; then
        print_message $RED "ERROR: AWS credentials are not configured"
        exit 1
    fi
    
    # Check if Python is installed
    if ! command -v python3 &> /dev/null; then
        print_message $RED "ERROR: Python 3 is not installed or not in PATH"
        exit 1
    fi
    
    print_message $GREEN "✓ All prerequisites met"
}

# Function to validate terraform configuration
validate_terraform() {
    print_message $BLUE "Validating Terraform configuration..."
    
    cd $TERRAFORM_DIR
    
    # Initialize terraform
    if [ -n "$S3_BACKEND_BUCKET" ]; then
        terraform init -backend-config="bucket=$S3_BACKEND_BUCKET"
    else
        terraform init
    fi
    
    # Validate configuration
    terraform validate
    
    # Format configuration
    terraform fmt -recursive
    
    print_message $GREEN "✓ Terraform configuration is valid"
    cd ..
}

# Function to create Lambda deployment package
create_lambda_package() {
    print_message $BLUE "Creating Lambda deployment package..."
    
    # Create dist directory
    mkdir -p dist
    
    # Remove old package
    rm -f dist/compliance-scanner.zip
    
    # Create temporary directory for package
    TEMP_DIR=$(mktemp -d)
    
    # Copy source files
    cp -r src/* $TEMP_DIR/
    
    # Install dependencies
    pip3 install -r src/requirements.txt -t $TEMP_DIR/ --quiet
    
    # Create zip package
    cd $TEMP_DIR
    zip -r ../compliance-scanner.zip . -q
    cd - > /dev/null
    
    # Move package to dist directory
    mv $TEMP_DIR/../compliance-scanner.zip dist/
    
    # Clean up
    rm -rf $TEMP_DIR
    
    print_message $GREEN "✓ Lambda deployment package created"
}

# Function to plan terraform deployment
plan_deployment() {
    print_message $BLUE "Planning Terraform deployment..."
    
    cd $TERRAFORM_DIR
    
    # Create terraform plan
    terraform plan -var="aws_region=$AWS_REGION" -var="environment=$ENVIRONMENT" -out=tfplan
    
    print_message $GREEN "✓ Terraform plan created"
    cd ..
}

# Function to apply terraform deployment
apply_deployment() {
    print_message $BLUE "Applying Terraform deployment..."
    
    cd $TERRAFORM_DIR
    
    if [ "$AUTO_APPROVE" = true ]; then
        terraform apply -auto-approve tfplan
    else
        terraform apply tfplan
    fi
    
    print_message $GREEN "✓ Infrastructure deployed successfully"
    cd ..
}

# Function to upload configuration files
upload_config() {
    print_message $BLUE "Uploading configuration files..."
    
    # Get S3 bucket name from terraform output
    cd $TERRAFORM_DIR
    S3_BUCKET=$(terraform output -raw s3_bucket_name)
    cd ..
    
    # Upload security policies
    aws s3 cp config/security_policies.json s3://$S3_BUCKET/config/security_policies.json
    
    print_message $GREEN "✓ Configuration files uploaded"
}

# Function to test deployment
test_deployment() {
    print_message $BLUE "Testing deployment..."
    
    cd $TERRAFORM_DIR
    LAMBDA_FUNCTION_NAME=$(terraform output -raw lambda_function_name)
    cd ..
    
    # Create test event
    cat > test_event.json << EOF
{
  "event_type": "manual_scan",
  "scan_config": {
    "dry_run": true,
    "enable_automatic_remediation": false,
    "scan_all_accounts": true
  }
}
EOF
    
    # Invoke Lambda function
    print_message $YELLOW "Invoking Lambda function for test..."
    aws lambda invoke \
        --function-name $LAMBDA_FUNCTION_NAME \
        --payload file://test_event.json \
        --cli-binary-format raw-in-base64-out \
        test_response.json
    
    # Check response
    if [ -f test_response.json ]; then
        print_message $GREEN "✓ Lambda function invoked successfully"
        print_message $BLUE "Response saved to test_response.json"
    else
        print_message $RED "ERROR: Lambda function test failed"
        exit 1
    fi
    
    # Clean up test files
    rm -f test_event.json test_response.json
}

# Function to display deployment outputs
show_outputs() {
    print_message $BLUE "Deployment Information:"
    
    cd $TERRAFORM_DIR
    echo ""
    terraform output
    echo ""
    
    print_message $GREEN "Deployment completed successfully!"
    print_message $YELLOW "Next steps:"
    echo "1. Review the CloudWatch dashboard for monitoring"
    echo "2. Configure SNS email subscriptions if needed"
    echo "3. Update security policies in S3 as required"
    echo "4. Set up cross-account roles in target accounts"
    cd ..
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -e, --environment ENV      Environment name (default: dev)"
    echo "  -r, --region REGION        AWS region (default: us-east-1)"
    echo "  -b, --backend-bucket BUCKET S3 bucket for Terraform state"
    echo "  -d, --dry-run              Plan only, don't apply"
    echo "  -y, --auto-approve         Auto-approve Terraform apply"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --environment prod --region us-west-2"
    echo "  $0 --dry-run"
    echo "  $0 --backend-bucket my-terraform-state-bucket"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -r|--region)
            AWS_REGION="$2"
            shift 2
            ;;
        -b|--backend-bucket)
            S3_BACKEND_BUCKET="$2"
            shift 2
            ;;
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -y|--auto-approve)
            AUTO_APPROVE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_message $RED "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main deployment flow
main() {
    print_message $GREEN "🚀 Starting Security Group Compliance Framework Deployment"
    print_message $BLUE "Environment: $ENVIRONMENT"
    print_message $BLUE "Region: $AWS_REGION"
    
    # Check prerequisites
    check_prerequisites
    
    # Create Lambda package
    create_lambda_package
    
    # Validate and initialize Terraform
    validate_terraform
    
    # Plan deployment
    plan_deployment
    
    if [ "$DRY_RUN" = true ]; then
        print_message $YELLOW "Dry run completed. Use --apply to deploy infrastructure."
        exit 0
    fi
    
    # Apply deployment
    apply_deployment
    
    # Upload configuration
    upload_config
    
    # Test deployment
    test_deployment
    
    # Show outputs
    show_outputs
}

# Run main function
main
