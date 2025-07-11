# AWS Security Group Compliance Framework - Architecture Documentation

## Overview

The AWS Security Group Compliance Framework is an event-driven, multi-account security remediation system built on AWS serverless technologies. It provides automated scanning, compliance checking, and remediation of security group violations across AWS organizations.

## High-Level Solution Architecture

```mermaid
graph TB
    subgraph "Management Account"
        CF[CloudFormation/Terraform]
        LAM[Lambda Function<br/>Compliance Handler]
        CW[CloudWatch]
        S3[S3 Config Store]
        SNS[SNS Notifications]
        SSM[Systems Manager<br/>Parameters]
        KMS[KMS Encryption]
    end
    
    subgraph "Target Account A"
        SG1[Security Groups]
        CT1[CloudTrail Events]
        EB1[EventBridge]
    end
    
    subgraph "Target Account B"
        SG2[Security Groups]
        CT2[CloudTrail Events]
        EB2[EventBridge]
    end
    
    subgraph "Target Account N"
        SGN[Security Groups]
        CTN[CloudTrail Events]
        EBN[EventBridge]
    end
    
    %% Event Flow
    SG1 -->|Security Group Changes| CT1
    SG2 -->|Security Group Changes| CT2
    SGN -->|Security Group Changes| CTN
    
    CT1 -->|API Events| EB1
    CT2 -->|API Events| EB2
    CTN -->|API Events| EBN
    
    EB1 -->|Cross-Account Rule| LAM
    EB2 -->|Cross-Account Rule| LAM
    EBN -->|Cross-Account Rule| LAM
    
    %% Configuration and Control
    S3 -->|Compliance Policies| LAM
    SSM -->|Runtime Config| LAM
    LAM -->|Assume Role| SG1
    LAM -->|Assume Role| SG2
    LAM -->|Assume Role| SGN
    
    %% Monitoring and Alerting
    LAM -->|Metrics & Logs| CW
    LAM -->|Violation Alerts| SNS
    KMS -->|Encryption| S3
    KMS -->|Encryption| SSM
    
    %% Management
    CF -->|Deploy/Update| LAM
    CF -->|Deploy/Update| S3
    CF -->|Deploy/Update| SNS
    
    classDef aws fill:#FF9900,stroke:#333,stroke-width:2px,color:#fff
    classDef lambda fill:#FF6B35,stroke:#333,stroke-width:2px,color:#fff
    classDef storage fill:#3F8C3F,stroke:#333,stroke-width:2px,color:#fff
    classDef security fill:#FF4444,stroke:#333,stroke-width:2px,color:#fff
    
    class CF,CW,SNS,EB1,EB2,EBN,CT1,CT2,CTN aws
    class LAM lambda
    class S3,SSM storage
    class SG1,SG2,SGN,KMS security
```

## Component Architecture

### Core Components

```mermaid
graph TD
    subgraph "Lambda Function Core"
        LH[Lambda Handler<br/>Entry Point]
        CM[ConfigManager<br/>Policy Management]
        CS[ComplianceScanner<br/>Violation Detection]
        SGR[SecurityGroupRemediator<br/>Enforcement Engine]
        MM[MetricsManager<br/>Observability]
    end
    
    subgraph "External Dependencies"
        S3C[S3 Config Store]
        EC2[EC2 API]
        CWL[CloudWatch Logs]
        CWM[CloudWatch Metrics]
        SNSN[SNS Notifications]
    end
    
    subgraph "Configuration Layer"
        CP[Compliance Policies<br/>JSON Configuration]
        RP[Runtime Parameters<br/>SSM Parameter Store]
        ENV[Environment Variables]
    end
    
    %% Flow connections
    LH --> CM
    LH --> CS
    LH --> SGR
    LH --> MM
    
    CM --> S3C
    CM --> RP
    CM --> ENV
    
    CS --> EC2
    CS --> CP
    
    SGR --> EC2
    SGR --> CWL
    
    MM --> CWM
    MM --> SNSN
    
    classDef core fill:#4A90E2,stroke:#333,stroke-width:2px,color:#fff
    classDef external fill:#FF9900,stroke:#333,stroke-width:2px,color:#fff
    classDef config fill:#50C878,stroke:#333,stroke-width:2px,color:#fff
    
    class LH,CM,CS,SGR,MM core
    class S3C,EC2,CWL,CWM,SNSN external
    class CP,RP,ENV config
```

## Event-Driven Processing Flow

```mermaid
sequenceDiagram
    participant SG as Security Group
    participant CT as CloudTrail
    participant EB as EventBridge
    participant LAM as Lambda Function
    participant EC2 as EC2 API
    participant S3 as S3 Config
    participant SNS as SNS Topic
    participant CW as CloudWatch
    
    Note over SG,CW: Real-time Security Group Change Detection
    
    SG->>CT: Security Group Modified<br/>(AuthorizeSecurityGroupIngress)
    CT->>EB: API Event Published
    EB->>LAM: Event Trigger<br/>(Cross-Account Rule)
    
    Note over LAM: Lambda Function Processing
    
    LAM->>S3: Load Compliance Policies
    S3-->>LAM: Policy Configuration
    
    LAM->>EC2: Assume Cross-Account Role
    LAM->>EC2: DescribeSecurityGroups
    EC2-->>LAM: Security Group Details
    
    LAM->>LAM: Scan for Violations<br/>(ComplianceScanner)
    
    alt Violations Found
        LAM->>EC2: Backup Security Group<br/>(CreateTags)
        LAM->>EC2: Apply Remediation<br/>(RevokeSecurityGroupIngress)
        LAM->>SNS: Send Violation Alert
        SNS-->>LAM: Notification Sent
        LAM->>CW: Log Violation Details
        LAM->>CW: Send Metrics
    else No Violations
        LAM->>CW: Log Compliance Status
        LAM->>CW: Send Success Metrics
    end
    
    Note over LAM,CW: Audit Trail and Monitoring
```

## Compliance Scanning Workflow

```mermaid
flowchart TD
    START([Event Received]) --> VALIDATE{Validate Event}
    VALIDATE -->|Valid| LOAD[Load Configuration]
    VALIDATE -->|Invalid| ERROR[Log Error & Exit]
    
    LOAD --> ASSUME[Assume Cross-Account Role]
    ASSUME --> DESCRIBE[Describe Security Groups]
    
    DESCRIBE --> SCAN{Scan for Violations}
    
    SCAN -->|No Violations| COMPLIANT[Mark as Compliant]
    SCAN -->|Violations Found| BACKUP[Create Backup Tags]
    
    BACKUP --> REMEDIATE{Remediation Type}
    
    REMEDIATE -->|Flag Only| FLAG[Add Violation Tags]
    REMEDIATE -->|Remove Rules| REMOVE[Revoke Ingress Rules]
    REMEDIATE -->|Emergency Mode| EMERGENCY[Complete Lockdown]
    
    FLAG --> NOTIFY[Send SNS Alert]
    REMOVE --> NOTIFY
    EMERGENCY --> NOTIFY
    
    NOTIFY --> METRICS[Record Metrics]
    COMPLIANT --> METRICS
    
    METRICS --> AUDIT[Write Audit Log]
    AUDIT --> END([Complete])
    ERROR --> END
    
    classDef process fill:#4A90E2,stroke:#333,stroke-width:2px,color:#fff
    classDef decision fill:#FFA500,stroke:#333,stroke-width:2px,color:#fff
    classDef action fill:#50C878,stroke:#333,stroke-width:2px,color:#fff
    classDef terminal fill:#FF6B6B,stroke:#333,stroke-width:2px,color:#fff
    
    class LOAD,ASSUME,DESCRIBE,BACKUP,FLAG,REMOVE,EMERGENCY,NOTIFY,METRICS,AUDIT process
    class VALIDATE,SCAN,REMEDIATE decision
    class COMPLIANT action
    class START,END,ERROR terminal
```

## Security and IAM Architecture

```mermaid
graph TB
    subgraph "Management Account"
        LER[Lambda Execution Role]
        LEP[Lambda Execution Policy]
    end
    
    subgraph "Target Account Cross-Account Setup"
        CAR[Cross-Account Role]
        CAP[Cross-Account Policy]
        TRUST[Trust Relationship]
    end
    
    subgraph "AWS Services"
        EC2SG[EC2 Security Groups]
        S3B[S3 Buckets]
        CWLOGS[CloudWatch Logs]
        SSMPS[SSM Parameter Store]
        SNST[SNS Topics]
    end
    
    subgraph "Policy Permissions"
        SGREAD[Security Group Read<br/>DescribeSecurityGroups<br/>DescribeSecurityGroupRules]
        SGWRITE[Security Group Write<br/>AuthorizeSecurityGroup*<br/>RevokeSecurityGroup*]
        SGTAG[Security Group Tagging<br/>CreateTags<br/>DeleteTags]
        GENREAD[General Read Only<br/>DescribeTags<br/>DescribeVpcs<br/>DescribeNetworkInterfaces]
    end
    
    %% Role Relationships
    LER -->|Attached| LEP
    CAR -->|Attached| CAP
    LER -->|AssumeRole| CAR
    
    %% Trust Relationship
    TRUST -->|Allows| LER
    CAR -->|Configured With| TRUST
    
    %% Permission Mappings
    LEP -->|Grants| SGREAD
    LEP -->|Grants| SGWRITE
    LEP -->|Grants| SGTAG
    LEP -->|Grants| GENREAD
    
    CAP -->|Grants| SGREAD
    CAP -->|Grants| SGWRITE
    CAP -->|Grants| SGTAG
    CAP -->|Grants| GENREAD
    
    %% Service Access
    SGREAD -->|Access| EC2SG
    SGWRITE -->|Modify| EC2SG
    SGTAG -->|Tag| EC2SG
    GENREAD -->|Describe| EC2SG
    
    LEP -->|Access| S3B
    LEP -->|Write| CWLOGS
    LEP -->|Read| SSMPS
    LEP -->|Publish| SNST
    
    classDef role fill:#FF6B35,stroke:#333,stroke-width:2px,color:#fff
    classDef policy fill:#4A90E2,stroke:#333,stroke-width:2px,color:#fff
    classDef service fill:#FF9900,stroke:#333,stroke-width:2px,color:#fff
    classDef permission fill:#50C878,stroke:#333,stroke-width:2px,color:#fff
    
    class LER,CAR role
    class LEP,CAP,TRUST policy
    class EC2SG,S3B,CWLOGS,SSMPS,SNST service
    class SGREAD,SGWRITE,SGTAG,GENREAD permission
```

## Multi-Account Deployment Model

```mermaid
graph TD
    subgraph "Organization Management Account"
        ORG[AWS Organizations]
        MGMT[Management Resources]
        DEPLOY[Deployment Pipeline]
    end
    
    subgraph "Security/Compliance Account"
        LAM[Lambda Functions]
        CONFIG[Configuration Store]
        MONITOR[Monitoring & Alerting]
        AUDIT[Audit Logging]
    end
    
    subgraph "Production Accounts"
        PROD1[Production Account 1<br/>Cross-Account Role]
        PROD2[Production Account 2<br/>Cross-Account Role]
        PRODN[Production Account N<br/>Cross-Account Role]
    end
    
    subgraph "Non-Production Accounts"
        DEV[Development Account<br/>Cross-Account Role]
        TEST[Testing Account<br/>Cross-Account Role]
        STAGE[Staging Account<br/>Cross-Account Role]
    end
    
    %% Organizational Structure
    ORG -->|Manages| PROD1
    ORG -->|Manages| PROD2
    ORG -->|Manages| PRODN
    ORG -->|Manages| DEV
    ORG -->|Manages| TEST
    ORG -->|Manages| STAGE
    
    %% Deployment Flow
    DEPLOY -->|Deploy Infrastructure| LAM
    DEPLOY -->|Deploy Configuration| CONFIG
    DEPLOY -->|Setup Cross-Account| PROD1
    DEPLOY -->|Setup Cross-Account| PROD2
    DEPLOY -->|Setup Cross-Account| PRODN
    DEPLOY -->|Setup Cross-Account| DEV
    DEPLOY -->|Setup Cross-Account| TEST
    DEPLOY -->|Setup Cross-Account| STAGE
    
    %% Runtime Access
    LAM -->|AssumeRole| PROD1
    LAM -->|AssumeRole| PROD2
    LAM -->|AssumeRole| PRODN
    LAM -->|AssumeRole| DEV
    LAM -->|AssumeRole| TEST
    LAM -->|AssumeRole| STAGE
    
    %% Monitoring Flow
    PROD1 -->|Events| MONITOR
    PROD2 -->|Events| MONITOR
    PRODN -->|Events| MONITOR
    DEV -->|Events| MONITOR
    TEST -->|Events| MONITOR
    STAGE -->|Events| MONITOR
    
    MONITOR -->|Audit Trail| AUDIT
    
    classDef mgmt fill:#8A2BE2,stroke:#333,stroke-width:2px,color:#fff
    classDef security fill:#FF6B35,stroke:#333,stroke-width:2px,color:#fff
    classDef prod fill:#FF4444,stroke:#333,stroke-width:2px,color:#fff
    classDef nonprod fill:#4A90E2,stroke:#333,stroke-width:2px,color:#fff
    
    class ORG,MGMT,DEPLOY mgmt
    class LAM,CONFIG,MONITOR,AUDIT security
    class PROD1,PROD2,PRODN prod
    class DEV,TEST,STAGE nonprod
```

## Data Flow and State Management

```mermaid
stateDiagram-v2
    [*] --> EventReceived: Security Group Change
    
    EventReceived --> ValidatingEvent: Parse CloudTrail Event
    ValidatingEvent --> LoadingConfig: Event Valid
    ValidatingEvent --> ErrorState: Invalid Event
    
    LoadingConfig --> AssumeRole: Config Loaded
    LoadingConfig --> ErrorState: Config Load Failed
    
    AssumeRole --> ScanningGroups: Role Assumed
    AssumeRole --> ErrorState: Assume Role Failed
    
    ScanningGroups --> Compliant: No Violations Found
    ScanningGroups --> ViolationsFound: Policy Violations Detected
    ScanningGroups --> ErrorState: Scan Failed
    
    ViolationsFound --> CreatingBackup: Start Remediation
    CreatingBackup --> DetermineAction: Backup Created
    CreatingBackup --> ErrorState: Backup Failed
    
    DetermineAction --> FlagOnly: flag_only_mode
    DetermineAction --> RemoveRules: remove_non_compliant_rules
    DetermineAction --> EmergencyMode: emergency_remediation
    
    FlagOnly --> NotifyViolation: Tags Applied
    RemoveRules --> NotifyViolation: Rules Removed
    EmergencyMode --> NotifyViolation: Complete Lockdown
    
    NotifyViolation --> RecordMetrics: Notification Sent
    Compliant --> RecordMetrics: Log Compliance
    
    RecordMetrics --> AuditLog: Metrics Recorded
    AuditLog --> [*]: Process Complete
    
    ErrorState --> RecordError: Log Error Details
    RecordError --> [*]: Error Handled
```

## Technology Stack

### Infrastructure Layer
- **Terraform**: Infrastructure as Code for AWS resource provisioning
- **AWS Lambda**: Serverless compute for compliance processing
- **AWS IAM**: Identity and access management with cross-account roles
- **AWS EventBridge**: Event-driven architecture for real-time processing
- **AWS CloudTrail**: API call auditing and change detection

### Data and Configuration Layer
- **AWS S3**: Configuration storage and backup repository
- **AWS Systems Manager**: Parameter store for runtime configuration
- **AWS KMS**: Encryption for data at rest and in transit
- **JSON**: Policy definition and configuration format

### Monitoring and Observability
- **AWS CloudWatch**: Logging, metrics, and monitoring
- **AWS SNS**: Notification and alerting system
- **Custom Metrics**: Business-specific compliance metrics
- **Structured Logging**: JSON-formatted audit trails

### Development and Deployment
- **Python 3.11**: Lambda runtime for business logic
- **boto3/botocore**: AWS SDK for Python
- **GitHub Actions**: CI/CD pipeline automation
- **Checkov**: Infrastructure security scanning

## Security Features

### Defense in Depth
1. **Least Privilege IAM**: Granular permissions with resource-specific ARNs
2. **Cross-Account Isolation**: Separate execution and target account boundaries
3. **Encryption**: KMS encryption for all data at rest and parameter storage
4. **Audit Logging**: Comprehensive CloudTrail and application logging
5. **Network Security**: VPC-based deployment with security group controls

### Compliance Controls
1. **Policy Validation**: Schema-based configuration validation
2. **Change Tracking**: Full audit trail of all remediation actions
3. **Rollback Capability**: Backup tags enable violation rollback
4. **Non-Disruptive Mode**: Flag-only mode for initial deployment
5. **Emergency Response**: Rapid lockdown capabilities for critical violations

### Operational Security
1. **Idempotent Operations**: Safe to run multiple times without side effects
2. **Error Handling**: Graceful failure with detailed error reporting
3. **Rate Limiting**: Controlled API usage to prevent service limits
4. **State Management**: Stateless design with external configuration
5. **Monitoring**: Real-time alerting for security violations and system errors

## Scalability and Performance

### Horizontal Scaling
- **Event-Driven**: Automatic scaling based on security group changes
- **Multi-Account**: Supports unlimited target accounts
- **Regional Deployment**: Per-region Lambda deployments for performance
- **Concurrent Processing**: Parallel processing of multiple accounts

### Performance Optimization
- **Efficient Scanning**: Targeted security group queries
- **Caching**: Configuration caching to reduce S3 API calls
- **Batch Operations**: Group operations for improved throughput
- **Regional Constraints**: Limit operations to specific AWS regions

This architecture provides a robust, scalable, and secure foundation for automated security group compliance across multi-account AWS environments while maintaining operational simplicity and comprehensive auditability.
