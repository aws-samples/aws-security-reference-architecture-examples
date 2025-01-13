# SRA Bedrock Organizations Solution

## Table of Contents
- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)
- [JSON Parameters Explanation](#json-parameters-explanation)

---

## Introduction

This solution provides an automated framework for deploying Bedrock organizational security controls using AWS CloudFormation. It leverages a Lambda function to configure and deploy AWS Config rules, CloudWatch metrics, and other resources necessary to monitor and enforce governance policies across multiple AWS accounts and regions in an organization.

The architecture follows best practices for security and scalability and is designed for easy extensibility.

---

## Deployed Resource Details

![Architecture Diagram](./documentation/bedrock-org.png)

This section provides a detailed explanation of the resources shown in the updated architecture diagram:

### Organization Management Account
- **(1.1) AWS CloudFormation**: Used to define and deploy resources in the solution.
- **CloudWatch Lambda Role (1.2)**: Role for enabling CloudWatch access by the Lambda function in the global region.
- **SNS Topic (1.3)**: SNS publish to Lambda. Handles fanout configuration of the solution.
- **Bedrock Lambda Function (1.4)**: Core function responsible for deploying resources and managing configurations across accounts and regions.
- **CloudWatch Log Group (1.5)**: Logs for monitoring the execution of the Lambda function.
- **Dead-Letter Queue (DLQ) (1.6)**: Handles failed Lambda invocations.
- **CloudWatch Filters (1.7)**: Filters specific log events to track relevant activities.
- **CloudWatch Alarms (1.8)**: Triggers notifications based on preconfigured thresholds.
- **SNS Topic (1.9)**: Publishes notifications for alarms and events.
10. **CloudWatch Link (1.10)**: Links CloudWatch metrics across accounts and regions for centralized observability.
11. **KMS Key (1.11)**: Encrypts SNS topic.

### All Bedrock Accounts
1. **CloudWatch Sharing Role (2.1)**: Role enabling CloudWatch metrics sharing.
2. **CloudWatch Filters (2.2)**: Region-specific filters to monitor log events for compliance and security.
3. **CloudWatch Alarms (2.3)**: Configured to trigger notifications for specific metric thresholds.
4. **SNS Topic (2.4)**: Publishes notifications for alarms and events in the respective regions.
5. **CloudWatch Link (2.5)**: Links metrics from regional accounts back to the Organization Management Account.
6. **KMS Key (2.6)**: Encrypts SNS topic.
7. **Rule Lambda Roles (2.7)**: Lambda execution roles for AWS Config rules.
8. **Config Rules (2.8)**: Enforces governance and compliance policies.
9. **Config Lambdas (2.9)**: Evaluates and remediates non-compliance with governance policies.

### Audit (Security Tooling) Account
1. **Resource Table (3.1)**: Maintains metadata for tracking deployed resources and configurations.
2. **CloudWatch Dashboard (3.2)**: Provides a centralized view of the security and compliance state across accounts and regions.
3. **CloudWatch Sink (3.3)**: Aggregates logs and metrics from other accounts and regions for analysis and auditing.

---

## Implementation Instructions

You can deploy this solution using the AWS Management Console or AWS CLI.

### Deploying via AWS Management Console
1. Open the [CloudFormation Console](https://console.aws.amazon.com/cloudformation).
2. Create a new stack by uploading the `sra-bedrock-org-main.yaml` template located in the `./templates` directory.
3. Provide the required parameters such as the email for SNS notifications and other configuration details.
4. Review and confirm the stack creation.

### Deploying via AWS CLI
1. Run the following command to deploy the stack:

```bash
aws cloudformation create-stack \
    --stack-name BedrockOrg \
    --template-body file://templates/sra-bedrock-org-main.yaml \
    --parameters \
        ParameterKey=pSRARepoZipUrl,ParameterValue=https://github.com/aws-samples/aws-security-reference-architecture-examples/archive/refs/heads/main.zip \
        ParameterKey=pDryRun,ParameterValue=false \
        ParameterKey=pSRAExecutionRoleName,ParameterValue=sra-execution-role \
        ParameterKey=pDeployLambdaLogGroup,ParameterValue=true \
        ParameterKey=pLogGroupRetention,ParameterValue=30 \
        ParameterKey=pLambdaLogLevel,ParameterValue=INFO \
        ParameterKey=pSRASolutionName,ParameterValue=sra-bedrock-org \
        ParameterKey=pSRASolutionVersion,ParameterValue=1.0.0 \
        ParameterKey=pSRAAlarmEmail,ParameterValue=alerts@examplecorp.com \
        ParameterKey=pSRAStagingS3BucketName,ParameterValue=staging-artifacts-bucket \
        ParameterKey=pBedrockOrgLambdaRoleName,ParameterValue=sra-bedrock-org-lambda-role \
        ParameterKey=pBedrockAccounts,ParameterValue='["123456789012","234567890123"]' \
        ParameterKey=pBedrockRegions,ParameterValue='["us-east-1","us-west-2"]' \
        ParameterKey=pBedrockModelEvalBucketRuleParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "input_params": {"BucketNamePrefix": "evaluation-bucket","CheckRetention": "true", "CheckEncryption": "true", "CheckLogging": "true", "CheckObjectLocking": "true", "CheckVersioning": "true"}}' \
        ParameterKey=pBedrockIAMUserAccessRuleParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "input_params": {}}' \
        ParameterKey=pBedrockGuardrailsRuleParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "input_params": {"content_filters": "true", "denied_topics": "true", "word_filters": "true", "sensitive_info_filters": "true", "contextual_grounding": "true"}}' \
        ParameterKey=pBedrockVPCEndpointsRuleParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "input_params": {"check_bedrock": "true", "check_bedrock_agent": "true", "check_bedrock_agent_runtime": "true", "check_bedrock_runtime": "true"}}' \
        ParameterKey=pBedrockInvocationLogCWRuleParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "input_params": {"check_retention": "true", "check_encryption": "true"}}' \
        ParameterKey=pBedrockInvocationLogS3RuleParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "input_params": {"check_retention": "true", "check_encryption": "true", "check_access_logging": "true", "check_object_locking": "true", "check_versioning": "true"}}' \
        ParameterKey=pBedrockCWEndpointsRuleParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "input_params": {}}' \
        ParameterKey=pBedrockS3EndpointsRuleParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "input_params": {}}' \
        ParameterKey=pBedrockGuardrailEncryptionRuleParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "input_params": {}}' \
        ParameterKey=pBedrockServiceChangesFilterParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "filter_params": {"log_group_name": "aws-controltower/CloudTrailLogs"}}' \
        ParameterKey=pBedrockBucketChangesFilterParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "filter_params": {"log_group_name": "aws-controltower/CloudTrailLogs", "bucket_names": ["my-bucket-name"]}}' \
        ParameterKey=pBedrockPromptInjectionFilterParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "filter_params": {"log_group_name": "invocation-log-group", "input_path": "input.inputBodyJson.messages[0].content"}}' \
        ParameterKey=pBedrockSensitiveInfoFilterParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "filter_params": {"log_group_name": "invocation-log-group", "input_path": "input.inputBodyJson.messages[0].content"}}' \
        ParameterKey=pBedrockCentralObservabilityParams,ParameterValue='{"deploy": "true", "bedrock_accounts": ["123456789012"], "regions": ["us-east-1"]}' \
    --capabilities CAPABILITY_NAMED_IAM
```

#### Notes:
- Replace alerts@examplecorp.com, my-staging-bucket, and other parameter values with your specific settings.
- Ensure the JSON strings (e.g., pBedrockAccounts, pBedrockModelEvalBucketRuleParams) are formatted correctly and match your deployment requirements.
- This example assumes the CloudFormation template file is saved in the templates directory. Adjust the --template-body path if necessary.
- Always validate the JSON parameters for correctness to avoid deployment errors.
- Ensure the --capabilities CAPABILITY_NAMED_IAM flag is included to allow CloudFormation to create the necessary IAM resources.
- An example test fork URL for `pSRARepoZipUrl` is - `https://github.com/liamschn/aws-security-reference-architecture-examples/archive/refs/heads/sra-genai.zip`
- The eval job bucket config rule will append `-<ACCOUNTID>-<REGION>` to the `BucketNamePrefix` parameter provided to get the existing bucket name(s).  Ensure any S3 eval job bucket names to be checked match this naming convention.


2. Monitor the stack creation progress in the AWS CloudFormation Console or via CLI commands.

### Post-Deployment
Once the stack is deployed, the Bedrock Lambda function (`sra-bedrock-org`) will automatically deploy all the resources and configurations across the accounts and regions specified in the parameters.

---

## References
- [AWS SRA Generative AI Deep-Dive](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/gen-ai-sra.html)
- [AWS CloudFormation Documentation](https://docs.aws.amazon.com/cloudformation/index.html)
- [AWS Config Rules](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html)
- [CloudWatch Metrics and Alarms](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html)
- [AWS Lambda](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html)
- [AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html)


## JSON Parameters Explanation

This section explains the parameters in the CloudFormation template that require JSON string values. Each parameter's structure and purpose are described in detail to assist in their configuration.

### `pBedrockModelEvalBucketRuleParams`
- **Purpose**: Configures a rule to validate a Bedrock Model Evaluation bucket. NOTE: `-<ACCOUNTID>-<REGION>` will be appended to get the existing bucket name(s).  Ensure any S3 eval job bucket names to be checked match this naming convention.
- **Structure**:
  {
    "deploy": "true|false",
    "accounts": ["account_id1", "account_id2"],
    "regions": ["region1", "region2"],
    "input_params": {
      "BucketNamePrefix": "bucket-name"
      "CheckRetention": "true|false",
      "CheckEncryption": "true|false",
      "CheckLogging": "true|false",
      "CheckObjectLocking": "true|false",
      "CheckVersioning": "true|false",

    }
  }
- **Fields**:
  - `deploy`: Whether the rule should be deployed (`true` or `false`).
  - `accounts`: List of account IDs to apply the rule.
  - `regions`: List of regions to apply the rule.
  - `input_params.BucketName`: Name of the evaluation bucket.

---

### `pBedrockGuardrailsRuleParams`
- **Purpose**: Enforces governance guardrails for Bedrock resources.
- **Structure**:
  {
    "deploy": "true|false",
    "accounts": ["account_id1", "account_id2"],
    "regions": ["region1", "region2"],
    "input_params": {
      "content_filters": "true|false",
      "denied_topics": "true|false",
      "word_filters": "true|false",
      "sensitive_info_filters": "true|false",
      "contextual_grounding": "true|false"
    }
  }
- **Fields**:
  - `deploy`: Whether the rule should be deployed.
  - `accounts`: List of account IDs.
  - `regions`: List of regions.
  - `input_params`: Specifies guardrail options (`true` or `false` for each filter).

---

### `pBedrockInvocationLogCWRuleParams`
- **Purpose**: Validates CloudWatch logging for model invocations.
- **Structure**:
  {
    "deploy": "true|false",
    "accounts": ["account_id1", "account_id2"],
    "regions": ["region1", "region2"],
    "input_params": {
      "check_retention": "true|false",
      "check_encryption": "true|false"
    }
  }
- **Fields**:
  - `deploy`: Whether the rule should be deployed.
  - `accounts`: List of account IDs.
  - `regions`: List of regions.
  - `input_params.check_retention`: Ensures log retention is configured.
  - `input_params.check_encryption`: Ensures logs are encrypted.

---

### `pBedrockInvocationLogS3RuleParams`
- **Purpose**: Validates S3 logging for model invocations.
- **Structure**:
  {
    "deploy": "true|false",
    "accounts": ["account_id1", "account_id2"],
    "regions": ["region1", "region2"],
    "input_params": {
      "check_retention": "true|false",
      "check_encryption": "true|false",
      "check_access_logging": "true|false",
      "check_object_locking": "true|false",
      "check_versioning": "true|false"
    }
  }
- **Fields**:
  - `deploy`: Whether the rule should be deployed.
  - `accounts`: List of account IDs.
  - `regions`: List of regions.
  - `input_params.check_retention`: Ensures bucket retention policies are configured.
  - `input_params.check_encryption`: Ensures bucket encryption is enabled.
  - `input_params.check_access_logging`: Ensures bucket access logging is enabled.
  - `input_params.check_object_locking`: Ensures bucket object locking is enabled.
  - `input_params.check_versioning`: Ensures bucket versioning is enabled.

---

### `pBedrockCWEndpointsRuleParams`
- **Purpose**: Validates CloudWatch VPC endpoints.
- **Structure**:
  {
    "deploy": "true|false",
    "accounts": ["account_id1", "account_id2"],
    "regions": ["region1", "region2"],
    "input_params": {}
  }
- **Fields**:
  - `deploy`: Whether the rule should be deployed.
  - `accounts`: List of account IDs.
  - `regions`: List of regions.
  - `input_params`: This field is currently empty.

---

### `pBedrockS3EndpointsRuleParams`
- **Purpose**: Validates S3 VPC endpoints.
- **Structure**:
  {
    "deploy": "true|false",
    "accounts": ["account_id1", "account_id2"],
    "regions": ["region1", "region2"],
    "input_params": {}
  }
- **Fields**:
  - `deploy`: Whether the rule should be deployed.
  - `accounts`: List of account IDs.
  - `regions`: List of regions.
  - `input_params`: This field is currently empty.

---

### `pBedrockServiceChangesFilterParams`
- **Purpose**: Tracks changes to services in CloudTrail logs.
- **Structure**:
  {
    "deploy": "true|false",
    "accounts": ["account_id1", "account_id2"],
    "regions": ["region1", "region2"],
    "filter_params": {
      "log_group_name": "log-group-name"
    }
  }
- **Fields**:
  - `deploy`: Whether the filter should be deployed.
  - `accounts`: List of account IDs.
  - `regions`: List of regions.
  - `filter_params.log_group_name`: Name of the log group to monitor for changes.

---

### `pBedrockBucketChangesFilterParams`
- **Purpose**: Monitors S3 bucket changes in CloudTrail logs.
- **Structure**:
  {
    "deploy": "true|false",
    "accounts": ["account_id1", "account_id2"],
    "regions": ["region1", "region2"],
    "filter_params": {
      "log_group_name": "log-group-name",
      "bucket_names": ["bucket1", "bucket2"]
    }
  }
- **Fields**:
  - `deploy`: Whether the filter should be deployed.
  - `accounts`: List of account IDs.
  - `regions`: List of regions.
  - `filter_params.log_group_name`: Name of the log group to monitor.
  - `filter_params.bucket_names`: List of bucket names to track.

---

### `pBedrockPromptInjectionFilterParams`
- **Purpose**: Filters prompt injection attempts in logs.
- **Structure**:
  {
    "deploy": "true|false",
    "accounts": ["account_id1", "account_id2"],
    "regions": ["region1", "region2"],
    "filter_params": {
      "log_group_name": "log-group-name",
      "input_path": "path.to.input"
    }
  }
- **Fields**:
  - `deploy`: Whether the filter should be deployed.
  - `accounts`: List of account IDs.
  - `regions`: List of regions.
  - `filter_params.log_group_name`: Name of the log group to monitor.
  - `filter_params.input_path`: Path to the input field to check.

---

### `pBedrockSensitiveInfoFilterParams`
- **Purpose**: Filters sensitive information from logs.
- **Structure**:
  {
    "deploy": "true|false",
    "accounts": ["account_id1", "account_id2"],
    "regions": ["region1", "region2"],
    "filter_params": {
      "log_group_name": "log-group-name",
      "input_path": "path.to.sensitive.data"
    }
  }
- **Fields**:
  - `deploy`: Whether the filter should be deployed.
  - `accounts`: List of account IDs.
  - `regions`: List of regions.
  - `filter_params.log_group_name`: The name of the log group to filter.
  - `filter_params.input_path`: Path to the data field containing sensitive information.

---

### `pBedrockCentralObservabilityParams`
- **Purpose**: Configures central observability for Bedrock accounts.
- **Structure**:
  {
    "deploy": "true|false",
    "bedrock_accounts": ["account_id1", "account_id2"],
    "regions": ["region1", "region2"]
  }
- **Fields**:
  - `deploy`: Whether central observability should be deployed.
  - `bedrock_accounts`: List of Bedrock account IDs.
  - `regions`: List of regions.
