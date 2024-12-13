# SRA Bedrock Organizations Solution

## Table of Contents
- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)

---

## Introduction

This solution provides an automated framework for deploying Bedrock organizational controls using AWS CloudFormation. It leverages a Lambda function to configure and deploy AWS Config rules, CloudWatch metrics, and other resources necessary to monitor and enforce governance policies across multiple AWS accounts and regions in an organization.

The architecture follows best practices for security and scalability and is designed for easy extensibility.

---

## Deployed Resource Details

![Architecture Diagram](./documentation/bedrock-org.png)

This section provides a detailed explanation of the resources shown in the architecture diagram:

1. **CloudFormation**: Used to define and deploy all the resources in the solution.
2. **CloudWatch Log Group**: Logs for Lambda functions to monitor execution details.
3. **SNS Topic (Alarms)**: For publishing CloudWatch alarm notifications.
4. **SNS Topic (DLQ)**: Dead-letter queue to handle failed Lambda invocations.
5. **KMS Key**: Used to encrypt resources such as SNS topics and SQS queues.
6. **CloudWatch Filters**: Monitors specific log events based on configured patterns.
7. **CloudWatch Alarms**: Triggers notifications based on predefined thresholds.
8. **CloudWatch Link**: Links metrics across accounts and regions.
9. **Bedrock Lambda Function**: Core function responsible for deploying resources.
10. **Audit (Security Tooling) Account**:
    - **CloudWatch Dashboard**: Provides an overview of the security state.
    - **CloudWatch Sink**: Receives metrics and logs from other accounts.
    - **Resource Table**: Maintains metadata for tracking deployed resources.
11. **Bedrock Regions**:
    - **CloudWatch Filters**: Region-specific event monitoring.
    - **CloudWatch Alarms**: Region-specific alarm configurations.
    - **SNS Topic**: Publishes notifications within a region.
    - **Config Rules**: Enforces compliance policies.
    - **Config Lambdas**: Functions to evaluate and remediate non-compliance.
    - **KMS Key**: Encrypts resources in the region.

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
        ParameterKey=pBedrockModelEvalBucketRuleParams,ParameterValue='{"deploy": "true", "accounts": ["123456789012"], "regions": ["us-east-1"], "input_params": {"BucketName": "evaluation-bucket"}}' \
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
