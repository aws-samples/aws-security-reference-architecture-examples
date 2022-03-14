# Organization CloudTrail<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents<!-- omit in toc -->

- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [FAQ](#faq)
- [References](#references)

## Introduction

The Organization CloudTrail solution will create an Organization CloudTrail within the Organization Management Account that is encrypted with a Customer Managed KMS Key managed in the Audit Account and logs delivered to the Log Archive Account. An
Organization CloudTrail logs all events for all AWS accounts in the AWS Organization.

When you create an organization trail, a trail with the name that you give it will be created in every AWS account that belongs to your organization. Users with CloudTrail permissions in member accounts will be able to see this trail when they log
into the AWS CloudTrail console from their AWS accounts, or when they run AWS CLI commands such as describe-trail. However, users in member accounts will not have sufficient permissions to delete the organization trail, turn logging on or off, change
what types of events are logged, or otherwise alter the organization trail in any way.

The solution default configuration deploys an Organization CloudTrail enabling only data events to avoid duplicating the existing AWS Control Tower CloudTrail, which has the management events enabled.

---

## Deployed Resource Details

![Architecture](./documentation/sra-cloudtrail-org.png)

### 1.0 Organization Management Account<!-- omit in toc -->

#### 1.1 AWS CloudFormation<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the management account or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 AWS Lambda Function<!-- omit in toc -->

- The Lambda Function contains logic for configuring the AWS Organization CloudTrail within the `management account`.

#### 1.3 Lambda Execution IAM Role<!-- omit in toc -->

- The AWS Lambda Function Role allows the AWS Lambda service to assume the role and perform actions defined in the attached IAM policies.

#### 1.4 Lambda CloudWatch Log Group<!-- omit in toc -->

- All the `AWS Lambda Function` logs are sent to a CloudWatch Log Group `</aws/lambda/<LambdaFunctionName>` to help with debugging and traceability of the actions performed.
- By default the `AWS Lambda Function` will create the CloudWatch Log Group with a `Retention` (14 days) and are encrypted with a CloudWatch Logs service managed encryption key.

#### 1.5 Organization CloudTrail<!-- omit in toc -->

- AWS CloudTrail for all AWS Organization accounts
- Member accounts are automatically added and cannot modify
- Data events can be disabled via the parameters
- CloudWatch logs can be disabled via the parameters

#### 1.6 Organization CloudTrail CloudWatch Log Group Role<!-- omit in toc -->

- IAM role used to send CloudTrail logs to the CloudWatch log group

#### 1.7 Organization CloudTrail CloudWatch Log Group<!-- omit in toc -->

- Contains the CloudTrail logs with a `Retention` (400 days)

---

### 2.0 Audit Account<!-- omit in toc -->

The example solutions use `Audit Account` instead of `Security Tooling Account` to align with the default account name used within the AWS Control Tower setup process for the Security Account. The Account ID for the `Audit Account` SSM parameter is
populated from the `SecurityAccountId` parameter within the `AWSControlTowerBP-BASELINE-CONFIG` StackSet.

#### 2.1 AWS CloudFormation<!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 2.2 Organization CloudTrail KMS Key<!-- omit in toc -->

- Customer managed KMS key for the AWS Organizations CloudTrail logs and S3 server-side encryption

#### 2.3 CloudTrail KMS Key Secret<!-- omit in toc -->

- AWS Secrets Manager secret containing the customer managed KMS key ARN

---

### 3.0 Security Log Archive Account<!-- omit in toc -->

#### 3.1 AWS CloudFormation<!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 3.2 Organization CloudTrail S3 Bucket<!-- omit in toc -->

- S3 bucket where the Organization CloudTrail logs are sent for all accounts in the AWS Organization

#### 3.3 CloudTrail S3 Bucket Secret<!-- omit in toc -->

- AWS Secrets Manager secret containing the CloudTrail S3 bucket name

---

## Implementation Instructions

### Prerequisites<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** This only needs to be done once for all the solutions.
2. Verify that the [SRA Prerequisites Solution](../../common/common_prerequisites/) has been deployed.

### Solution Deployment<!-- omit in toc -->

1. Choose a Deployment Method:
   - [AWS CloudFormation](#aws-cloudformation)
   - [Customizations for AWS Control Tower](../../../docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md)
2. To enforce object encryption within the S3 bucket using the KMS key, add the following S3 bucket policy statements to the bucket created by the solution (e.g. sra-org-trail-logs-<account_id>-<aws_region>). The
   [sra-cloudtrail-org-bucket.yaml](templates/sra-cloudtrail-org-bucket.yaml) has the statements commented out and can be updated after the creation of the CloudTrail.

   ```json
   {
     "Sid": "DenyUnencryptedObjectUploads",
     "Effect": "Deny",
     "Principal": "*",
     "Action": "s3:PutObject",
     "Resource": "arn:aws:s3:::sra-org-trail-logs-<account_id>-<region>/*",
     "Condition": {
       "StringNotEquals": {
         "s3:x-amz-server-side-encryption": "aws:kms"
       }
     }
   },
   {
     "Sid": "DenyWrongKMSKey",
     "Effect": "Deny",
     "Principal": "*",
     "Action": "s3:PutObject",
     "Resource": "arn:aws:s3:::sra-org-trail-logs-<logging_account_id>-<region>/*",
     "Condition": {
       "StringNotEquals": {
         "s3:x-amz-server-side-encryption-aws-kms-key-id": "<bucket_encryption_key_arn>"
       }
     }
   }
   ```

#### AWS CloudFormation<!-- omit in toc -->

In the `management account (home region)`, launch an AWS CloudFormation **Stack** using one of the options below:

- **Option 1:** (Recommended) Use the [sra-cloudtrail-org-main-ssm.yaml](templates/sra-cloudtrail-org-main-ssm.yaml) template. This is a more automated approach where some of the CloudFormation parameters are populated from SSM parameters created by
  the [SRA Prerequisites Solution](../../common/common_prerequisites/).
- **Option 2:** Use the [sra-cloudtrail-org-main.yaml](templates/sra-cloudtrail-org-main.yaml) template. Input is required for the CloudFormation parameters where the default is not set.

#### Verify Solution Deployment<!-- omit in toc -->

1. Log into the `management account` and navigate to the CloudTrail page
2. Select Trails and select the `sra-cloudtrail-org` trail
3. Verify the correct configurations have been applied

#### Solution Delete Instructions<!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **Stack** (`sra-cloudtrail-org-main-ssm` or `sra-cloudtrail-org-main`) created above.
2. In the `management account (home region)`, delete the AWS CloudWatch **Log Group** (e.g. /aws/lambda/<solution_name>) for the Lambda function deployed.
3. In the `log archive acccount (home region)`, delete the S3 bucket (e.g. sra-org-trail-logs-<account_id>-<aws_region>) created by the solution.

---

## FAQ

- What additional steps are required if replacing an existing Organization Trail with this solution?
  - Update any metric filters and any other resources that reference the CloudWatch Log Group
  - If a CloudWatch Log Group Subscription is used for forwarding the logs, remove the Subscription from the old group and add it to the new group

---

## References

- [Creating a CloudTrail for the Organization](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html)
- [Allowing Cross-Account Access to a KMS Key](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-modifying-external-accounts.html)
