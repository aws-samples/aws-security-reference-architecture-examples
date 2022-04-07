# GuardDuty Organization<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)

---

## Introduction

The GuardDuty Organization solution will enable Amazon GuardDuty by delegating administration to a member account within the Organization management account and configuring GuardDuty within the delegated administrator account for all the existing and
future AWS Organization accounts. GuardDuty is also configured to send the findings to a central S3 bucket encrypted with a KMS key.

---

## Deployed Resource Details

![Architecture](./documentation/guardduty-org.png)

### 1.0 Organization Management Account<!-- omit in toc -->

#### 1.1 AWS CloudFormation<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the management account or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 AWS Lambda Function<!-- omit in toc -->

- The Lambda function includes logic to enable and configure GuardDuty

#### 1.3 Lambda Execution IAM Role<!-- omit in toc -->

- IAM role used by the Lambda function to enable the GuardDuty Delegated Administrator Account within each region provided

#### 1.4 Lambda CloudWatch Log Group<!-- omit in toc -->

- All the `AWS Lambda Function` logs are sent to a CloudWatch Log Group `</aws/lambda/<LambdaFunctionName>` to help with debugging and traceability of the actions performed.
- By default the `AWS Lambda Function` will create the CloudWatch Log Group and logs are encrypted with a CloudWatch Logs service managed encryption key.

#### 1.5 Configuration SNS Topic<!-- omit in toc -->

- SNS Topic used to fanout the Lambda function for deleting GuardDuty within each account and region.

#### 1.6 Dead Letter Queue (DLQ)<!-- omit in toc -->

- SQS dead letter queue used for retaining any failed Lambda events.

#### 1.7 Alarm SNS Topic<!-- omit in toc -->

- SNS Topic used to notify subscribers when messages hit the DLQ.

#### 1.8 GuardDuty<!-- omit in toc -->

- GuardDuty is enabled for each existing active account and region during the initial setup
- GuardDuty will automatically enable new member accounts/regions when added to the AWS Organization

---

### 2.0 Log Archive Account<!-- omit in toc -->

#### 2.1 AWS CloudFormation<!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 2.2 GuardDuty Delivery S3 Bucket<!-- omit in toc -->

- S3 bucket where GuardDuty findings are exported for each account/region within the AWS Organization

#### 2.3 GuardDuty<!-- omit in toc -->

- See [1.5 GuardDuty](#15-guardduty)

---

### 3.0 Audit Account<!-- omit in toc -->

The example solutions use `Audit Account` instead of `Security Tooling Account` to align with the default account name used within the AWS Control Tower setup process for the Security Account. The Account ID for the `Audit Account` SSM parameter is
populated from the `SecurityAccountId` parameter within the `AWSControlTowerBP-BASELINE-CONFIG` StackSet.

#### 3.1 AWS CloudFormation<!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 3.2 GuardDuty Delivery KMS Key<!-- omit in toc -->

- GuardDuty is configured to encrypt the exported findings with a customer managed KMS key

#### 3.3 Configuration IAM Role<!-- omit in toc -->

- IAM role assumed by the Lambda function within the management account to configure GuardDuty within each region provided

#### 3.4 GuardDuty<!-- omit in toc -->

- See [1.5 GuardDuty](#15-guardduty)

---

### 4.0 All Existing and Future Organization Member Accounts<!-- omit in toc -->

#### 4.1 GuardDuty<!-- omit in toc -->

- See [1.5 GuardDuty](#15-guardduty)

#### 4.2 Delete Detector Role<!-- omit in toc -->

- An IAM role is created within all the accounts to clean up the GuardDuty detectors when the Disable GuardDuty parameter is set to 'true' and the CloudFormation stack is updated.

---

## Implementation Instructions

### Prerequisites<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** This only needs to be done once for all the solutions.
2. Verify that the [SRA Prerequisites Solution](../../common/common_prerequisites/) has been deployed.

### Solution Deployment<!-- omit in toc -->

Choose a Deployment Method:

- [AWS CloudFormation](#aws-cloudformation)
- [Customizations for AWS Control Tower](../../../docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md)

#### AWS CloudFormation<!-- omit in toc -->

In the `management account (home region)`, launch an AWS CloudFormation **Stack** using one of the options below:

- **Option 1:** (Recommended) Use the [sra-guardduty-org-main-ssm.yaml](templates/sra-guardduty-org-main-ssm.yaml) template. This is a more automated approach where some of the CloudFormation parameters are populated from SSM parameters created by
  the [SRA Prerequisites Solution](../../common/common_prerequisites/).

  ```bash
  aws cloudformation deploy --template-file $HOME/aws-sra-examples/aws_sra_examples/solutions/guardduty/guardduty_org/templates/sra-guardduty-org-main-ssm.yaml --stack-name sra-guardduty-org-main-ssm --capabilities CAPABILITY_NAMED_IAM
  ```

- **Option 2:** Use the [sra-guardduty-org-main.yaml](templates/sra-guardduty-org-main.yaml) template. Input is required for the CloudFormation parameters where the default is not set.

  ```bash
  aws cloudformation deploy --template-file $HOME/aws-sra-examples/aws_sra_examples/solutions/guardduty/guardduty_org/templates/sra-guardduty-org-main.yaml --stack-name sra-guardduty-org-main --capabilities CAPABILITY_NAMED_IAM --parameter-overrides pAuditAccountId=<AUDIT_ACCOUNT_ID> pLogArchiveAccountId=<LOG_ARCHIVE_ACCOUNT_ID> pOrganizationId=<ORGANIZATION_ID> pRootOrganizationalUnitId=<ROOT_ORGANIZATIONAL_UNIT_ID> pSRAStagingS3BucketName=<SRA_STAGING_S3_BUCKET_NAME>
  ```

#### Verify Solution Deployment<!-- omit in toc -->

1. Log into the Management account and navigate to the GuardDuty page
   1. Validate that the delegated admin account is set for each region
2. Log into the Audit account and navigate to the GuardDuty page
   1. Verify the correct GuardDuty configurations have been applied to each region
   2. Verify all existing accounts have been enabled
   3. Verify the findings export is configured for the S3 bucket
   4. Generate sample findings to verify S3 delivery
3. Log into the Log archive account and navigate to the S3 page
   1. Verify the sample findings have been delivered

#### Solution Delete Instructions<!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **Stack** (`sra-guardduty-org-main-ssm` or `sra-guardduty-org-main`) created above.
2. In the `management account (home region)`, delete the AWS CloudWatch **Log Group** (e.g. /aws/lambda/<solution_name>) for the Lambda function deployed.
3. In the `log archive acccount (home region)`, delete the S3 bucket (e.g. sra-guardduty-delivery-<account_id>-<aws_region>) created by the solution.

---

## References

- [Managing GuardDuty Accounts with AWS Organizations](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_organizations.html)
