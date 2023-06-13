# Detective Organization<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)

---

## Introduction

The Detective Organization solution will automate enabling Amazon Detective by delegating administration to an account (e.g. Audit or Security Tooling) and configuring Detective for all the existing and future AWS Organization accounts.

**Key solution features:**

- Delegates Detective administration to another account (i.e Audit account).
- Assumes a role in the delegated administrator account to configure organizations management.
- Adds all existing accounts including the `management account` as members.

---

## Deployed Resource Details

![Architecture](./documentation/sra-detective-org.png)

### 1.0 Organization Management Account<!-- omit in toc -->

#### 1.1 AWS CloudFormation<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the `management account` or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 IAM Roles<!-- omit in toc -->

- The `Lambda IAM Role` is used by the Lambda function to enable the Detective Delegated Administrator Account within each region provided.
- The `Configuration IAM Role` is assumed by the Lambda function to configure Detective within the delegated administrator account and all member accounts.

#### 1.3 Compliance Event Rule<!-- omit in toc -->

- The `Organization Compliance Scheduled Event Rule` triggers the `AWS Lambda Function` to capture AWS Account status updates (e.g. suspended to active).
  - A parameter is provided to set the schedule frequency.
  - See the [Instructions to Manually Run the Lambda Function](#instructions-to-manually-run-the-lambda-function) for triggering the `AWS Lambda Function` before the next scheduled run time.

#### 1.4 Dead Letter Queue (DLQ)<!-- omit in toc -->

- SQS dead letter queue used for retaining any failed Lambda events.

#### 1.5 Alarm SNS Topic<!-- omit in toc -->

- SNS Topic used to notify subscribers when messages hit the DLQ.

#### 1.6 AWS Lambda Function<!-- omit in toc -->

- The Lambda function includes logic to enable and configure Detective.

#### 1.7 Lambda Layer<!-- omit in toc -->

- The python boto3 SDK lambda layer to enable capability for lambda to activate all elements of the Detective service.
- This is downloaded during the deployment process and packaged into a layer that is used by the lambda function in this solution.
- The Detective API available in the current lambda environment (as of 06/06/2023) is boto3-1.20.32, however, enhanced functionality of the Detective API used in this solution requires at least 1.26.135 (see references below).
- Note: Future revisions to this solution will remove this layer when boto3 is updated within the lambda environment.

#### 1.8 Lambda CloudWatch Log Group<!-- omit in toc -->

- All the `AWS Lambda Function` logs are sent to a CloudWatch Log Group `</aws/lambda/<LambdaFunctionName>` to help with debugging and traceability of the actions performed.
- By default the `AWS Lambda Function` will create the CloudWatch Log Group and logs are encrypted with a CloudWatch Logs service managed encryption key.
- Parameters are provided for changing the default log group retention and encryption KMS key.

#### 1.9 Detective<!-- omit in toc -->

- The Detective delegated administrator is registered within organizations in the `management account` using the Detective APIs within each provided region.

---

### 2.0 Audit Account<!-- omit in toc -->

The example solutions use `Audit Account` instead of `Security Tooling Account` to align with the default account name used within the AWS Control Tower 
setup process for the Security Account. The Account ID for the `Audit Account` SSM parameter is 
populated from the `SecurityAccountId` parameter within the `AWSControlTowerBP-BASELINE-CONFIG` StackSet.

#### 2.1 AWS CloudFormation<!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 2.2 Configuration IAM Role<!-- omit in toc -->

- IAM role assumed by the Lambda function within the `management account` to configure Detective within each region provided.

#### 2.3 Detective (Delegated admin)<!-- omit in toc -->

- Detective is enabled in the delegated admin account within each provided region.
- Detective core package, Amazon EKS audit logs and AWS security findings are enabled for the behavior graphs. 
- New organization accounts are automatically enabled as member accounts.

---

### 3.0 All Existing and Future Organization Member Accounts<!-- omit in toc -->

#### 3.1 AWS CloudFormation<!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 3.2 Configuration IAM Role<!-- omit in toc -->

- IAM role assumed by the Lambda function within the `management account` to configure Detective within each account provided.

#### 3.3 Detective (Members)<!-- omit in toc -->

- Detective is enabled from the delegated administrator account.

---

## Implementation Instructions

### Prerequisites<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** This only needs to be done once for all the solutions.
2. Verify that the [SRA Prerequisites Solution](../../common/common_prerequisites/) has been deployed.
3. Verify that Amazon GuardDuty enabled. If you are not a GuardDuty customer, or have been a GuardDuty customer for less than 48 hours, you cannot enable Detective. You must either enable GuardDuty or wait for 48 hours (see references below).

### Solution Deployment<!-- omit in toc -->

Choose a Deployment Method:

- [AWS CloudFormation](#aws-cloudformation)
- [Customizations for AWS Control Tower](../../../docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md)

#### AWS CloudFormation<!-- omit in toc -->

In the `management account (home region)`, launch an AWS CloudFormation **Stack** using one of the options below:

- **Option 1:** (Recommended) Use the [sra-detective-org-main-ssm.yaml](templates/sra-detective-org-main-ssm.yaml) template. This is a more automated approach where some of the CloudFormation parameters are populated from SSM parameters created by
  the [SRA Prerequisites Solution](../../common/common_prerequisites/).

  ```bash
  aws cloudformation deploy --template-file $HOME/aws-sra-examples/aws_sra_examples/solutions/detective/detective_org/templates/sra-detective-org-main-ssm.yaml --stack-name sra-detective-org-main-ssm --capabilities CAPABILITY_NAMED_IAM
  ```

- **Option 2:** Use the [sra-detective-org-main.yaml](templates/sra-detective-org-main.yaml) template. Input is required for the CloudFormation parameters where the default is not set.

  ```bash
  aws cloudformation deploy --template-file $HOME/aws-sra-examples/aws_sra_examples/solutions/detective/detective_org/templates/sra-detective-org-main.yaml --stack-name sra-detective-org-main --capabilities CAPABILITY_NAMED_IAM --parameter-overrides pAuditAccountId=<AUDIT_ACCOUNT_ID> pOrganizationId=<ORGANIZATION_ID> pRootOrganizationalUnitId=<ROOT_ORGANIZATIONAL_UNIT_ID> pSRAStagingS3BucketName=<SRA_STAGING_S3_BUCKET_NAME>
  ```

#### Verify Solution Deployment<!-- omit in toc -->

1. Log into the `management account` and navigate to the Detective page
   1. Select Settings and then Account Management
   2. Verify that the delegated admin account is set for each region
2. Log into the Audit account and navigate to the Detective page
   1. Select Settings and then Account Management
   2. Verify the auto-enable organization accounts is ON in each region
   3. Select Settings and then General
   4. Verify the Detective service, AWS security findings and EKS audit logs are enabled in each region
3. Log into a member account and verify the Detective service is enabled

#### Solution Update Instructions<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** Get the latest code and run the staging script.
2. Update the existing CloudFormation Stack or CFCT configuration. **Note:** Make sure to update the `SRA Solution Version` parameter and any new added parameters.

#### Solution Delete Instructions<!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **Stack** (`sra-detective-org-main-ssm` or `sra-detective-org-main`).
2. In the `management account (home region)`, verify that the Lambda function processing is complete by confirming no more CloudWatch logs are generated.
3. In the `management account (home region)`, delete the AWS CloudWatch **Log Group** (e.g. /aws/lambda/<solution_name>) for the Lambda function deployed.

#### Instructions to Manually Run the Lambda Function<!-- omit in toc -->

1. In the `management account (home region)`, navigate to the AWS Lambda Functions page.
2. Select the `checkbox` next to the Lambda Function and select `Test` from the `Actions` menu.
3. Scroll down to view the `Test event`.
4. Click the `Test` button to trigger the Lambda Function with the default values.
5. Verify that the updates were successful within the expected account(s).

---

## References

- [Managing multiple accounts in Amazon Detective with AWS Organizations](https://docs.aws.amazon.com/detective/latest/adminguide/accounts.html)
- [Determining whether an account can be enabled](https://docs.aws.amazon.com/detective/latest/adminguide/accounts-orgs-members-enable.html#accounts-orgs-members-enable-eligibility)
- [Managing AWS SDKs in Lambda Functions](https://docs.aws.amazon.com/lambda/latest/operatorguide/sdks-functions.html)
- [Lambda runtimes](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html)
- [Python Boto3 SDK changelog](https://github.com/boto/boto3/blob/develop/CHANGELOG.rst)
