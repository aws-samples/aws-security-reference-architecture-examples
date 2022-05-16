# EC2 Default EBS Encryption<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents<!-- omit in toc -->

- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)

## Introduction

The EC2 default EBS encryption solution enables the account level default EBS encryption within each `AWS account` and `AWS region` in the AWS Organization.

You can configure your AWS account to enforce the encryption of the new EBS volumes and snapshot copies that you create. For example, Amazon EBS encrypts the EBS volumes created when you launch an instance and the snapshots that you copy from an
unencrypted snapshot. For examples of transitioning from unencrypted to encrypted EBS resources, see [Encrypt unencrypted resources](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encrypt-unencrypted).

Encryption by default has no effect on existing EBS volumes or snapshots.

**Key solution features:**

- Sets EC2 Default EBS Encryption settings for all existing accounts and provided regions including the `management account` and future accounts.
- Ability to exclude accounts via provided account tags.
- Triggered when new accounts are added to the AWS Organization, account tag updates, and on account status changes.

### **Considerations**<!-- omit in toc -->

- Encryption by default is a Region-specific setting. If you enable it for a Region, you cannot disable it for individual volumes or snapshots in that Region.
- When you enable encryption by default, you can launch an instance only if the instance type supports EBS encryption. For more information, see
  [Supported instance types](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#EBSEncryption_supported_instances).
- If you copy a snapshot and encrypt it to a new KMS key, a complete (non-incremental) copy is created. This results in additional storage costs.
- When migrating servers using AWS Server Migration Service (SMS), do not turn on encryption by default. If encryption by default is already on and you are experiencing delta replication failures, turn off encryption by default. Instead, enable AMI
  encryption when you create the replication job.

---

## Deployed Resource Details

![Architecture](./documentation/ec2-default-ebs-encryption.png)

### 1.0 Control Tower Management Account<!-- omit in toc -->

#### 1.1 AWS CloudFormation<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the management account or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 IAM Roles<!-- omit in toc -->

- The `Lambda IAM Role` is used by the Lambda function to identify existing and future accounts that need EC2 Default EBS Encryption configured.
- The EC2 default EBS encryption IAM role is deployed into each account within the AWS Organization and it is assumed by the central `AWS Lambda Function` to configure the default encryption setting for the account and region.
- The `Event Rule IAM Role` is assumed by EventBridge to forward Global events to the `Home Region` default Event Bus.

#### 1.3 Regional Event Rules<!-- omit in toc -->

- The `AWS Control Tower Lifecycle Event Rule` triggers the `AWS Lambda Function` when a new AWS Account is provisioned through AWS Control Tower.
- The `Organization Compliance Scheduled Event Rule` triggers the `AWS Lambda Function` to capture AWS Account status updates (e.g. suspended to active).
  - A parameter is provided to set the schedule frequency.
  - See the [Instructions to Manually Run the Lambda Function](#instructions-to-manually-run-the-lambda-function) for triggering the `AWS Lambda Function` before the next scheduled run time.
- The `AWS Organizations Event Rule` triggers the `AWS Lambda Function` when updates are made to accounts within the organization.
  - When AWS Accounts are added to the AWS Organization outside of the AWS Control Tower Account Factory. (e.g. account created via AWS Organizations console, account invited from another AWS Organization).
  - When tags are added or updated on AWS Accounts.

#### 1.4 Global Event Rules<!-- omit in toc -->

- If the `Home Region` is different from the `Global Region (e.g. us-east-1)`, then global event rules are created within the `Global Region` to forward events to the `Home Region` default Event Bus.
- The `AWS Organizations Event Rule` forwards AWS Organization account update events.

#### 1.5 Dead Letter Queue (DLQ)<!-- omit in toc -->

- SQS dead letter queue used for retaining any failed Lambda events.

#### 1.6 AWS Lambda Function<!-- omit in toc -->

- The AWS Lambda Function contains the logic for configuring the EC2 default EBS encryption settings within each account and region.

#### 1.7 Lambda CloudWatch Log Group<!-- omit in toc -->

- All the `AWS Lambda Function` logs are sent to a CloudWatch Log Group `</aws/lambda/<LambdaFunctionName>` to help with debugging and traceability of the actions performed.
- By default the `AWS Lambda Function` will create the CloudWatch Log Group and logs are encrypted with a CloudWatch Logs service managed encryption key.
- Parameters are provided for changing the default log group retention and encryption KMS key.

#### 1.8 Alarm SNS Topic<!-- omit in toc -->

- SNS Topic used to notify subscribers when messages hit the Dead Letter Queue (DLQ).

#### 1.9 SNS Topic<!-- omit in toc -->

- SNS Topic used to fanout the Lambda function for setting the EC2 default EBS encryption configuration.

#### 1.10 EC2 Default EBS Encryption<!-- omit in toc -->

- The `AWS Lambda Function` configures the default EBS encryption for the account and region with the `AWS managed EBS encryption key` (alias/aws/ebs).

---

### 2.0 All Existing and Future Organization Member Accounts<!-- omit in toc -->

#### 2.1 AWS CloudFormation<!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 2.2 EC2 Default EBS Encryption IAM Role<!-- omit in toc -->

- The EC2 default EBS encryption IAM role is deployed into each account within the AWS Organization and it is assumed by the central `AWS Lambda Function` to configure the default encryption setting for the account and region.

#### 2.3 EC2 Default EBS Encryption<!-- omit in toc -->

- See [1.10 EC2 Default EBS Encryption](#110-ec2-default-ebs-encryption)

---

## Implementation Instructions

### Prerequisites<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** This only needs to be done once for all the solutions.
2. Verify that the [SRA Prerequisites Solution](../../common/common_prerequisites/) has been deployed.
3. No AWS Organizations Service Control Policies (SCPs) are blocking the `ec2:GetEbsEncryptionByDefault` and `ec2:EnableEbsEncryptionByDefault` API actions
4. All targeted regions need to be enabled in all accounts within the AWS Organization

### Solution Deployment<!-- omit in toc -->

1. Choose a Deployment Method:
   - [AWS CloudFormation](#aws-cloudformation)
   - [Customizations for AWS Control Tower](../../../docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md)

#### AWS CloudFormation<!-- omit in toc -->

In the `management account (home region)`, launch an AWS CloudFormation **Stack** using one of the options below:

- **Option 1:** (Recommended) Use the [sra-ec2-default-ebs-encryption-main-ssm.yaml](templates/sra-ec2-default-ebs-encryption-main-ssm.yaml) template. This is a more automated approach where some of the CloudFormation parameters are populated from
  SSM parameters created by the [SRA Prerequisites Solution](../../common/common_prerequisites/).

  ```bash
  aws cloudformation deploy --template-file $HOME/aws-sra-examples/aws_sra_examples/solutions/ec2/ec2_default_ebs_encryption/templates/sra-ec2-default-ebs-encryption-main-ssm.yaml --stack-name sra-ec2-default-ebs-encryption-main-ssm --capabilities CAPABILITY_NAMED_IAM
  ```

- **Option 2:** Use the [sra-ec2-default-ebs-encryption-main.yaml](templates/sra-ec2-default-ebs-encryption-main.yaml) template. Input is required for the CloudFormation parameters where the default is not set.

  ```bash
  aws cloudformation deploy --template-file $HOME/aws-sra-examples/aws_sra_examples/solutions/ec2/ec2_default_ebs_encryption/templates/sra-ec2-default-ebs-encryption-main.yaml --stack-name sra-ec2-default-ebs-encryption-main --capabilities CAPABILITY_NAMED_IAM --parameter-overrides pOrganizationId=<ORGANIZATION_ID> pRootOrganizationalUnitId=<ROOT_ORGANIZATIONAL_UNIT_ID> pSRAStagingS3BucketName=<SRA_STAGING_S3_BUCKET_NAME>
  ```

**Region parameter definitions:**

- Control Tower Regions Only
  - `true` = All AWS Control Tower governed regions
  - `false` = All default AWS enabled regions
- Enabled Regions = User provided regions. **Leave blank to enable all regions**. **Note:** All provided regions need to be enabled in all accounts within the AWS Organization.

#### Verify Solution Deployment<!-- omit in toc -->

1. How to verify after the solution deployment completes?
   1. Log into an account and navigate to the EC2 console page
   2. Select a region where the EBS default encryption was enabled
   3. Select the `EBS Encryption` from the `Account attributes` section and verify the settings match the parameters provided in the configuration

#### Solution Update Instructions<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** Get the latest code and run the staging script.
2. Update the existing CloudFormation Stack or CFCT configuration. **Note:** Make sure to update the `SRA Solution Version` parameter and any new added parameters.

#### Solution Delete Instructions<!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **Stack** created in step 3 of the solution deployment. **Note:** The solution will not modify the default EBS encryption setting on a `Delete` event. Only the SSM
   configuration parameter is deleted in this step.
2. In the `management account (home region)`, delete the AWS CloudFormation **Stack** created in step 2 of the solution deployment.
3. In the `management account (home region)`, delete the AWS CloudFormation **StackSet** created in step 1 of the solution deployment. **Note:** there should not be any `stack instances` associated with this StackSet.
4. In the `management account (home region)`, delete the AWS CloudWatch **Log Group** (e.g. /aws/lambda/<solution_name>) for the Lambda function deployed in step 2 of the solution deployment.

#### Instructions to Manually Run the Lambda Function<!-- omit in toc -->

1. In the `management account (home region)`.
2. Navigate to the AWS Lambda Functions page.
3. Select the `checkbox` next to the Lambda Function and select `Test` from the `Actions` menu.
4. Scroll down to view the `Test event`.
5. Click the `Test` button to trigger the Lambda Function with the default values.
6. Verify that the updates were successful within the expected account(s).

---

## References

- [EC2 Encryption by Default](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default)
