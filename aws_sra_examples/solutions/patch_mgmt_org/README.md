# Patch Manager<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)

---

## Introduction

The Patch Manager solution will automate enabling Systems Manager - Patch manager by delegating administration to an account (e.g. Audit or Security Tooling) and configuring Patch Manager for all the existing and future AWS Organization accounts.

**Key solution features:**

- Delegates Patch Manager administration to another account (i.e Audit account).
TODO: If we were to do this, we would need to delegate for all of Systems Manager.

- Assumes a role in the delegated administrator account to configure organizations management.
- Assumes a role in each member account to enable/disable standards aligning with the delegated administrator account.
- Ability to disable Patch Manager within all accounts and regions via a parameter and CloudFormation update event.

---

## Prerequisites

The Patch Manager solution requires:
- SSM Agent 3.0.502 or later to be installed on the managed node
- Internet connectivity from the managed node to the source patch repositories
- Supported OS

---

## Deployed Resource Details

![Architecture](./documentation/patchmgr.png)

### 1.0 Organization Management Account<!-- omit in toc -->

#### 1.1 AWS Patch Manager<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the `management account` or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 IAM Roles<!-- omit in toc -->

- The `Lambda IAM Role` is used by the Lambda function to enable the Patch Manager Delegated Administrator Account within each region provided.
- The `Configuration IAM Role` is assumed by the Lambda function to configure Patch Manager within the delegated administrator account and all member accounts.
- The `SSMAutomation Role` is used by the Maintenance Window to execute the task.
- The `DefaultHostConfig Role` is used to enable the Default Host Configuration setting.
- The `AWSSystemsManagerDefaultEC2InstanceManagement Role` profile is automatically attached to new instances.

#### 1.3 Maintenance Windows<!-- omit in toc -->

##### Maintenance Windows Window

Three maintenance windows are created:
- `Update_Linux` Linux Patch Scans
- `Update_Windows` Windows Patch Scans
- `Update_SSMAgent` updates SSM Agent

##### Maintenance Windows Tasks

Three tasks are created and registered with the windows:
- `AWS-RunPatchBaseline` Runs a patch scan on Linux
- `AWS-RunPatchBaseline` Runs a patch scan on Windows
- `AWS-UpdateSSMAgent` Runs an SSM Agent update on Linux and Windows

##### Maintenance Window Targets

Three targets are created and registered with the windows:
- `Update_Linux` which includes all instances with the tag InstanceOS:Linux
- `Update_Windows` which includes all instances with the tag InstanceOS:Windows
- `Update_SSMAgent` which includes all instances with the tag InstanceOS:Windows or InstanceOS:Linux

#### 1.4 Command Documents<!-- omit in toc -->

These AWS Managed SSM Documents are used by the tasks:
- AWS-UpdateSSMAgent
- AWS-RunPatchBaseline


## Implementation Instructions

### Prerequisites<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** This only needs to be done once for all the solutions.
2. Verify that the [SRA Prerequisites Solution](../../common/common_prerequisites/) has been deployed.

### Solution Deployment<!-- omit in toc -->

Choose a Deployment Method:

- [AWS CloudFormation](#aws-cloudformation)
- [Customizations for AWS Control Tower](../../../docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md)

#### AWS CloudFormation<!-- omit in toc -->

In the `management account (home region)`, launch the [sra-inspector-org-main-ssm.yaml](templates/sra-inspector-org-main-ssm.yaml) template. This uses an approach where some of the CloudFormation parameters are populated from SSM parameters created by the [SRA Prerequisites Solution](../../common/common_prerequisites/).

  ```bash
  aws cloudformation deploy --template-file $HOME/aws-sra-examples/aws_sra_examples/solutions/inspector/inspector_org/templates/sra-inspector-org-main-ssm.yaml --stack-name sra-inspector-org-main-ssm --capabilities CAPABILITY_NAMED_IAM
  ```

#### Verify Solution Deployment<!-- omit in toc -->

1. Log into the `management account` and navigate to the Inspector page
   1. Select Settings and then General
   1. Verify that the delegated admin account is set for each region
2. Log into the Audit account and navigate to the Inspector page
   1. Verify the Inspector service is enabled in each region
   2. Verify the auto-enable ec2, ecr and lambda standard scanning for new accounts is ON in each region, and lambda code scanning in supported regions
   3. Verify all existing member accounts have inspector ec2, ecr, and lambda standard scanning enabled in each region, and lambda code scanning in supported regions
3. Log into a member account and verify the inspector is enabled and configured to scan ec2, ecr, lambda functions and lambda code

#### Solution Update Instructions<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** Get the latest code and run the staging script.
2. Update the existing CloudFormation Stack or CFCT configuration. **Note:** Make sure to update the `SRA Solution Version` parameter and any new added parameters.

#### Solution Delete Instructions<!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **Stack** (`sra-inspector-org-main-ssm` or `sra-inspector-org-main`).
2. In the `management account (home region)`, delete stack instances from the the AWS CloudFormation **StackSet** (`sra-inspector-org-main-ssm` or `sra-inspector-org-main`).
3. In the `management account (home region)`, delete AWS CloudFormation **StackSet** (`sra-inspector-org-main-ssm` or `sra-inspector-org-main`).
4. In the `management account (home region)`, verify that the Lambda function processing is complete by confirming no more CloudWatch logs are generated.
5. In the `management account (home region)`, delete the AWS CloudWatch **Log Group** (e.g. /aws/lambda/<solution_name>) for the Lambda function deployed.

#### Instructions to Manually Run the Lambda Function<!-- omit in toc -->

1. In the `management account (home region)`.
2. Navigate to the AWS Lambda Functions page.
3. Select the `checkbox` next to the Lambda Function and select `Test` from the `Actions` menu.
4. Scroll down to view the `Test event`.
5. Click the `Test` button to trigger the Lambda Function with the default values.
6. Verify that the updates were successful within the expected account(s).

---

## References

- [Managing multiple accounts in Amazon Inspector with AWS Organizations](https://docs.aws.amazon.com/inspector/latest/user/managing-multiple-accounts.html)
- [Managing AWS SDKs in Lambda Functions](https://docs.aws.amazon.com/lambda/latest/operatorguide/sdks-functions.html)
- [Lambda runtimes](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html)
- [Python Boto3 SDK changelog](https://github.com/boto/boto3/blob/develop/CHANGELOG.rst)
- [AWS Regions where Lambda code scanning is currently available](https://docs.aws.amazon.com/inspector/latest/user/inspector_regions.html)

