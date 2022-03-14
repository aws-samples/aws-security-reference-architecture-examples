# Customizations for AWS Control Tower (CFCT) Setup<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents<!-- omit in toc -->

- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)

## Introduction

The `SRA Customizations for Control Tower (CFCT) Solution` deploys the [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) (CFCT) solution. This provides a method to simplify the deployment of SRA solutions and customer customizations within an AWS Control Tower environment.

The Customizations for AWS Control Tower solution combines AWS Control Tower and other highly-available, trusted AWS services to help customers more quickly set up a secure, multi-account AWS environment using AWS best practices. Before deploying this solution, you must have an AWS Control Tower landing zone deployed in your account.

You can easily add customizations to your AWS Control Tower landing zone using an AWS CloudFormation template and service control policies (SCPs). You can deploy the custom template and policies to individual accounts and organizational units (OUs) within your organization. This solution integrates with AWS Control Tower lifecycle events to ensure that resource deployments stay in sync with your landing zone. For example, when a new account is created using the AWS Control Tower account factory, the solution ensures that all resources attached to the account's OUs will be automatically deployed.

## Deployed Resource Details

![Architecture](./documentation/common-cfct-setup.png)

### 1.0 Organization Management Account<!-- omit in toc -->

#### 1.1 AWS CloudFormation<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a Stack within the management account.
- For parameter details, review the AWS [CloudFormation templates](templates/).

#### 1.2 Customizations for AWS Control Tower CloudFormation Template<!-- omit in toc -->

- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) (CFCT) solution to support deploying customizations easily to your AWS Control Tower landing zone.
- Defaults updated per SRA recommendations:
  <!-- markdownlint-disable MD034 -->
  - `Amazon S3 URL` = https://s3.amazonaws.com/solutions-reference/customizations-for-aws-control-tower/latest/custom-control-tower-initiation.template
  - `AWS CodePipeline Source` = AWS CodeCommit
  - `Failure Tolerance Percentage` = 0

## Implementation Instructions

### Prerequisites<!-- omit in toc -->

- AWS Control Tower is deployed.
- `aws-security-reference-architecture-examples` repository is stored on your local machine or pipeline where you will be deploying from.
- Ensure the [SRA Prerequisites Solution](../common_prerequisites/) was deployed.

### Solution Deployment<!-- omit in toc -->

1. In the `management account (home region)`, launch the AWS CloudFormation **Stack** using the template file as the source from the below chosen options:
   - **Option 1:** (Recommended) Use this template, [sra-common-cfct-setup-main-ssm.yaml](templates/sra-common-cfct-setup-main-ssm.yaml), for a more automated approach where CloudFormation parameters resolve SSM parameters.
   - **Option 2:** Use this template, [sra-common-cfct-setup-main.yaml](templates/sra-common-cfct-setup-main.yaml), where input is required for the CloudFormation parameters, without resolving SSM parameters.
2. For CodeCommit setup follow these steps: [AWS CodeCommit Repo](../../../docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md#aws-codecommit-repo)

### Solution Delete Instructions<!-- omit in toc -->

In the `management account (home region)`, delete the AWS CloudFormation Stack created in step 2 of the solution deployment. **Note:** On a Delete Event, the solution will not:

- Delete below Customizations for Control Tower (CFCT) resources:
- CodeCommit Repo (e.g., `custom-control-tower-configuration`)
- S3 Buckets (e.g., buckets names containing `custom-control-tower` or `customcontroltower`)

## References

- [How AWS Control Tower works with roles to create and manage accounts](https://docs.aws.amazon.com/controltower/latest/userguide/roles-how.html)
- [AWS Systems Manager Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)
- [Working with AWS CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html)
- [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/)
