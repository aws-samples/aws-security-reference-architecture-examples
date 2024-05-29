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

The SRA Patch Manager solution will automate enabling Systems Manager - Patch manager by configuring Patch Manager for all the existing AWS Organization accounts.

**Key solution features:**
- Assumes a role in each member account to enable/disable the Patch Manager Solution.
- Creates 3 Maintenance Windows to Scan or Patch Windows or Linux Managed Instances
- Configures the [Default Host Configuration](https://docs.aws.amazon.com/systems-manager/latest/userguide/quick-setup-default-host-management-configuration.html) feature.
- Ability to disable Patch Manager within all accounts and regions via a parameter and CloudFormation update event.

---

## Prerequisites

The Patch Manager solution requires:
- SSM Agent 3.0.502 or later to be installed on the managed node
- Internet connectivity from the managed node to the source patch repositories
- Supported OS
- A tag is applied to the Managed Instance. Key: InstanceOS Value: Linux or Windows

---

## Deployed Resource Details

![Architecture](./documentation/patchmgr.png)

### 1.0 Organization Management Account<!-- omit in toc -->

#### 1.1 AWS Patch Manager<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the `management account` or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 IAM Roles<!-- omit in toc -->

- The `Lambda IAM Role` is used by the Lambda function in the management account to enable the Patch Manager in the management account.
- The `Patch Management IAM Role` is assumed by the Lambda function in each of the member accounts to to configure Patch Manager.
- The `SSM Automation Role` is used by the Maintenance Window to execute the task.
- The `DefaultHostConfig Role` is used to enable the Default Host Configuration setting.
- The `Patch Mgr EC2 Profile` is used if there are issue with the Default Host Configuration setting.

#### 1.3 Maintenance Windows<!-- omit in toc -->

##### Maintenance Windows Window

Three Maintenance Windows are created:
- `Update_SSM` updates SSM Agent on all Managed Instances
- `Windows_Scan` scans for missing patches on all Managed Instances Tagged as Windows
- `Linux_Scan` scans for missing patches on all Managed Instances Tagged as Linux

##### Maintenance Windows Tasks

Three tasks are created and registered with each of the Maintenance Windows:
- `Update_SSM` Runs an SSM Agent update on all Managed Instances
- `Windows_Scan` Runs a scan on all Managed Instances Tagged as Windows
- `Linux_Scan` Runs a scan on all Managed Instances Tagged as Linux

##### Maintenance Window Targets

Three target groups are created and registered with each of the Maintenance Windows:
- `Update_SSM` which includes all instances with the tag InstanceOS:Windows or InstanceOS:Linux
- `Windows_Scan`  which includes all instances with the tag InstanceOS:Windows
- `Linux_Scan`  which includes all instances with the tag InstanceOS:Linux

#### 1.4 Command Documents<!-- omit in toc -->

These AWS Managed SSM Documents are used by the tasks:
- `AWS-UpdateSSMAgent`
- `AWS-RunPatchBaseline`



## Implementation Instructions

### Prerequisites<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** This only needs to be done once for all the solutions.
2. Verify that the [SRA Prerequisites Solution](../../common/common_prerequisites/) has been deployed.

### Solution Deployment<!-- omit in toc -->

Choose a Deployment Method:

- [AWS CloudFormation](#aws-cloudformation)
- [Customizations for AWS Control Tower](../../../docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md)

#### AWS CloudFormation<!-- omit in toc -->

Refer to the [AWS SRA Easy Setup](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/easy_setup#customizations-for-control-tower-implementation-instructions) Guide to pick the best installation type for you.

Choose to deploy the Patch Manager solution from within the chosen deployment type.

#### Verify Solution Deployment<!-- omit in toc -->

1. Log into the `management account` and navigate to the Systems Manager page.
   1. Select Maintenance Windows.
   2. Verify that there is now a maintnance window with registered tasks and targets.
2. Log into a member account and verify the maintenance windows also exist.

#### Solution Update Instructions<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** Get the latest code and run the staging script.
2. Update the existing CloudFormation Stack or CFCT configuration. **Note:** Make sure to update the `SRA Solution Version` parameter and any new added parameters.

#### Solution Delete Instructions<!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **Stack** (`sra-patch-mgmt-main-ssm`).

---

## References

- [AWS Systems Manager Patch Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager.html)
- [Amazon Machine Images (AMIs) with SSM Agent preinstalled](https://docs.aws.amazon.com/systems-manager/latest/userguide/ami-preinstalled-agent.html)
- [Troubleshooting managed node availability using ssm-cli](https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-cli.html)
