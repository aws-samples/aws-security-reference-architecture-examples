# Access Analyzer <!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents <!-- omit in toc -->

- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)

---

## Introduction

The IAM Access Analyzer solution enables AWS IAM Access Analyzer by delegating administration to a member account within the Organization management account. It then configures Access Analyzer within the `delegated administrator account` for all the
existing and future AWS Organization accounts.

In addition to the organization deployment, the solution deploys AWS Access Analyzer to all the member accounts and regions for analyzing account level permissions.

---

## Deployed Resource Details

![Architecture](./documentation/iam-access-analyzer.png)

### 1.0 Organization Management Account <!-- omit in toc -->

#### 1.1 AWS CloudFormation <!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the management account or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 AWS Organizations <!-- omit in toc -->

- AWS Organizations is used to delegate an administrator account for AWS Access Analyzer Delegated Administrator Account
- See [Common Register Delegated Administrator](../../common/common_register_delegated_administrator)

#### 1.3 Account AWS IAM Access Analyzer <!-- omit in toc -->

AWS IAM Access Analyzer is configured to monitor [supported resources](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html) for the AWS Account zone of trust.

---

### 2.0 Audit Account <!-- omit in toc -->

#### 2.1 AWS CloudFormation <!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 2.2 Account AWS IAM Access Analyzer <!-- omit in toc -->

- See [1.2 Account AWS IAM Access Analyzer](#12-account-aws-iam-access-analyzer)

#### 2.3 Organization AWS IAM Access Analyzer <!-- omit in toc -->

- AWS IAM Access Analyzer is configured to monitor supported resources for the AWS Organization zone of trust.

---

### 3.0 All Existing and Future Organization Member Accounts <!-- omit in toc -->

#### 3.1 AWS CloudFormation <!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 3.2 Account AWS IAM Access Analyzer <!-- omit in toc -->

- See [1.2 Account AWS IAM Access Analyzer](#12-account-aws-iam-access-analyzer)

---

## Implementation Instructions

### Pre-requisites <!-- omit in toc -->

1. Register a delegated administrator using the [Common Register Delegated Administrator](../../common/common_register_delegated_administrator) solution
   1. pServicePrincipalList = "access-analyzer.amazonaws.com"

### [Customizations for AWS Control Tower](./customizations_for_aws_control_tower) <!-- omit in toc -->

### CloudFormation StackSets <!-- omit in toc -->

### Solution Deployment <!-- omit in toc -->

#### AWS Control Tower <!-- omit in toc -->

- [Customizations for AWS Control Tower](./customizations_for_aws_control_tower)

#### AWS CloudFormation <!-- omit in toc -->

1. In the `management account (home region)`, launch an AWS CloudFormation **Stack Set** and deploy to `All active accounts` in all `Governed Regions` using the [sra-iam-access-analyzer-account.yaml](templates/sra-iam-access-analyzer-account.yaml)
   template file as the source. **Note:** Include the `management account` in the account list so that the IAM service-linked role is created, which is required for the next step.
2. In the `management account (home region)`, launch an AWS CloudFormation **Stack Set** and deploy to the `Audit account` in all `Governed Regions` using the [sra-iam-access-analyzer-org.yaml](templates/sra-iam-access-analyzer-org.yaml) template
   file as the source.

#### Verify Solution Deployment <!-- omit in toc -->

1. Log into the Audit account and navigate to the IAM Access Analyzer page
   1. Verify that there are 2 Access Analyzers (account and organization)
   2. Verify all existing accounts/regions have an account Access Analyzer

#### Solution Delete Instructions <!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **StackSet** created in step 2 of the solution deployment. **Note:** there should not be any `stack instances` associated with this StackSet.
2. In the `management account (home region)`, delete the AWS CloudFormation **StackSet** created in step 1 of the solution deployment. **Note:** there should not be any `stack instances` associated with this StackSet.
3. Clean up the `delegated administrator` registered in the **Prerequisites**

---

## References

- [Using AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
