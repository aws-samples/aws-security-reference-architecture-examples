# Conformance Pack Organization Rules<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents<!-- omit in toc -->

- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)

---

## Introduction

The Conformance Pack Organization Rules solution deploys Organization AWS Config rules by delegating administration to a member account within the Organization Management account and then creating an Organization Conformance Pack within the delegated
administrator account for all the existing and future AWS Organization accounts.

An [AWS Config Conformance Pack](https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html) is a collection of AWS Config rules and remediation actions that can be easily deployed as a single entity in an account and a Region or
across an organization in AWS Organizations.

Conformance packs are created by authoring a YAML template that contains the list of AWS Config managed or custom rules and remediation actions. You can deploy the template by using the AWS Config console or the AWS CLI. To quickly get started and to
evaluate your AWS environment, use one of the sample conformance pack templates.

---

## Deployed Resource Details

![Architecture](./documentation/config-conformance-pack-org.png)

### 1.0 Organization Management Account<!-- omit in toc -->

#### 1.1 AWS CloudFormation<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the management account or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 AWS Organizations<!-- omit in toc -->

- AWS Organizations is used to delegate an administrator account for AWS Config and to identify AWS accounts for aggregation.

---

### 2.0 Log Archive Account<!-- omit in toc -->

#### 2.1 AWS CloudFormation<!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 2.2 Conformance Pack Delivery Bucket<!-- omit in toc -->

- Organization Conformance Packs require a delivery S3 bucket with "awsconfigconforms" as the bucket name prefix. We create this bucket within the Security Log Archive account to stay consistent with where our consolidated logs are stored.

#### 2.3 Organization Conformance Pack<!-- omit in toc -->

- The Organization conformance pack template is deployed to each provided region within the `delegated administrator account` and all accounts within the AWS Organization (except excluded accounts)

---

### 3.0 Audit Account (Security Tooling)<!-- omit in toc -->

The example solutions use `Audit Account` instead of `Security Tooling Account` to align with the default account name used within the AWS Control Tower setup process for the Security Account. The Account ID for the `Audit Account`  can be determined from the `SecurityAccountId` parameter within the `AWSControlTowerBP-BASELINE-CONFIG` StackSet in AWS Control Tower environments, but is specified manually in other environments, and then stored in an SSM parameter (this is all done in the common prerequisites solution).

#### 3.1 AWS CloudFormation<!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 3.2 Organization Conformance Pack<!-- omit in toc -->

- See [2.3 Organization Conformance Pack](#23-organization-conformance-pack)

---

### 4.0 All Existing and Future Organization Member Accounts<!-- omit in toc -->

#### 4.1 AWS Config Service-Linked Roles<!-- omit in toc -->

- AWS Config creates 2 service-linked roles within each AWS account which are used to setup and send data to the delivery S3 bucket
  - AWSServiceRoleForConfigMultiAccountSetup - is used for the AWS Config multi-account setup
  - AWSServiceRoleForConfigConforms - is used to send data to the delivery S3 bucket

#### 4.2 Organization Conformance Pack<!-- omit in toc -->

- See [2.3 Organization Conformance Pack](#23-organization-conformance-pack)

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

- **Option 1:** (Recommended) Use the [sra-config-conformance-pack-org-main-ssm.yaml](templates/sra-config-conformance-pack-org-main-ssm.yaml) template. This is a more automated approach where some of the CloudFormation parameters are populated from
  SSM parameters created by the [SRA Prerequisites Solution](../../common/common_prerequisites/).

  ```bash
  aws cloudformation deploy --template-file $HOME/aws-sra-examples/aws_sra_examples/solutions/config/config_conformance_pack_org/templates/sra-config-conformance-pack-org-main-ssm.yaml --stack-name sra-config-conformance-pack-org-main-ssm --capabilities CAPABILITY_NAMED_IAM
  ```

- **Option 2:** Use the [sra-config-conformance-pack-org-main.yaml](templates/sra-config-conformance-pack-org-main.yaml) template. Input is required for the CloudFormation parameters where the default values are not set.

  ```bash
  aws cloudformation deploy --template-file $HOME/aws-sra-examples/aws_sra_examples/solutions/config/config_conformance_pack_org/templates/sra-config-conformance-pack-org-main-ssm.yaml --stack-name sra-config-conformance-pack-org-main-ssm --capabilities CAPABILITY_NAMED_IAM --parameter-overrides pAuditAccountId=<AUDIT_ACCOUNT_ID> pLogArchiveAccountId=<LOG_ARCHIVE_ACCOUNT_ID> pOrganizationId=<ORGANIZATION_ID> pRegionsToDeployConformancePacks=<REGIONS_TO_DEPLOY_CONFORMANCE_PACKS> pSRAStagingS3BucketName=<SRA_STAGING_S3_BUCKET_NAME>
  ```

#### Verify Solution Deployment<!-- omit in toc -->

1. In the `Audit account` and navigate to the AWS Config page
2. Verify the correct configurations have been applied to each region
   1. Conformance packs -> `sra-operational-best-practices-for-encryption-and-keys` created in each region
   2. Settings -> Delivery location set to the `awsconfigconforms-<log_archive_account_id>-<home_region>`

#### Solution Delete Instructions<!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **Stack/StackSet** created by the solution deployment. **Note:** there should not be any `stack instances` associated with the StackSet.
2. In the `Log Archive account`, delete the delivery S3 bucket. e.g. awsconfigconforms-sra-<log_archive_account_id>-<home_region>

---

## References

- [Enabling AWS Config Rules Across all Accounts in Your Organization](https://docs.aws.amazon.com/config/latest/developerguide/config-rule-multi-account-deployment.html)
- [Conformance Packs](https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html)
