# S3 Block Account Public Access<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents<!-- omit in toc -->

- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)

## Introduction

The S3 block account public access solution enables the S3 account level settings within each `AWS account` in the AWS Organization.

The Amazon S3 Block Public Access feature provides settings for access points, buckets, and accounts to help you manage public access to Amazon S3 resources. By default, new buckets, access points, and objects don't allow public access. However,
users can modify bucket policies, access point policies, or object permissions to allow public access. S3 Block Public Access settings override these policies and permissions so that you can limit public access to these resources.

With S3 Block Public Access, account administrators and bucket owners can easily set up centralized controls to limit public access to their Amazon S3 resources that are enforced regardless of how the resources are created.

### Block public access settings<!-- omit in toc -->

> **S3 Block Public Access provides four settings. This solution applies the settings to the account, which applies to all buckets and access points that are owned by that account.**

- **BlockPublicAcls**
  - Setting this option to TRUE causes the following behavior:
    - PUT Bucket acl and PUT Object acl calls fail if the specified access control list (ACL) is public.
    - PUT Object calls fail if the request includes a public ACL.
    - If this setting is applied to an account, then PUT Bucket calls fail if the request includes a public ACL.
- **IgnorePublicAcls**
  - Setting this option to TRUE causes Amazon S3 to ignore all public ACLs on a bucket and any objects that it contains.
- **BlockPublicPolicy**
  - Setting this option to TRUE for a bucket causes Amazon S3 to reject calls to PUT Bucket policy if the specified bucket policy allows public access, and to reject calls to PUT access point policy for all of the bucket's access points if the
    specified policy allows public access.
- **RestrictPublicBuckets**
  - Setting this option to TRUE restricts access to an access point or bucket with a public policy to only AWS service principals and authorized users within the bucket owner's account. This setting blocks all cross-account access to the access point
    or bucket (except by AWS service principals), while still allowing users within the account to manage the access point or bucket.

---

## Deployed Resource Details

![Architecture](./documentation/s3-block-account-public-access.png)

### 1.0 Control Tower Management Account<!-- omit in toc -->

#### 1.1 AWS CloudFormation<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the management account or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 AWS Lambda Function<!-- omit in toc -->

- The AWS Lambda Function contains the logic for configuring the S3 block public access settings within each account.
- The function is triggered by CloudFormation Create, Update, and Delete events and also by the `Control Tower Lifecycle Event Rule` when new accounts are provisioned.

#### 1.3 AWS SSM Parameter Store<!-- omit in toc -->

- The Lambda Function creates/updates configuration parameters within the `SSM Parameter Store` on CloudFormation events and the parameters are used when triggered by the `Control Tower Lifecycle Event Rule`, which does not send the properties on the
  event like CloudFormation does.

#### 1.4 AWS Control Tower Lifecycle Event Rule<!-- omit in toc -->

- The AWS Control Tower Lifecycle Event Rule triggers the `AWS Lambda Function` when a new AWS Account is provisioned through AWS Control Tower.

#### 1.5 AWS Lambda CloudWatch Log Group<!-- omit in toc -->

- All the `AWS Lambda Function` logs are sent to a CloudWatch Log Group `</aws/lambda/<LambdaFunctionName>` to help with debugging and traceability of the actions performed.
- By default the `AWS Lambda Function` will create the CloudWatch Log Group with a `Retention` (Never expire) and are encrypted with a CloudWatch Logs service managed encryption key.
- Optional parameters are included to allow creating the CloudWatch Log Group, which allows setting `KMS Encryption` using a customer managed KMS key and setting the `Retention` to a specific value (e.g. 14 days).

#### 1.6 AWS Lambda Function Role<!-- omit in toc -->

- The AWS Lambda Function Role allows the AWS Lambda service to assume the role and perform actions defined in the attached IAM policies.
- The role is also trusted by the S3 Block Account Public Access IAM Role within each account so that it can configure the S3 account settings.

#### 1.7 S3 Block Account Public Access IAM Role<!-- omit in toc -->

- The S3 block account public access IAM role is deployed into each account within the AWS Organization and it is assumed by the central `AWS Lambda Function` to configure the block public access settings for the account.

#### 1.8 S3 Account Settings<!-- omit in toc -->

- The `AWS Lambda Function` configures the block public access settings for the account.

---

### 2.0 All Existing and Future Organization Member Accounts<!-- omit in toc -->

#### 2.1 AWS CloudFormation<!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 2.2 S3 Block Account Public Access IAM Role<!-- omit in toc -->

- See [1.7 S3 Block Account Public Access IAM Role](#17-s3-block-account-public-access-iam-role)

#### 2.3 S3 Account Settings<!-- omit in toc -->

- See [1.8 S3 Account Settings](#18-s3-account-settings)

---

## Implementation Instructions

### Prerequisites<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** This only needs to be done once for all the solutions.
2. Verify that the [SRA Prerequisites Solution](../../common/common_prerequisites/) has been deployed.
3. No AWS Organizations Service Control Policies (SCPs) are blocking the `s3:GetAccountPublicAccessBlock` and `s3:PutAccountPublicAccessBlock` API actions

### Solution Deployment<!-- omit in toc -->

Choose a Deployment Method:

- [AWS CloudFormation](#aws-cloudformation)
- [Customizations for AWS Control Tower](../../../docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md)

#### AWS CloudFormation<!-- omit in toc -->

- **Option 1:** (Recommended) Use the [sra-s3-block-account-public-access-main-ssm.yaml](templates/sra-s3-block-account-public-access-main-ssm.yaml) template. This is a more automated approach where some of the CloudFormation parameters are populated from SSM parameters created by the [SRA Prerequisites Solution](../../common/common_prerequisites/).
- **Option 2:** Use the [sra-s3-block-account-public-access-main.yaml](templates/sra-s3-block-account-public-access-main.yaml) template. Input is required for the CloudFormation parameters where the default is not set.

#### Verify Solution Deployment<!-- omit in toc -->

How to verify after the pipeline completes?

1. Log into an account and navigate to the S3 console page
2. Select the `Block Public Access settings for this account` in the side menu and verify the settings match the parameters provided in the configuration

#### Solution Delete Instructions<!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **Stack** (`sra-s3-block-account-public-access-main-ssm` or `sra-s3-block-account-public-access-main`) created above.
2. In the `management account (home region)`, delete the AWS CloudWatch **Log Group** (e.g. /aws/lambda/<solution_name>) for the Lambda function deployed.

---

## References

- [Blocking public access to your Amazon S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
