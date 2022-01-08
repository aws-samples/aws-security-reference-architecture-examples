# AWS Config Control Tower Management Account<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents<!-- omit in toc -->

- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)

## Introduction

The `AWS Config Control Tower Management Account Solution` enables AWS Config in the Control Tower `management account`, and updates the AWS Config aggregator in the `audit account` accordingly. The AWS CloudFormation templates enabling AWS Config
used by AWS Control Tower for the member accounts was used as a reference for this solution. All resources that support tags are provided a tag keypair of `sra-solution: sra-config-management-account`.

[AWS Config](https://aws.amazon.com/config/) is a service that enables you to assess, audit, and evaluate the configurations of your AWS resources. Config continuously monitors and records your AWS resource configurations and allows you to automate
the evaluation of recorded configurations against desired configurations. With Config, you can:

- Review changes in configurations and relationships between AWS resources.
- Dive into detailed resource configuration histories.
- Determine your overall compliance against the configurations specified in your internal guidelines.

An [Aggregator](https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html) is an AWS Config resource type that collects AWS Config configuration and compliance data from the following:

- Multiple accounts and multiple regions.
- Single account and multiple regions.
- An organization in AWS Organizations and all the accounts in that organization which have AWS Config enabled.

`AWS Config` enables you to simplify compliance auditing, security analysis, change management, and operational troubleshooting. While an `Aggregator` lets you view the resource configuration and compliance data recorded in AWS Config across
accounts/regions.

---

## Deployed Resource Details

![Architecture](./documentation/config-management-account.png)

### 1.0 Organization Management Account<!-- omit in toc -->

#### 1.1 AWS CloudFormation<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the management account or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`. CloudFormation triggers the custom resource Lambda
  function on Create, Update, and Delete events.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 AWS Config<!-- omit in toc -->

- The `AWS Config Delivery Channel` continually records the changes that occur to your AWS resources, it sends notifications and updated configuration states through the delivery channel.
- The `AWS Config Recorder` describes the AWS resource types for which AWS Config records configuration changes.
- The configuration recorder stores the configurations of the supported resources in your account as configuration items.

#### 1.3 AWS Config Recorder IAM Role<!-- omit in toc -->

- The AWS Config Recorder IAM role is deployed into the `management account` and it is assumed by AWS Config so that the recorder can detect changes in your resource configurations and capture these changes as configuration items.

#### 1.4 AWS Lambda Function Role<!-- omit in toc -->

- The AWS Lambda Function Role allows the AWS Lambda service to assume the role and perform actions defined in the attached IAM policies.
- This solution's Lambda function queries and updates the list of source accounts and regions being aggregated in the AWS Config Aggregator from the `audit account`.

#### 1.5 AWS Lambda Function<!-- omit in toc -->

- An external deployment package is used in the AWS Lambda Function in the [sra-config-management-account-update-aggregator.yaml](templates/sra-config-management-account-update-aggregator.yaml) template that contains the logic for querying and
  updating the list of source accounts and regions being aggregated in the AWS Config Aggregator from the `audit account`.
- The function is triggered by CloudFormation Create, Update, and Delete events.

#### 1.6 AWS Lambda CloudWatch Log Group<!-- omit in toc -->

- `AWS Lambda Function` logs are sent to a CloudWatch Log Group `</aws/lambda/<LambdaFunctionName>` to help with debugging and traceability of the actions performed.
- By default the `AWS Lambda Function` will create the CloudWatch Log Group with a `Retention` (Never expire) and the logs are encrypted with a CloudWatch Logs service managed encryption key.
- Optional parameters are included to allow creating the CloudWatch Log Group, which allows setting `KMS Encryption` using a customer managed KMS key and setting the `Retention` to a specific value (e.g. 14 days).

---

### 2.0 Audit Account<!-- omit in toc -->

#### 2.1 AWS Config Aggregator<!-- omit in toc -->

- `AWS Control Tower` creates an `AWS Config Aggregator` within the Audit Account for all accounts within the `AWS Organization`.
- The `Lambda Function` within the `management account` adds the `management account` to the existing `AWS Config Aggregator`.

---

## Implementation Instructions

### Prerequisites<!-- omit in toc -->

- AWS Control Tower is deployed.
- AWS Config is not enabled in the `management account`.
- AWS Config Aggregator exists in the `audit account`.
- AWS Config S3 bucket exists in the `log archive account`.
- `aws-security-reference-architecture-examples` repository is stored on your local machine or pipeline where you will be deploying from.
- Ensure the [SRA Prerequisites Solution](../common/../../common/common_prerequisites/) was deployed.

### Solution Deployment<!-- omit in toc -->

1. Package the solution, see the [Staging](#staging) instructions.
2. Choose a Deployment Method:
   - [AWS CloudFormation](#aws-cloudformation)
   - [Customizations for AWS Control Tower](../../../docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md)

#### AWS CloudFormation<!-- omit in toc -->

In the `management account (home region)`, launch the AWS CloudFormation **Stack** using the template file as the source from the below chosen options:

- **Option 1:** (Recommended) Use this template, [sra-config-management-account-main-ssm.yaml](templates/sra-config-management-account-main-ssm.yaml), for a more automated approach where CloudFormation parameters resolve SSM parameters.
- **Option 2:** Use this template, [sra-config-management-account-main.yaml](templates/sra-config-management-account-main.yaml), where input is required for the CloudFormation parameters, without resolving SSM parameters.

### Staging<!-- omit in toc -->

1. Package the Lambda code into a zip file and upload the solution files (Lambda Zip files, CloudFormation templates, and other deployment files) to the SRA Staging S3 bucket (from above step), using the
   [Packaging script](../../../utils/packaging_scripts/stage_solution.sh).

   - `SRA_REPO` environment variable should point to the folder where `aws-security-reference-architecture-examples` repository is stored.
   - `BUCKET` environment variable should point to the S3 Bucket where the solution files are stored.
   - See CloudFormation Output from Step 1 in the [Solution Deployment](#solution-deployment) instructions. Or follow this syntax: `sra-staging-<CONTROL-TOWER-MANAGEMENT-ACCOUNT>-<CONTROL-TOWER-HOME-REGION>`

     ```bash
     # Example (assumes repository was downloaded to your home directory)
     export SRA_REPO="$HOME"/aws-security-reference-architecture-examples/aws_sra_examples
     export BUCKET=sra-staging-123456789012-us-east-1
     sh "$SRA_REPO"/utils/packaging_scripts/stage_solution.sh \
         --staging_bucket_name $BUCKET \
         --solution_directory "$SRA_REPO"/solutions/config/config_management_account
     ```

     ```bash
     # Use template below and set the 'SRA_REPO' and 'SRA_BUCKET' with your values.
     export SRA_REPO=
     export BUCKET=
     sh "$SRA_REPO"/utils/packaging_scripts/stage_solution.sh \
         --staging_bucket_name $BUCKET \
         --solution_directory "$SRA_REPO"/solutions/config/config_management_account
     ```

---

## References

- [AWS Config: Getting Started](https://docs.aws.amazon.com/config/latest/developerguide/getting-started.html)
- [AWS Config: Multi-Account Multi-Region Data Aggregation](https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html)
- [Amazon CloudWatch: Encrypt log data in CloudWatch Logs using AWS Key Management Service](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html)
- [Working with AWS CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html)
- [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/)
