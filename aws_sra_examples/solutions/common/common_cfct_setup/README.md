# Customizations for AWS Control Tower (CFCT) Setup<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents<!-- omit in toc -->

- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [References](#references)

## Introduction

The `SRA Customizations for Control Tower (CFCT) Solution` deploys the [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) (CFCT) solution, including satisfying CFCT
prerequisites. (e.g., moving the `management account` to an OU). This provides a method to simplify the deployment of SRA solutions and customer customizations within an AWS Control Tower environment.

The Customizations for AWS Control Tower solution combines AWS Control Tower and other highly-available, trusted AWS services to help customers more quickly set up a secure, multi-account AWS environment using AWS best practices. Before deploying
this solution, you must have an AWS Control Tower landing zone deployed in your account.

You can easily add customizations to your AWS Control Tower landing zone using an AWS CloudFormation template and service control policies (SCPs). You can deploy the custom template and policies to individual accounts and organizational units (OUs)
within your organization. This solution integrates with AWS Control Tower lifecycle events to ensure that resource deployments stay in sync with your landing zone. For example, when a new account is created using the AWS Control Tower account
factory, the solution ensures that all resources attached to the account's OUs will be automatically deployed.

## Deployed Resource Details

![Architecture](./documentation/common-cfct-setup.png)

### 1.0 Organization Management Account<!-- omit in toc -->

#### 1.1 AWS CloudFormation<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a Stack within the management account.
- For parameter details, review the AWS [CloudFormation templates](templates/).

#### 1.2 Management OU AWS Lambda IAM Role<!-- omit in toc -->

- The Management OU AWS Lambda Function Role allows the AWS Lambda service to assume the role and perform actions defined in the attached IAM policies.

#### 1.3 Management OU AWS Lambda Function<!-- omit in toc -->

- An external deployment package is used in the AWS Lambda Function in the [sra-common-cfct-setup-management-account-ou.yaml](templates/sra-common-cfct-setup-management-account-ou.yaml) template contains the logic for moving the management account to
  an OU in AWS Organizations to satisfy a Customizations for Control Tower (CFCT) prerequisite.
- The function is triggered by CloudFormation Create, Update, and Delete events.

#### 1.4 AWS Lambda CloudWatch Log Group<!-- omit in toc -->

- `AWS Lambda Function` logs are sent to a CloudWatch Log Group `</aws/lambda/<LambdaFunctionName>` to help with debugging and traceability of the actions performed.
- By default the `AWS Lambda Function` will create the CloudWatch Log Group with a `Retention` (Never expire) and the logs are encrypted with a CloudWatch Logs service managed encryption key.
- Optional parameters are included to allow creating the CloudWatch Log Group, which allows setting `KMS Encryption` using a customer managed KMS key and setting the `Retention` to a specific value (e.g. 14 days).

#### 1.5 Customizations for AWS Control Tower CloudFormation Template<!-- omit in toc -->

- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) (CFCT) solution to support deploying customizations easily to your AWS Control Tower landing zone.
- Defaults updated per SRA recommendations:
  <!-- markdownlint-disable MD034 -->
  - `Amazon S3 URL` = https://s3.amazonaws.com/solutions-reference/customizations-for-aws-control-tower/latest/custom-control-tower-initiation.template
  - `AWS CodePipeline Source` = AWS CodeCommit
  - `Failure Tolerance Percentage` = 0
- **Note:** Prerequisites must be met. Automated solutions included.
  - The `Management Account` resides in an OU to allow CFCT to deploy StackSets to the `management account`. To automate, set CloudFormation parameter `Move Management Account to OU` to `true`.

## Implementation Instructions

### Prerequisites<!-- omit in toc -->

- AWS Control Tower is deployed.
- `aws-security-reference-architecture-examples` repository is stored on your local machine or pipeline where you will be deploying from.
- Ensure the [SRA Prerequisites Solution](../common_prerequisites/) was deployed.

### Solution Deployment<!-- omit in toc -->

1. Package the solution, see the [Staging](#staging) instructions.
2. In the `management account (home region)`, launch the AWS CloudFormation **Stack** using the template file as the source from the below chosen options:
   - **Option 1:** (Recommended) Use this template, [sra-common-cfct-setup-main-ssm.yaml](templates/sra-common-cfct-setup-main-ssm.yaml), for a more automated approach where CloudFormation parameters resolve SSM parameters.
   - **Option 2:** Use this template, [sra-common-cfct-setup-main.yaml](templates/sra-common-cfct-setup-main.yaml), where input is required for the CloudFormation parameters, without resolving SSM parameters.
3. For CodeCommit setup follow these steps: [AWS CodeCommit Repo](../../../docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md#aws-codecommit-repo)

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
         --solution_directory "$SRA_REPO"/solutions/common/common_cfct_setup
     ```

     ```bash
     # Use template below and set the 'SRA_REPO' and 'SRA_BUCKET' with your values.
     export SRA_REPO=
     export BUCKET=
     sh "$SRA_REPO"/utils/packaging_scripts/stage_solution.sh \
         --staging_bucket_name $BUCKET \
         --solution_directory "$SRA_REPO"/solutions/common/common_cfct_setup
     ```

### Solution Delete Instructions<!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation Stack created in step 2 of the solution deployment. **Note:** On a Delete Event, the solution will not:
   1. Move the management account
   2. Delete the OU `CFCT-Management`
   3. Delete below Customizations for Control Tower (CFCT) resources:
      1. CodeCommit Repo (e.g., `custom-control-tower-configuration`)
      2. S3 Buckets (e.g., buckets names containing `custom-control-tower` or `customcontroltower`)

## References

- [How AWS Control Tower works with roles to create and manage accounts](https://docs.aws.amazon.com/controltower/latest/userguide/roles-how.html)
- [AWS Systems Manager Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)
- [Working with AWS CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html)
- [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/)
