# GuardDuty Organization <!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [Appendix](#appendix)
- [References](#references)

---

## Introduction

The GuardDuty Organization solution will enable Amazon GuardDuty by delegating administration to a member account within the Organization management account and configuring GuardDuty within the delegated administrator account for all the existing and
future AWS Organization accounts. GuardDuty is also configured to send the findings to a central S3 bucket encrypted with a KMS key.

---

## Deployed Resource Details

![Architecture](./documentation/guardduty-org.png)

### 1.0 Organization Management Account <!-- omit in toc -->

#### 1.1 AWS CloudFormation <!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the management account or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 AWS Lambda Function <!-- omit in toc -->

- The Lambda function includes logic to enable and configure GuardDuty

#### 1.3 Lambda CloudWatch Log Group <!-- omit in toc -->

- All the `AWS Lambda Function` logs are sent to a CloudWatch Log Group `</aws/lambda/<LambdaFunctionName>` to help with debugging and traceability of the actions performed.
- By default the `AWS Lambda Function` will create the CloudWatch Log Group and logs are encrypted with a CloudWatch Logs service managed encryption key.

#### 1.4 Lambda Execution IAM Role <!-- omit in toc -->

- IAM role used by the Lambda function to enable the GuardDuty Delegated Administrator Account within each region provided

#### 1.5 GuardDuty <!-- omit in toc -->

- GuardDuty is enabled for each existing active account and region during the initial setup
- GuardDuty will automatically enable new member accounts/regions when added to the AWS Organization

---

### 2.0 Security Log Archive Account <!-- omit in toc -->

#### 2.1 AWS CloudFormation <!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 2.2 GuardDuty Delivery S3 Bucket <!-- omit in toc -->

- S3 bucket where GuardDuty findings are exported for each account/region within the AWS Organization

#### 2.3 GuardDuty <!-- omit in toc -->

- See [1.5 GuardDuty](#15-guardduty)

---

### 3.0 Audit Account <!-- omit in toc -->

#### 3.1 AWS CloudFormation <!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 3.2 GuardDuty Delivery KMS Key <!-- omit in toc -->

- GuardDuty is configured to encrypt the exported findings with a customer managed KMS key

#### 3.3 Configuration IAM Role <!-- omit in toc -->

- IAM role assumed by the Lambda function within the management account to configure GuardDuty within each region provided

#### 3.4 GuardDuty <!-- omit in toc -->

- See [1.5 GuardDuty](#15-guardduty)

---

### 4.0 All Existing and Future Organization Member Accounts <!-- omit in toc -->

#### 4.1 GuardDuty <!-- omit in toc -->

- See [1.5 GuardDuty](#15-guardduty)

#### 4.2 Delete Detector Role <!-- omit in toc -->

- An IAM role is created within all the accounts to clean up the GuardDuty detectors in a CloudFormation delete event

---

## Implementation Instructions

### Prerequisites <!-- omit in toc -->

- AWS Control Tower is deployed.
- `aws-security-reference-architecture-examples` repository is stored on your local machine or location where you will be deploying from.
- GuardDuty is not enabled in any of the accounts within the AWS Organization

### Staging <!-- omit in toc -->

1. In the `management account (home region)`, launch the AWS CloudFormation **Stack** using the [prereq-controltower-execution-role.yaml](../../../utils/aws_control_tower/prerequisites/prereq-controltower-execution-role.yaml) template file as the
   source, to implement the `AWSControlTowerExecution` role pre-requisite.
   - **Note:** Only do this step, if the `AWSControlTowerExecution` IAM role doesn't already exist in the Control Tower `management account`.
2. In the `management account (home region)`, launch the AWS CloudFormation **StackSet** targeting only the `management account` in all of the enabled regions (include home region)
   [prereq-lambda-s3-bucket.yaml](../../../utils/aws_control_tower/prerequisites/prereq-lambda-s3-bucket.yaml) template file as the source, to implement an S3 bucket that will store the Lambda Zip files. (Example Bucket Name:
   `lambda-zips-<Management Account ID>-<AWS Region>`)
   - For additional guidance see [CloudFormation StackSet Instructions](#cloudformation-stackset-instructions)
   - Take note of the S3 Bucket Name from the CloudFormation Outputs, as you will need it for both the packaging step, and the **Solution Deployment Order** section.
   - **Note:** Only do this step if you don't already have an S3 bucket to store the Lambda zip files for CloudFormation custom resources in the Control Tower `management account`.
     - Lambda functions can only access Zip files from an S3 bucket in the same AWS region as the where Lambda function resides.
     - Although for this solution, S3 bucket is only needed in the `home region`, it is recommended to deploy the S3 bucket as a **stackset**, so that you can support future Lambda functions in other regions.
3. Package the Lambda code into a zip file and upload it to the S3 bucket (from above step), using the [Packaging script](../../../utils/packaging_scripts/package-lambda.sh).
   - `SRA_REPO` environment variable should point to the folder where `aws-security-reference-architecture-examples` repository is stored.
   - `BUCKET` environment variable should point to the S3 Bucket where the Lambda zip files are stored.
   - See CloudFormation Output from Step 2
     - Or follow this syntax: `lambda-zips-<CONTROL-TOWER-MANAGEMENT-ACCOUNT>-<CONTROL-TOWER-HOME-REGION>`

```bash
# Example (assumes repository was downloaded to your home directory)
export SRA_REPO="$HOME"/aws-security-reference-architecture-examples
export BUCKET=sra-staging-123456789012-us-east-1
sh "$SRA_REPO"/aws_sra_examples/utils/packaging_scripts/package-lambda.sh \
--file_name guardduty-org.zip \
--bucket $BUCKET \
--src_dir "$SRA_REPO"/aws_sra_examples/solutions/guardduty/guardduty_org/lambda/src
```

```bash
# Export AWS CLI profile for the 'management account'
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_SESSION_TOKEN=

# Use template below and set the 'SRA_REPO' and 'BUCKET' with your values.
export SRA_REPO=
export BUCKET=
sh "$SRA_REPO"/aws_sra_examples/utils/packaging_scripts/package-lambda.sh \
--file_name guardduty-org.zip \
--bucket $BUCKET \
--src_dir "$SRA_REPO"/aws_sra_examples/solutions/guardduty/guardduty_org/lambda/src
```

### Solution Deployment <!-- omit in toc -->

#### Customizations for AWS Control Tower <!-- omit in toc -->

- [Customizations for AWS Control Tower](./customizations_for_aws_control_tower)

#### AWS CloudFormation <!-- omit in toc -->

1. In the `management account (home region)`, launch an AWS CloudFormation **Stack Set** and deploy to the `Audit account (home region)` using the [sra-guardduty-org-configuration-role.yaml](templates/sra-guardduty-org-configuration-role.yaml)
   template file as the source.
2. In the `management account (home region)`, launch an AWS CloudFormation **Stack Set** and deploy to the `Audit account (home region)` using the [sra-guardduty-org-delivery-kms-key.yaml](templates/sra-guardduty-org-delivery-kms-key.yaml) template
   file as the source.
3. In the `management account (home region)`, launch an AWS CloudFormation **Stack Set** and deploy to the `Log archive account (home region)` using the [sra-guardduty-org-delivery-s3-bucket.yaml](templates/sra-guardduty-org-delivery-s3-bucket.yaml)
   template file as the source.
4. In the `management account (home region)`, launch an AWS CloudFormation **Stack** using the [sra-guardduty-org-configuration.yaml](templates/sra-guardduty-org-configuration.yaml) template file as the source.
5. In the `management account (home region)`, launch an AWS CloudFormation **Stack Set** and deploy to `All active accounts (home region)` using the [sra-guardduty-org-delete-detector-role.yaml](templates/sra-guardduty-org-delete-detector-role.yaml)

#### Verify Solution Deployment <!-- omit in toc -->

1. Log into the Management account and navigate to the GuardDuty page
   1. Validate that the delegated admin account is set for each region
2. Log into the Audit account and navigate to the GuardDuty page
   1. Verify the correct GuardDuty configurations have been applied to each region
   2. Verify all existing accounts have been enabled
   3. Verify the findings export is configured for the S3 bucket
   4. Generate sample findings to verify S3 delivery
3. Log into the Log archive account and navigate to the S3 page
   1. Verify the sample findings have been delivered

#### Solution Delete Instructions <!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **Stack** created in step 4 of the solution deployment.
2. In the `management account (home region)`, delete the AWS CloudFormation **StackSet** created in step 5 of the solution deployment. **Note:** there should not be any `stack instances` associated with this StackSet.
3. In the `management account (home region)`, delete the AWS CloudFormation **StackSet** created in step 3 of the solution deployment. **Note:** there should not be any `stack instances` associated with this StackSet.
   1. In the `Log Archive account (home region)`, empty and delete the S3 bucket created in step 3
4. In the `management account (home region)`, delete the AWS CloudFormation **StackSet** created in step 2 of the solution deployment. **Note:** there should not be any `stack instances` associated with this StackSet.
5. In the `management account (home region)`, delete the AWS CloudFormation **StackSet** created in step 1 of the solution deployment. **Note:** there should not be any `stack instances` associated with this StackSet.
6. In the `management account (home region)`, delete the AWS CloudWatch **Log Group** (e.g. /aws/lambda/<solution_name>) for the Lambda function deployed in step 4 of the solution deployment.

---

## Appendix

### CloudFormation StackSet Instructions <!-- omit in toc -->

If you need to launch an AWS CloudFormation **StackSet** in the `management account`, see below steps (for additional details, see
[Create a stack set with self-managed permissions](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-getting-started-create.html#stacksets-getting-started-create-self-managed))

1. AWS CloudFormation -> StackSets -> Create StackSet
2. Choose a Template (upload template)
3. Specify StackSet Details (enter parameter values)
4. Configure StackSet Options -> Self-service permissions
   - IAM Admin Role Name: `AWSControlTowerStackSetRole`
   - IAM Execution Role Name: `AWSControlTowerExecution`
5. Set Deployment Options -> Deploy New Stacks
   - Deploy Stacks in Accounts -> enter the AWS Control Tower Management Account ID
   - Specify Regions: choose regions you want to deploy stacks too (include home region)
6. If in future, you need to update the Stack Set (e.g., add/remove a region), see [Getting Started with AWS CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-getting-started.html)

---

## References

- [Managing GuardDuty Accounts with AWS Organizations](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_organizations.html)
