# Register Delegated Administrator Account<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents<!-- omit in toc -->

- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [Appendix](#appendix)
- [References](#references)

---

## Introduction

The register delegated administrator account solution is a common solution to register a delegated administrator account (e.g. Security Tooling Account) within the AWS Organizations management account using the AWS Organizations APIs.

---

## Deployed Resource Details

![Architecture](./documentation/sra-common-register-delegated-administrator.png)

### 1.0 Organization Management Account<!-- omit in toc -->

#### 1.1 AWS CloudFormation<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the management account or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 AWS Lambda Function<!-- omit in toc -->

- The Lambda function delegates the administrator account for the provided service principals

#### 1.3 Lambda CloudWatch Log Group<!-- omit in toc -->

- Contains Lambda function execution logs

#### 1.4 Lambda Execution IAM Role<!-- omit in toc -->

- IAM role used by the Lambda function to enable AWS service access for the provided service and register an AWS account as the delegated administrator.

#### 1.5 AWS Organizations<!-- omit in toc -->

- AWS Organizations APIs are used to delegate the administrator account

---

### 2.0 Delegated Administrator Account (Audit)<!-- omit in toc -->

#### 2.1 Services Supported<!-- omit in toc -->

- The services that support a delegated administrator account can be configured and managed within this account.
- Service Principal Mapping

| Service                      | Service Principal                      |
| ---------------------------- | -------------------------------------- |
| AWS IAM Access Analyzer      | access-analyzer.amazonaws.com          |
| AWS Audit Manager            | auditmanager.amazonaws.com             |
| AWS CloudFormation StackSets | stacksets.cloudformation.amazonaws.com |
| AWS Config                   | config.amazonaws.com                   |
| AWS Config Conformance Packs | config-multiaccountsetup.amazonaws.com |
| Amazon Macie                 | macie.amazonaws.com                    |
| AWS Security Hub             | securityhub.amazonaws.com              |
| Amazon S3 Storage Lens       | storage-lens.s3.amazonaws.com          |

---

## Implementation Instructions

### Prerequisites<!-- omit in toc -->

- AWS Control Tower is deployed.
- `aws-security-reference-architecture-examples` repository is stored on your local machine or location where you will be deploying from.

### Staging<!-- omit in toc -->

1. In the `management account (home region)`, launch the AWS CloudFormation **Stack** using the [prereq-controltower-execution-role.yaml](../../../utils/aws_control_tower/prerequisites/prereq-controltower-execution-role.yaml) source, to implement the
   `AWSControlTowerExecution` role pre-requisite.
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
--file_name common-register-delegated-administrator.zip \
--bucket $BUCKET \
--src_dir "$SRA_REPO"/aws_sra_examples/solutions/common/common_register_delegated_administrator/lambda/src
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
--file_name common-register-delegated-administrator.zip \
--bucket $BUCKET \
--src_dir "$SRA_REPO"/aws_sra_examples/solutions/commmon/common_register_delegated_administrator/lambda/src
```

### Solution Deployment<!-- omit in toc -->

#### Customizations for AWS Control Tower<!-- omit in toc -->

- [Customizations for AWS Control Tower](./customizations_for_aws_control_tower)

#### AWS CloudFormation<!-- omit in toc -->

1. In the `management account (home region)`, launch an AWS CloudFormation **Stack** using the [sra-common-register-delegated-administrator.yaml](templates/sra-common-register-delegated-administrator.yaml) template file as the source.

#### Verify Solution Deployment<!-- omit in toc -->

- Verify the configuration using the following AWS CLI shell script

  ```shell
  # Export management account AWS credentials before running the below command
  for accountId in $(aws organizations list-delegated-administrators --query 'DelegatedAdministrators[*].Id' \
  --output text); do echo -e "$accountId\n Service Principals: " \
  $(aws organizations list-delegated-services-for-account --account-id $accountId \
  --query 'DelegatedServices[*].ServicePrincipal'); done
  ```

#### Solution Delete Instructions<!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **Stack** created in step 1 of the solution deployment.
2. In the `management account (home region)`, delete the AWS CloudWatch **Log Group** (e.g. /aws/lambda/<solution_name>) for the Lambda function deployed in step 3 of the solution deployment.

---

## Appendix

### CloudFormation StackSet Instructions<!-- omit in toc -->

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

- [AWS services that you can use with AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services_list.html)
