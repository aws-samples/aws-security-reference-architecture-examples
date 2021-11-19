# Firewall Manager <!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents <!-- omit in toc -->

- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [Appendix](#appendix)
- [References](#references)

## Introduction

The Organization Firewall Manager solution will delegate an administrator account (e.g. Audit Account), deploy a maximum allowed security group, configure a security group policy, and configure multiple WAF policies.

AWS Firewall Manager simplifies your AWS WAF, AWS Shield Advanced, and Amazon VPC security groups administration and maintenance tasks across multiple accounts and resources. With Firewall Manager, you set up your AWS WAF firewall rules, Shield
Advanced protections, and Amazon VPC security groups just once. Firewall Manager is particularly useful when you want to protect your entire organization rather than a few number of specific accounts and resources, or if you frequently add new
resources that you want to protect. To use Firewall Manager, your account must be a member of an organization in the AWS Organizations service, and you must **enable AWS Config** for each member account in your AWS Organization.

---

## Deployed Resource Details

![Architecture](./documentation/firewall-manager-org.png)

### 1.0 Organization Management Account <!-- omit in toc -->

#### 1.1 AWS CloudFormation <!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the management account or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 AWS Lambda Function <!-- omit in toc -->

The Lambda function contains logic to associate a delegated administrator account for Firewall Manager

#### 1.3 Lambda Execution IAM Role <!-- omit in toc -->

- IAM role used by the Lambda function to configure the Firewall Delegated Administrator Account

#### 1.4 Lambda CloudWatch Log Group <!-- omit in toc -->

- All the `AWS Lambda Function` logs are sent to a CloudWatch Log Group `</aws/lambda/<LambdaFunctionName>` to help with debugging and traceability of the actions performed.
- By default the `AWS Lambda Function` will create the CloudWatch Log Group with a `Retention` (14 days) and are encrypted with a CloudWatch Logs service managed encryption key.

#### 1.5 Firewall Manager <!-- omit in toc -->

- Firewall Manager APIs are used to delegate an administrator account.

---

### 2.0 Audit Account <!-- omit in toc -->

#### 2.1 AWS CloudFormation <!-- omit in toc -->

- See [1.1 AWS CloudFormation](#11-aws-cloudformation)

#### 2.2 VPC and Security Group <!-- omit in toc -->

- A security group is used by the Firewall Manager security group policy to define the maximum allowed rules.
- A VPC is required for creating the security group.

- **Using AWS Firewall Manager to audit VPC Security Groups:**

  - AWS Firewall Manager enables the ability to audit (and remediate - if desired) security groups across the AWS Organization Unit. This solution utilizes
    [Content Audit Security Group Policies](https://docs.aws.amazon.com/waf/latest/developerguide/security-group-policies.html#security-group-policies-audit) to verify that Security Groups created across the AWS Organization Unit adhere to the rules.
  - A [Usage Audit Security Group Policy](https://docs.aws.amazon.com/waf/latest/developerguide/security-group-policies.html#security-group-policies-usage) is used to identify and remediate unused security groups to keep proper hygiene in the target
    accounts.

- **Security Group Policies:**
  - Firewall Manager Security Group Content Audit Policy
    - This Security Group Policy utilizes a provided security group to audit against 2 rules:
      - The only protocol that can ever allow inbound traffic is TCP/443 (HTTPS)
      - All other protocols are allowed internally to the CIDR blocks for the VPC Networks
  - Firewall Manager Unused Security Group Policy
    - This Security Group policy specifically targets unused Security groups.
    - If remediation is enabled, Firewall Manager will automatically clean up security groups that are not actively being used to maintain good hygiene in the AWS environment.

#### 2.3 Firewall Manager <!-- omit in toc -->

- This solution utilizes AWS Firewall Manager to deploy a baseline set of [AWS Managed WAF Rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html) to monitor and remediate the configured resources within the
  AWS Organization.
- [Firewall Manager WAF Policies](https://docs.aws.amazon.com/waf/latest/developerguide/waf-policies.html) allow Firewall Manager to centrally mandate the application of AWS WAF Rule sets and Web ACLs to endpoints (ELBs, CloudFront Distributions, and
  API Gateway) in the environment.
- The solution enforces the policies based on resource tags, which can be enforced using an IAM or SCP policy.

- **WAF Policies:**
  - FMS Regional WAF Default Policy
    - Resource Types
      - ELBv2
    - API Gateway
    - AWS Managed Rule sets
      - AWS Core Ruleset
      - AWS SQL Database Ruleset
      - AWS IP Reputation List
    - Resource Tag
      - Key: fms-default-policy
      - Value: true
  - FMS CloudFront Default Policy
    - Resource Types
      - Cloudfront Distribution
    - AWS Managed Rule sets
      - AWS Core Ruleset
      - AWS SQL Database Ruleset
      - AWS IP Reputation List
    - Resource Tag
      - Key: fms-default-policy
      - Value: true
  - FMS Regional WAF Windows Policy
    - Resource Types
      - ELBv2
      - API Gateway
    - AWS Managed Rule sets
      - AWS Windows Operating System Ruleset
    - Resource Tag
      - Key: workload-os
      - Value: windows
  - FMS Regional WAF Linux Policy
    - Resource Types
      - ELBv2
      - API Gateway
    - AWS Managed Rule sets
      - AWS Linux Operating System Ruleset
    - Resource Tag
      - Key: workload-os
      - Value: linux
  - FMS Regional WAF Posix Policy
    - Resource Types
      - ELBv2
      - API Gateway
    - AWS Managed Rule sets
      - AWS Posix Operating System Ruleset
    - Resource Tag
      - Key: workload-os
      - Value: posix

#### 2.4 Firewall Manager Disassociate IAM Role <!-- omit in toc -->

- The Firewall Manager Disassociate IAM role is deployed to the `delegated administrator account` to disassociate the account from Firewall Manager when the solution is deleted.
- Firewall Manager requires the disassociation to happen within the `delegated administrator account`. The `management account` Lambda function assumes this role to disassociate the account when the custom resource is deleted via CloudFormation.

---

## Implementation Instructions

### Prerequisites <!-- omit in toc -->

- AWS Control Tower is deployed.
- `aws-security-reference-architecture-examples` repository is stored on your local machine or location where you will be deploying from.

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
--file_name firewall-manager-org-delegate-admin.zip \
--bucket $BUCKET \
--src_dir "$SRA_REPO"/aws_sra_examples/solutions/firewall_manager/firewall_manager_org/lambda/src
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
--file_name firewall-manager-org-delegate-admin.zip \
--bucket $BUCKET \
--src_dir "$SRA_REPO"/aws_sra_examples/solutions/firewall_manager/firewall_manager_org/lambda/src
```

### Solution Deployment <!-- omit in toc -->

#### Customizations for AWS Control Tower <!-- omit in toc -->

- [Customizations for AWS Control Tower](./customizations_for_aws_control_tower)

#### AWS CloudFormation <!-- omit in toc -->

1. In the `management account (home region)`, launch an AWS CloudFormation **Stack** using the [sra-firewall-manager-org-delegate-admin.yaml](templates/sra-firewall-manager-org-delegate-admin.yaml) template file as the source.
2. In the `management account (home region)`, launch an AWS CloudFormation **Stack Set** and deploy to the `Audit account (home region)` using the
   [sra-firewall-manager-org-disassociate-iam-role.yaml](templates/sra-firewall-manager-org-disassociate-iam-role.yaml) template file as the source.
3. In the `management account (home region)`, launch an AWS CloudFormation **Stack Set** and deploy to the `Audit account (home region)` using the [sra-firewall-manager-org-sg-policy.yaml](templates/sra-firewall-manager-org-sg-policy.yaml) template
   file as the source.
4. In the `management account (home region)`, launch an AWS CloudFormation **Stack Set** and deploy to the `Audit account (home region)` using the [sra-firewall-manager-org-waf-policy.yaml](templates/sra-firewall-manager-org-waf-policy.yaml) template
   file as the source.

#### Verify Solution Deployment <!-- omit in toc -->

1. Log into the Audit account and navigate to the AWS Firewall Manager page
2. Verify the correct configurations have been applied
   1. Security policies
      - security-group-maximum-allowed
      - security-group-common-policy
      - fms-regional-waf-default-policy
      - fms-regional-waf-windows-policy
      - fms-regional-waf-linux-policy
      - fms-regional-waf-posix-policy

#### Solution Delete Instructions <!-- omit in toc -->

1. In the `management account (home region)`, delete the AWS CloudFormation **StackSet** created in step 4 of the solution deployment. **Note:** there should not be any `stack instances` associated with this StackSet.
2. In the `management account (home region)`, delete the AWS CloudFormation **StackSet** created in step 3 of the solution deployment. **Note:** there should not be any `stack instances` associated with this StackSet.
3. In the `management account (home region)`, delete the AWS CloudFormation **StackSet** created in step 2 of the solution deployment. **Note:** there should not be any `stack instances` associated with this StackSet.
4. In the `management account (home region)`, delete the AWS CloudFormation **Stack** created in step 1 of the solution deployment.
5. In the `management account (home region)`, delete the AWS CloudWatch **Log Group** (e.g. /aws/lambda/<solution_name>) for the Lambda function deployed in step 3 of the solution deployment.

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

- [Firewall Manager Developer Guide](https://docs.aws.amazon.com/waf/latest/developerguide/fms-chapter.html)
- [Firewall Manager WAF Policies](https://docs.aws.amazon.com/waf/latest/developerguide/waf-policies.html)
- [Firewall Manager Security Group Policy Usage](https://docs.aws.amazon.com/waf/latest/developerguide/security-group-policies.html#security-group-policies-usage)
