# Change Log<!-- omit in toc -->

## Table of Contents<!-- omit in toc -->

- [Introduction](#introduction)
- [2023-11-06](#2023-11-06)
- [2023-10-23](#2023-10-23)
- [2023-10-10](#2023-10-10)
- [2023-09-27](#2023-09-27)
- [2023-09-26](#2023-09-26)
- [2023-09-22](#2023-09-22)
- [2023-08-07](#2023-08-07)
- [2023-07-07](#2023-07-07)
- [2023-07-01](#2023-07-01)
- [2023-06-21](#2023-06-21)
- [2023-06-20](#2023-06-20)
- [2023-06-01](#2023-06-01)
- [2023-05-12](#2023-05-12)
- [2023-05-05](#2023-05-05)
- [2023-04-10](#2023-04-10)
- [2023-01-19](#2023-01-19)
- [2022-12-02](#2022-12-02)
- [2022-09-15](#2022-09-15)
- [2022-07-29](#2022-07-29)
- [2022-07-15](#2022-07-15)
- [2022-05-23](#2022-05-23)
- [2022-05-15](#2022-05-15)
- [2022-04-25](#2022-04-25)
- [2022-04-14](#2022-04-14)
- [2022-04-10](#2022-04-10)
- [2022-04-04](#2022-04-04)
- [2022-03-29](#2022-03-29)
- [2022-03-16](#2022-03-16)
- [2022-03-14](#2022-03-14)
- [2022-01-07](#2022-01-07)
- [2021-12-16](#2021-12-16)
- [2021-12-10](#2021-12-10)
- [2021-11-22](#2021-11-22)
- [2021-11-20](#2021-11-20)
- [2021-11-19](#2021-11-19)
- [2021-09-02](#2021-09-02)
- [2021-09-01](#2021-09-01)

---

## Introduction

All notable changes to this project will be documented in this file.

---
## 2023-11-06

- Updated [Account Alternate Contacts](aws_sra_examples/solutions/account/account_alternate_contacts) solution to make AWS Control Tower optional.

## 2023-10-23

Updated [Firewall Manager](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions/firewall_manager/firewall_manager_org) solution to make AWS Control Tower optional.

## 2023-10-10

- Updated [Inspector](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions/inspector/inspector_org) solution to enable automatic lambda code scan.

## 2023-09-27

- Updated [Config Management Account](aws_sra_examples/solutions/config/config_management_account) solution to make AWS Control Tower optional.
- Updated [AWS Config Conformance Pack](aws_sra_examples/solutions/config/config_conformance_pack_org) solution to make AWS Control Tower optional.

## 2023-09-26

- Updated [Macie](aws_sra_examples/solutions/macie/macie_org) solution to make AWS Control Tower optional.

## 2023-09-22

- Updated [Detective Organization](aws_sra_examples/solutions/detective/detective_org) solution to make AWS Control Tower optional.

## 2023-08-07

- Updated [Common Prerequisites](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions/common/common_prerequisites) solution to make AWS Control Tower optional.
- Updated [Security Hub](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions/securityhub/securityhub_org) solution to make AWS Control Tower optional.
- Updated [Inspector](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions/inspector/inspector_org) solution to make AWS Control Tower optional.
- Updated [GuardDuty](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions/guardduty/guardduty_org) solution to make AWS Control Tower optional.
- Updated [Easy Setup](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/easy_setup) to support solution updates for making AWS Control Tower optional.
- Updated [CloudTrail](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions/cloudtrail/cloudtrail_org) solution to make AWS Control Tower optional.
- Updated [IAM Access Analyzer](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions/iam/iam_access_analyzer) solution to make AWS Control Tower optional.

## 2023-07-07

- Updated [CloudTrail](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions/cloudtrail/cloudtrail_org) solution to enable delegated administrator.

## 2023-07-01

- Added [Detective Organization](aws_sra_examples/solutions/detective/detective_org) solution to [Easy Setup](aws_sra_examples/easy_setup) and [Quick Setup](aws_sra_examples/quick_setup/)

## 2023-06-21

- Added [GuardDuty Organization](aws_sra_examples/solutions/guardduty/guardduty_org) EKS, Malware, RDS, and Lambda protections to [Easy Setup](aws_sra_examples/easy_setup) and [Quick Setup](aws_sra_examples/quick_setup/) deployment options
- Added [Inspector Organization](aws_sra_examples/solutions/inspector/inspector_org) solution to [Quick Setup](aws_sra_examples/quick_setup/) deployment option

## 2023-06-20

### Changed<!-- omit in toc -->

- Add the [Detective Organization](aws_sra_examples/solutions/detective/detective_org) solution to enable detective within the organization.

## 2023-06-01

### Changed<!-- omit in toc -->

- Added GuardDuty EKS, Malware, RDS, and Lambda protections [GuardDuty Organization](aws_sra_examples/solutions/guardduty/guardduty_org)
- Added fix to support deploying to more than 50 accounts. https://github.com/aws-samples/aws-security-reference-architecture-examples/issues/139. UpdateMemberDetectors and CreateMembers parameters accountIds and accountDetails support a max number
  of 50 items

## 2023-05-12

### Changed<!-- omit in toc -->

- Updated [CfCT template](aws_sra_examples/solutions/common/common_cfct_setup/templates/customizations-for-aws-control-tower.template) to resolve issue #137.

## 2023-05-05

### Changed<!-- omit in toc -->

- Added the [Easy Setup](aws_sra_examples/easy_setup) solution to enhance customer experience during deployment operations.

## 2023-04-10

### Changed<!-- omit in toc -->

- Added NIST Security Standard to Security Hub solution [Security Hub Organization](aws_sra_examples/solutions/securityhub/securityhub_org)

## 2023-01-19

### Changed<!-- omit in toc -->

- Add the [Inspector Organization](aws_sra_examples/solutions/inspector/inspector_org) solution to enable inspector within the organization.

## 2022-12-02

### Changed<!-- omit in toc -->

- Updated the [Security Hub Organization](aws_sra_examples/solutions/securityhub/securityhub_org) solution to support enabling the CIS AWS Foundations Benchmark v1.4.0 standard.

## 2022-09-15

### Changed<!-- omit in toc -->

- Updated the [customizations-for-aws-control-tower.template](aws_sra_examples/solutions/common/common_cfct_setup/templates/customizations-for-aws-control-tower.template) to the latest version v2.5.0 and added Checkov suppressions.

## 2022-07-29

### Added<!-- omit in toc -->

- Added [Quick Setup](aws_sra_examples/quick_setup/) which provides the ability to deploy all the solutions from a single centralized CloudFormation template.

### Changed<!-- omit in toc -->

- Updated all the solution main templates to use a consistent naming convention for solution parameter labels.
- Added pSourceStackName parameter to the [AWS Config Conformance Pack](aws_sra_examples/solutions/config/config_conformance_pack_org) and [Security Hub Organization](aws_sra_examples/solutions/securityhub/securityhub_org) solutions to handle the
  DependsOn requirement for the Config Management Account solution within the Quick Setup solution.
- Updated the [Firewall Manager](aws_sra_examples/solutions/firewall_manager/firewall_manager_org), [Macie](aws_sra_examples/solutions/macie/macie_org), [GuardDuty](aws_sra_examples/solutions/guardduty/guardduty_org), and
  [IAM Password Policy](aws_sra_examples/solutions/iam/iam_password_policy) solutions to remove default parameters from the CFCT configuration and main templates.
- Updated the [CFCT-DEPLOYMENT-INSTRUCTIONS.md](aws_sra_examples/docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md) to include instructions for disabling solutions within all accounts before deletion.
- Updated the [Common Prerequisites](aws_sra_examples/solutions/common/common_prerequisites) solution to fix a spelling error.
- Updated all StackSet resources to use the `Managed Execution` setting, which allows queuing of operations.
- Updated all Stack resources in the main templates to include the DeletionPolicy and UpdateReplacePolicy with a value of Delete to resolve cfn-lint findings.
- Updated all the python boto3 clients to include configuration setting the max_attempts to 10 increasing from the default of 5. This prevents retry errors that we have started to see from some of the API calls.

## 2022-07-15

### Changed<!-- omit in toc -->

- Added Checkov Lambda Function suppressions for CKV_AWS_115 (Reserved Concurrent Executions) and CKV_AWS_117 (Run within a VPC) to all solution templates with Lambda Function configurations.
- Updated Lambda python files to fix mypy finding for log_level to always be a string value.
- Updated the [customizations-for-aws-control-tower.template](aws_sra_examples/solutions/common/common_cfct_setup/templates/customizations-for-aws-control-tower.template) to the latest version v2.4.0 and added Checkov suppressions.
- Updated pyproject.toml dependencies to the latest versions.
- Updated [Macie](aws_sra_examples/solutions/macie/macie_org) solution to increase retries and handle API errors when creating existing members.
- Updated [EC2 Default EBS Encryption](aws_sra_examples/solutions/ec2/ec2_default_ebs_encryption) to include default string value for the pExcludeEC2DefaultEBSEncryptionTags parameter.
- Updated [Account Alternate Contacts](aws_sra_examples/solutions/account/account_alternate_contacts) to include default string value for the pExcludeAlternateContactAccountTags parameter.

## 2022-05-23

### Changed<!-- omit in toc -->

- [EC2 Default EBS Encryption](aws_sra_examples/solutions/ec2/ec2_default_ebs_encryption) solution updates:
  - Added DeadLetterConfig to the Lambda function.
  - Removed the checkov suppression for not having a DLQ configured.
- [S3 Block Account Public Access](aws_sra_examples/solutions/s3/s3_block_account_public_access) solution updates:
  - Removed the checkov suppression for not having a DLQ configured.

## 2022-05-15

### Added<!-- omit in toc -->

- Added customizations-for-aws-control-tower.template to align with the latest [user guide](https://docs.aws.amazon.com/controltower/latest/userguide/cfct-template.html) instructions.

### Changed<!-- omit in toc -->

- [Common CFCT Setup](aws_sra_examples/solutions/common/common_cfct_setup) solution updates:
  - Replaced the S3 template link with the latest template from the GitHub repository.
- [EC2 Default EBS Encryption](aws_sra_examples/solutions/ec2/ec2_default_ebs_encryption) solution updates:
  - Added account and organization event support.
  - Added SNS fanout for configuring accounts to replace multi-threading.
  - Added Lambda environment variables to replace SSM parameter for configuration.
- [S3 Block Account Public Access](aws_sra_examples/solutions/s3/s3_block_account_public_access) solution updates:
  - Added account and organization event support.
  - Added SNS fanout for configuring accounts to replace multi-threading.
  - Added Lambda environment variables to replace SSM parameter for configuration.
- [Security Hub Organization](aws_sra_examples/solutions/securityhub/securityhub_org) updates:
  - Added account and organization event support.
- Updated the staging script to include \*.template files.

## 2022-04-25

### Added<!-- omit in toc -->

- Added [Account Alternate Contacts](aws_sra_examples/solutions/account/account_alternate_contacts) solution to set alternate contacts (Billing, Security, Operations) for all existing and future AWS Organization accounts.

## 2022-04-14

### Changed<!-- omit in toc -->

- [Security Hub Organization](aws_sra_examples/solutions/securityhub/securityhub_org) updates:
  - Use environment variables instead of an SSM parameter for configuration parameters.
  - Batch SNS messages in groups of 10 instead of individual messages for each account.
  - Removed boto3 from the requirements.txt to use the recently updated Lambda runtime default boto3.
- Updated the .flake8 configuration to exclude E203 (whitespace before ':') and TYP001 (guard import by `if False: # TYPE_CHECKING`)

### Fixed<!-- omit in toc -->

- [Security Hub Organization](aws_sra_examples/solutions/securityhub/securityhub_org) fix for enabling the management account before adding it as a member in the delegated admin account configuration.

## 2022-04-10

### Added<!-- omit in toc -->

- Added GitHub action workflow templates to run code quality and security checks.

### Changed<!-- omit in toc -->

- Updated Lambda python files to fix and suppress flake8 findings.
- Updated dependencies within the pyproject.toml file to the latest version.

## 2022-04-04

### Changed<!-- omit in toc -->

- Updated the [DOWNLOAD-AND-STAGE-SOLUTIONS.md](aws_sra_examples/docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md) document to change the order of the steps to have the authenticate step before deploying the staging S3 bucket.

### Fixed<!-- omit in toc -->

- Fixed all solution templates that deploy Lambda functions to include a condition that determines if the region supports Graviton (arm64) architecture.

## 2022-03-29

### Changed<!-- omit in toc -->

- Updated the [Common Prerequisites](aws_sra_examples/solutions/common/common_prerequisites) solution README to remove deploying the Staging S3 Bucket within the Solution Deployment steps. The
  [DOWNLOAD-AND-STAGE-SOLUTIONS.md](aws_sra_examples/docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md) document now includes this step.
- Updated the [DOWNLOAD-AND-STAGE-SOLUTIONS.md](aws_sra_examples/docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md) document to include deploying the Staging S3 Bucket template. Also, added an AWS CLI command for deploying the template via the command line.
- Updated the `Solution Deployment` instructions in all solution README files to include AWS CLI commands for deploying the main templates. The AWS CLI command can be used to deploy the template via the command line within tools like CloudShell.
- Updated all main template parameters that allow a blank string to include a default empty string allowing the AWS CLI command to work without passing the `optional` parameters.
- Added an allowed pattern for email address parameters.
- All solution template description were updated.

### Removed<!-- omit in toc -->

- Removed the sra-common-cfct-setup-main-ssm.yaml template as it was the same as the other main template.

## 2022-03-16

### Fixed<!-- omit in toc -->

- Fixed the [Common Prerequisites](aws_sra_examples/solutions/common/common_prerequisites) solution to support Control Tower configurations with a single governed region.

## 2022-03-14

### Added<!-- omit in toc -->

- Added new document [DOWNLOAD-AND-STAGE-SOLUTIONS.md](aws_sra_examples/docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md) to explain the steps for downloading the SRA example code and staging the solutions within the S3 staging bucket.
- Added [Security Hub Organization](aws_sra_examples/solutions/securityhub/securityhub_org) solution to configure Security Hub using AWS Organizations. All existing accounts are added to the central admin account, standards are enabled/disabled per
  provided parameters, a region aggregator is created per the provided paramenter, and a parameter is provided for disabling Security Hub within all accounts and regions via SNS fanout.

### Changed<!-- omit in toc -->

- Updated the [CFCT-DEPLOYMENT-INSTRUCTIONS.md](aws_sra_examples/docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md) document to remove references to the common_cfct_setup solution.
- [CloudTrail](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions/cloudtrail/cloudtrail_org) solution
  - Added main templates to simplify deployments via nested stacks.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
  - Added integration with Secrets Manager to share CloudFormation output values with the management account.
  - Updated the bucket policy to use aws:SourceArn to align with the updated documentation
    [Organization Trail Bucket Policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html#org-trail-bucket-policy).
  - Updated the CFCT configuration to use the main templates and parameters.
- [Common CFCT Setup](aws_sra_examples/solutions/common/common_cfct_setup) solution
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
  - Removed the Lambda function that created a new OU and moved the management account. This is no longer required due to the latest version of the CFCT solution supporting deployments to the management account within the root OU.
- [Common Prerequisites](aws_sra_examples/solutions/common/common_prerequisites) solution
  - Added a template to create a KMS key for sharing CloudFormation outputs via Secrets Manager secrets.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
  - Updated the staging bucket policy to fix the reference to the AWSControlTowerExecution role ARN.
  - Added SRA version parameter to main templates for triggering updates to StackSets.
  - Added logic within the descriptions to reference the rControlTowerExecutionRoleStack resource if the cCreateAWSControlTowerExecutionRole condition is met. This logic avoids creating an empty stack when the condition is false.
- [Common Register Delegated Administrator](aws_sra_examples/solutions/common/common_register_delegated_administrator) solution
  - Added main templates to simplify deployments via nested stacks.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
  - Updated the CFCT configuration to use the main templates and parameters.
  - Added integration with Secrets Manager to share CloudFormation output values with the management account.
  - Updated the Lambda function to align with latest coding standards.
- [AWS Config Aggregator](aws_sra_examples/solutions/config/config_aggregator_org) solution
  - Added main templates to simplify deployments via nested stacks.
  - Updated the CFCT configuration to use the main templates and parameters.
  - Added pRegisterDelegatedAdminAccount parameter to determine whether or not to register the delegated administrator account. This allows the ability to register the delegated admin accounts outside of this solution.
- [AWS Config Conformance Pack](aws_sra_examples/solutions/config/config_conformance_pack_org) solution
  - Added main templates to simplify deployments via nested stacks.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
  - Updated the CFCT configuration to use the main templates and parameters.
  - Added pRegisterDelegatedAdminAccount parameter to determine whether or not to register the delegated administrator account.
  - Moved the list_config_recorder_status.py script from the utils/aws_control_tower/helper_scripts to the solution scripts folder.
  - Updated and moved the Operational-Best-Practices-for-Encryption-and-Keys.yaml conformance pack template to the templates/aws_config_conformance_packs folder.
- [AWS Config Management Account](aws_sra_examples/solutions/config/config_management_account) solution
  - Added SRA version parameter to main templates for triggering updates to StackSets.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
- [EC2 Default EBS Encryption](aws_sra_examples/solutions/ec2/ec2_default_ebs_encryption) solution
  - Added main templates to simplify deployments via nested stacks.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
- [Firewall Manager](aws_sra_examples/solutions/firewall_manager/firewall_manager_org) solution
  - Added main templates to simplify deployments via nested stacks.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
- [GuardDuty](aws_sra_examples/solutions/guardduty/guardduty_org) solution
  - Added main templates to simplify deployments via nested stacks.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
  - Added a parameter and logic to disable GuardDuty within all accounts and regions using SNS fanout.
- [IAM Access Analyzer](aws_sra_examples/solutions/iam/iam_access_analyzer) solution
  - Added main templates to simplify deployments via nested stacks.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
- [IAM Password Policy](aws_sra_examples/solutions/iam/iam_password_policy) solution
  - Renamed solution and files to remove \_acct suffix
  - Added main templates to simplify deployments via nested stacks.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
- [Macie](aws_sra_examples/solutions/macie/macie_org) solution
  - Added main templates to simplify deployments via nested stacks.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.
  - Added a parameter and logic to disable Macie within all accounts and regions using SNS fanout.
- [S3 Block Account Public Access](aws_sra_examples/solutions/s3/s3_block_account_public_access) solution
  - Added main templates to simplify deployments via nested stacks.
  - Updated documentation, diagram, and templates to be consistent with the rest of the solutions.

### Removed<!-- omit in toc -->

- The `Account Security Hub Enabler` solution was replaced with the [Security Hub Organization](aws_sra_examples/solutions/securityhub/securityhub_org) solution.
- The `package-lambda.sh` script was replaced by the stage_solution.sh script.
- The `Prerequisites for AWS Control Tower solutions` files were replaced with the [Common Prerequisites](aws_sra_examples/solutions/common/common_prerequisites) solution.

### Fixed<!-- omit in toc -->

- Fixed checkov metadata entries to use updated [check suppression via CFN Metadata](https://github.com/bridgecrewio/checkov/pull/2216).

## 2022-01-07

### Added<!-- omit in toc -->

- [Customizations for AWS Control Tower (CFCT) Setup](aws_sra_examples/solutions/common/common_cfct_setup) solution

### Changed<!-- omit in toc -->

- Updates to the [stage_solution.sh](https://github.com/aws-samples/aws-security-reference-architecture-examples/blob/main/aws_sra_examples/utils/packaging_scripts/stage_solution.sh) packaging script to support better error logging and include
  packaging of `common` solutions.
- In [Common Prerequisites](aws_sra_examples/solutions/common/common_prerequisites) and [AWS Config Management Account](aws_sra_examples/solutions/config/config_management_account) solutions:
  - Updates to logging to include tracebacks for when exceptions are raised.
- In [Common Prerequisites](aws_sra_examples/solutions/common/common_prerequisites) solution:
  - Set `DeletionPolicy=Retain` and `UpdateReplacePolicy=Retain` for the IAM Role: `AWSControlTowerExecution`
- Renamed `DEPLOYMENT-METHODS.md` to [CFCT-DEPLOYMENT-INSTRUCTIONS.md](aws_sra_examples/docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md) to provide manual and automated steps for deployment of Customizations for Control Tower (CFCT), including prerequisites.

### Removed<!-- omit in toc -->

- CFCT deployment option for the [Common Prerequisites](aws_sra_examples/solutions/common/common_prerequisites) solution.

## 2021-12-16

### Added<!-- omit in toc -->

- [Config Management Account](aws_sra_examples/solutions/config/config_management_account) solution

### Changed<!-- omit in toc -->

- In [Common Prerequisites](aws_sra_examples/solutions/common/common_prerequisites) solution:
  - Removed `TAG_KEY/TAG_VALUE` as environment variables and only kept them as Custom Resource Properties, since CloudWatch event is no longer needed in this solution.
  - Removed `pManagementAccountId` from multiple templates, and instead used as needed `AWS::AccountId`.

### Fixed<!-- omit in toc -->

- Nothing Fixed

## 2021-12-10

### Added<!-- omit in toc -->

- [Common Prerequisites](aws_sra_examples/solutions/common/common_prerequisites) solution
- `Deployment Methods` documentation
- [Staging Script](aws_sra_examples/utils/packaging_scripts/) - `stage_solution.sh`

### Changed<!-- omit in toc -->

- Nothing Changed

### Fixed<!-- omit in toc -->

- Nothing Fixed

## 2021-11-22

### Added<!-- omit in toc -->

- [EC2 Default EBS Encryption](aws_sra_examples/solutions/ec2/ec2_default_ebs_encryption) solution

### Changed<!-- omit in toc -->

- Nothing Changed

## 2021-11-20

### Added<!-- omit in toc -->

- [S3 Block Account Public Access](aws_sra_examples/solutions/s3/s3_block_account_public_access) solution

### Changed<!-- omit in toc -->

- Nothing Changed

## 2021-11-19

### Added<!-- omit in toc -->

- Added `.flake8`, `poetry.lock`, `pyproject.toml`, and `.markdownlint.json` to define coding standards that we will require and use when building future solutions. Contributors should use the standards defined within these files before submitting
  pull requests. Existing solutions will get refactored to these standards in future updates.
- Added S3 `BucketKeyEnabled` to the solutions that create S3 objects (e.g. CloudTrail, GuardDuty, and Macie)

### Changed<!-- omit in toc -->

- Removed the AWS Config Aggregator account solution since AWS Control Tower deploys an account aggregator within the Audit account.
- Modified the directory structure to support multiple internal packages (e.g. 1 for each solution). The folder structure also allows for tests (integration, unit, etc.). See
  [Real Python Application with Internal Packages](https://realpython.com/python-application-layouts/#application-with-internal-packages)
- Renamed folders and files with snake_case to align with [PEP8 Package and Module Names](https://www.python.org/dev/peps/pep-0008/#package-and-module-names)
- Modified links within `README.md` files to align with the updated folders and file names
- Updated the `README.md` files to provide consistency and improved formatting.
- Renamed parameter and template files to `sra-<solution_name>...`
- Updated default values for parameters for resource names with sra- prefix to help with protecting resources deployed

## 2021-09-02

### Added<!-- omit in toc -->

- Nothing Added

### Changed<!-- omit in toc -->

- Removed all code and references to AWS Landing Zone as it is currently in Long-term Support and will not receive any additional features.

### Fixed<!-- omit in toc -->

- Nothing Fixed

---

## 2021-09-01

### Added<!-- omit in toc -->

- [AWS IAM Access Analyzer](aws_sra_examples/solutions/iam/iam_access_analyzer) solution
- [Organization AWS Config Aggregator](aws_sra_examples/solutions/config/config_aggregator_org) solution
- [Common Register Delegated Administrator](aws_sra_examples/solutions/common/common_register_delegated_administrator) solution

### Changed<!-- omit in toc -->

- Nothing Changed

### Fixed<!-- omit in toc -->

- Nothing Fixed

---
