# Change Log<!-- omit in toc -->

## Table of Contents<!-- omit in toc -->

- [Introduction](#introduction)
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
