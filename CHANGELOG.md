# Change Log <!-- omit in toc -->

## Table of Contents <!-- omit in toc -->

- [Introduction](#introduction)
- [2021-11-19](#2021-11-19)
- [2021-09-02](#2021-09-02)
- [2021-09-01](#2021-09-01)

---

## Introduction

All notable changes to this project will be documented in this file.

---

## 2021-11-19

### Added <!-- omit in toc -->

- Added `.flake8`, `poetry.lock`, `pyproject.toml`, and `.markdownlint.json` to define coding standards that we will require and use when building future solutions. Contributors should use the standards defined within these files before submitting
  pull requests. Existing solutions will get refactored to these standards in future updates.
- Added S3 `BucketKeyEnabled` to the solutions that create S3 objects (e.g. CloudTrail, GuardDuty, and Macie)

### Changed <!-- omit in toc -->

- Removed the AWS Config Aggregator account solution since AWS Control Tower deploys an account aggregator within the Audit account.
- Modified the directory structure to support multiple internal packages (e.g. 1 for each solution). The folder structure also allows for tests (integration, unit, etc.). See
  [Real Python Application with Internal Packages](https://realpython.com/python-application-layouts/#application-with-internal-packages)
- Renamed folders and files with snake_case to align with [PEP8 Package and Module Names](https://www.python.org/dev/peps/pep-0008/#package-and-module-names)
- Modified links within `README.md` files to align with the updated folders and file names
- Updated the `README.md` files to provide consistency and improved formatting.
- Renamed parameter and template files to `sra-<solution_name>...`
- Updated default values for parameters for resource names with sra- prefix to help with protecting resources deployed

## 2021-09-02

### Added <!-- omit in toc -->

- Nothing Added

### Changed <!-- omit in toc -->

- Removed all code and references to AWS Landing Zone as it is currently in Long-term Support and will not receive any additional features.

### Fixed <!-- omit in toc -->

- Nothing Fixed

---

## 2021-09-01

### Added <!-- omit in toc -->

- AWS IAM Access Analyzer solution
- Organization AWS Config Aggregator Solution
- Common Register Delegated Administrator Solution

### Changed <!-- omit in toc -->

- Nothing Changed

### Fixed <!-- omit in toc -->

- Nothing Fixed

---
