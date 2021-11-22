# Customizations for AWS Control Tower Implementation Instructions <!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

---

## Table of Contents <!-- omit in toc -->

- [Version 1 Solution Deployment](#version-1-solution-deployment)
- [Version 2 Solution Deployment](#version-2-solution-deployment)
- [Solution Delete Instructions](#solution-delete-instructions)
- [How to check the solution version?](#how-to-check-the-solution-version)
- [References](#references)

## Version 1 Solution Deployment

1. Copy the files to the Customizations for AWS Control Tower configuration

   - custom-control-tower-configuration
     - parameters [**required for manifest version 2020-01-01**]
       - Copy the parameter files from the [parameters](./parameters) folder
     - policies [optional]
       - service control policies files (\*.json)
     - templates [**required**]
       - Copy the template files from the [templates](../templates) folder
     - [manifest.yaml](./manifest.yaml) [**required**]

2. Verify and update the parameters within each of the parameter json files to match the target environment
3. Update the manifest.yaml file with the `organizational unit names`, `account names` and `SSM parameters` for the target environment
4. Deploy the Customizations for AWS Control Tower configuration by pushing the code to the `AWS CodeCommit` repository or uploading to the `AWS S3 Bucket`

## Version 2 Solution Deployment

1. Copy the files to the Customizations for AWS Control Tower configuration

   - custom-control-tower-configuration
     - policies [optional]
       - service control policies files (\*.json)
     - templates [**required**]
       - Copy the template files from the [templates](../templates) folder
     - [manifest.yaml](./manifest-v2.yaml) [**required**]

2. Update the manifest.yaml file with the `parameters`, `organizational unit names`, `account names` and `SSM parameters` for the target environment
3. Deploy the Customizations for AWS Control Tower configuration by pushing the code to the `AWS CodeCommit` repository or uploading to the `AWS S3 Bucket`

## Solution Delete Instructions

1. Within the Customizations for AWS Control Tower configuration
   1. Remove the solution configuration from the `manifest.yaml` file
   2. (Optional) Delete the parameter (Version 1 only) and template files for the solution
2. Deploy the Customizations for AWS Control Tower configuration
3. After the pipeline completes, log into the `management account` and navigate to the `CloudFormation StackSet` page
   1. Delete the Stack Instances from the `CustomControlTower-<solution_name>*` CloudFormation StackSets
   2. After the Stack Instances are deleted, delete the `CustomControlTower-<solution_name>*` CloudFormation StackSets

## How to check the solution version?

1. Within the `management account (home region)` find the **CloudFormation Stack** for the Customizations for Control Tower (e.g. custom-control-tower-initiation)
2. Select the `Outputs` tab
3. The `CustomControlTowerSolutionVersion` **Value** is the version running in the environment
   1. v1.x.x = manifest.yaml version 2020-01-01
   2. v2.x.x = manifest.yaml version 2021-03-15

## References

- [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/)
