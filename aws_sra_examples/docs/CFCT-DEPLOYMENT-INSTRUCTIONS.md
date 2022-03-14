# Customizations for AWS Control Tower Deployment Instructions<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

---

## Table of Contents<!-- omit in toc -->

- [Prerequisites](#prerequisites)
- [References](#references)

## Prerequisites

### Create the AWSControlTowerExecution IAM Role<!-- omit in toc -->

- The `AWSControlTowerExecution` Role provides the support needed to deploy solutions to the `management account` across regions as CloudFormation `StackSets` and it is required for the SRA CFCT solution deployments.
- This role is created as part of the [common_prerequisites](../solutions/common/common_prerequisites) solution deployment.

## Deploy Customizations for AWS Control Tower (CFCT) Solution<!-- omit in toc -->

Deploy the [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution following the below instructions.

- In the `Management account (home region)`, deploy a new CloudFormation stack with the below recommended settings:
  <!-- markdownlint-disable-next-line MD034 -->
  - `Amazon S3 URL` = https://s3.amazonaws.com/solutions-reference/customizations-for-aws-control-tower/latest/custom-control-tower-initiation.template
  - `Stack name` = custom-control-tower-initiation
  - `AWS CodePipeline Source` = AWS CodeCommit
  - `Failure Tolerance Percentage` = 0
  - Acknowledge that AWS CloudFormation might create IAM resources with custom names

### AWS CodeCommit Repo<!-- omit in toc -->

1. On the local machine install [git](https://git-scm.com/downloads) and [git-remote-codecommit](https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-connect.html).
2. Clone the AWS CodeCommit repository via `git clone codecommit::<HOME REGION>://custom-control-tower-configuration custom-control-tower-configuration`

### Deployment Instructions<!-- omit in toc -->

1. Determine which version of the [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution you have deployed:
   1. Within the `management account (home region)` find the **CloudFormation Stack** for the Customizations for Control Tower (e.g. `custom-control-tower-initiation`)
   2. Select the `Outputs` tab
   3. The `CustomControlTowerSolutionVersion` **Value** is the version running in the environment
      1. Version 1 = v1.x.x = manifest.yaml version 2020-01-01
      2. Version 2 = v2.x.x = manifest.yaml version 2021-03-15
2. Follow the instructions for the cooresponding version:
   - [Version 1 Deployment Instructions](#version-1-deployment-instructions)
   - [Version 2 Deployment Instructions](#version-2-deployment-instructions)

#### Version 1 Deployment Instructions<!-- omit in toc -->

1. Copy the files to the Customizations for AWS Control Tower configuration `custom-control-tower-configuration`
   - parameters [**required for manifest version 2020-01-01**]
     - Copy the parameter files from the `parameters` folder
     - Only one of the main parameter files is required. We recommend using the `main-ssm` file.
   - policies [optional]
     - service control policies files (\*.json)
   - templates [**required**]
     - Copy the template files from the `templates` folder that are referenced in the `manifest.yaml`
     - Only one of the main template files is required. We recommend using the `main-ssm` file.
   - `manifest.yaml` [**required**]
2. Verify and update the parameters within each of the parameter json files to match the target environment
3. Update the manifest.yaml file with the `organizational unit names`, `account names` and `SSM parameters` for the target environment
4. Deploy the Customizations for AWS Control Tower configuration by pushing the code to the `AWS CodeCommit` repository or uploading to the `AWS S3 Bucket`

#### Version 2 Deployment Instructions<!-- omit in toc -->

1. Copy the files to the Customizations for AWS Control Tower configuration `custom-control-tower-configuration`
   - policies [optional]
     - service control policies files (\*.json)
   - templates [**required**]
     - Copy the template files from the `templates` folder that are referenced in the `manifest-v2.yaml`
     - Only one of the main template files is required. We recommend using the `main-ssm` file.
   - `manifest-v2.yaml` [**required**]
2. Rename the `manifest-v2.yaml` to `manifest.yaml`
3. Update the manifest.yaml file with the `parameters`, `organizational unit names`, `account names` and `SSM parameters` for the target environment
4. Deploy the Customizations for AWS Control Tower configuration by pushing the code to the `AWS CodeCommit` repository or uploading to the `AWS S3 Bucket`

### Delete Instructions<!-- omit in toc -->

1. Within the Customizations for AWS Control Tower configuration
   1. Remove the solution configuration from the `manifest.yaml` file
   2. (Optional) Delete the parameter (Version 1 only) and template files for the solution
2. Deploy the Customizations for AWS Control Tower configuration
3. After the pipeline completes, log into the `management account` and navigate to the `CloudFormation StackSet` page
   1. Delete the Stack Instances from the `CustomControlTower-<solution_name>*` CloudFormation StackSets
   2. After the Stack Instances are deleted, delete the `CustomControlTower-<solution_name>*` CloudFormation StackSets

## References

- [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/)
