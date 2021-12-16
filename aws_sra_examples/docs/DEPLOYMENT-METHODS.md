# Deployment Methods<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

---

## Table of Contents<!-- omit in toc -->

- [Customizations for AWS Control Tower Deployment Instructions](#customizations-for-aws-control-tower-deployment-instructions)
- [References](#references)

## Customizations for AWS Control Tower Deployment Instructions

### Prerequisites<!-- omit in toc -->

1. Move the `Organizations Management Account` to an Organizational Unit (OU) (e.g. Management), so that CloudFormation StackSets can be deployed to the `Management Account`
   1. Within the AWS Control Tower console page, select `Organizational units` from the side menu, click the `Add an OU` button, and set the `OU name = Management`
   2. Within the AWS Organizations console page, select `AWS accounts` from the side menu
      1. Select the checkbox next to the `Management Account`
      2. From the `Actions` menu, select `Move` and select the new `Management OU` that was created above
      3. Select `Move AWS account`
2. Within the AWS CloudFormation StackSets console page, `Enable trusted access` with AWS Organizations to use service-managed permissions. To verify that the trusted access is enabled:
   1. Within the AWS Organizations console page, select `Services` from the side menu
   2. Verify that `CloudFormation StackSets` has `Trusted access = Access enabled`
3. Deploy the [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution following the below instructions.
   1. In the `Management account (home region)`, deploy a new CloudFormation stack with the below recommended settings:
      <!-- markdownlint-disable-next-line MD034 -->
      - `Amazon S3 URL` = https://s3.amazonaws.com/solutions-reference/customizations-for-aws-control-tower/latest/custom-control-tower-initiation.template
      - `Stack name` = custom-control-tower-initiation
      - `AWS CodePipeline Source` = AWS CodeCommit
      - `Failure Tolerance Percentage` = 0
      - Acknowledge that AWS CloudFormation might create IAM resources with custom names
   2. On the local machine install [git](https://git-scm.com/downloads) and [git-remote-codecommit](https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-connect.html).
   3. Clone the AWS CodeCommit repository via `git clone codecommit::<HOME REGION>://custom-control-tower-configuration custom-control-tower-configuration`

### Deployment Instructions<!-- omit in toc -->

1. Determine which version of the [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution you have deployed:
   1. Within the `management account (home region)` find the **CloudFormation Stack** for the Customizations for Control Tower (e.g. custom-control-tower-initiation)
   2. Select the `Outputs` tab
   3. The `CustomControlTowerSolutionVersion` **Value** is the version running in the environment
      1. Version 1 = v1.x.x = manifest.yaml version 2020-01-01
      2. Version 2 = v2.x.x = manifest.yaml version 2021-03-15
2. Create the `AWSControlTowerExecution` IAM role in the `management account (home region)` by launching an AWS CloudFormation **Stack** using the
   [sra-common-prerequisites-control-tower-execution-role.yaml](../solutions/common/common_prerequisites/templates/sra-common-prerequisites-control-tower-execution-role.yaml) template file as the source.
3. Follow the instructions for the cooresponding version:
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
