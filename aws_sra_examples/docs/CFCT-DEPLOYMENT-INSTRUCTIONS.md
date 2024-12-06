# Customizations for AWS Control Tower Deployment Instructions<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

---

CfCT is a deployment mechanism that for SRA solutions within Control Tower enabled AWS environments.
The requisite [SRA solution configuration files](https://github.com/boueya/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions) are stored in either CodeCommit or S3 and programmatically configured in AWS with a CodePipeline. Whether you're using the sra-easy-setup deployment method or deploying SRA controls ADHOC, the CfCT deployment mechanism makes managing and customizing SRA solutions easier.


## Table of Contents<!-- omit in toc -->

- [Prerequisites](#prerequisites)
  - [Deploy Control Tower](#deploy-control-tower)
  - [Create the AWSControlTowerExecution IAM Role](#create-the-awscontroltowerexecution-iam-role)
  - [Deploy Customizations for AWS Control Tower (CFCT) Solution](#deploy-customizations-for-aws-control-tower-cfct-solution)
  - [AWS CodeCommit Repo](#aws-codecommit-repo)
- [References](#references)


## Prerequisites

### Deploy Control Tower

- These customizations act on existing Control Tower deployments. If you do not have Control Tower deployed into your environment, please do so through the AWS console. For more details on Control Tower and Landing Zone deployments, see the [userguide](https://docs.aws.amazon.com/controltower/latest/userguide/quick-start.html).

### Create the AWSControlTowerExecution IAM Role

- The `AWSControlTowerExecution` Role provides the support needed to deploy solutions to the `management account` across regions as CloudFormation `StackSets` and it is required for the SRA CFCT solution deployments.
- This role is created as part of the [common_prerequisites](../solutions/common/common_prerequisites) solution deployment.

### Deploy Customizations for AWS Control Tower (CFCT) Solution

- Option 1 (Recommended) Deploy the [Common CFCT Setup](../solutions/common/common_cfct_setup/) solution.
- Option 2 Manually deploy the [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution following the below instructions.
  - In the `Management account (home region)`, deploy a new CloudFormation stack with the below recommended settings:
    <!-- markdownlint-disable-next-line MD034 -->
    - `Amazon S3 URL` = https://s3.amazonaws.com/solutions-reference/customizations-for-aws-control-tower/latest/custom-control-tower-initiation.template
    - `Stack name` = custom-control-tower-initiation
    - `AWS CodePipeline Source` = AWS CodeCommit | S3
    - `Failure Tolerance Percentage` = 0
    - Acknowledge that AWS CloudFormation might create IAM resources with custom names

Note: Version 2 or higher of CfCT is expected.

### AWS CodeCommit Repo
*Note: AWS CodeCommit is being deprecated and cannot be deployed to new environments, unless that environment is a part of an AWS Organization with an account that already has CodeCommit deployed. Please see [AWS S3 Repo](#aws-s3-repo) for new AWS Accounts.*

Create a CodeCommit repo for SRA customization [configuration files](#deployment-instructions).

1. On the local machine install [git](https://git-scm.com/downloads) and [git-remote-codecommit](https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-connect.html).
2. Clone the AWS CodeCommit repository via `git clone codecommit::<HOME REGION>://custom-control-tower-configuration custom-control-tower-configuration`

### AWS S3 Repo

Create a CodeCommit repo for SRA cusotmization [configuration files](#deployment-instructions).

- By default, the CodePipeline deployed from the custom-control-tower-initiation CloudFormation will use the `custom-control-tower-configuration-<< ACCOUNT NAME >>-<< REGION NAME >>` S3 bucket as a Source repo. Additionally, it will look for the `custom-control-tower-configuration.zip` file. The pipeline will fail without it. We have provided users with an example `_custom-control-tower-configuration.zip` file in S3 with an example repo for convenience.

- If you would like to change the S3 bucket Source for the CodePipeline, you will need to navigate to the CodePipeline within the AWS console, edit the Source stage for the CodePipeline and update the Bucket name value. Users can also modify the S3 object key value if the ZIP filename differs from default.


## Deployment Instructions<!-- omit in toc -->

1. Determine which version of the [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution you have deployed:
   1. Within the `management account (home region)` find the **CloudFormation Stack** for the Customizations for Control Tower (e.g. `custom-control-tower-initiation`)
   2. Select the `Outputs` tab
   3. The `CustomControlTowerSolutionVersion` **Value** is the version running in the environment
      1. Version 1 = v1.x.x = manifest.yaml version 2020-01-01
      2. Version 2 = v2.x.x = manifest.yaml version 2021-03-15
2. If version 2 is installed, continue to the deployment instructions below.  If not, you will need to update your version of CfCT.


#### Deployment Instructions<!-- omit in toc -->
*Note: these instructions assume version 2 or higher of the CfCT solution has been installed.*

##### Configue Your SRA Deployment Repo

SRA Customizations with CfCT are deployed via a CodePipeline from either a CodeCommit or S3 source. 
Here's an example of an repo for sra-easy-deploy.yaml deployment with controls/parameters for GuardDuty.

   ├── manifest.yaml
   |
   ├── parameters
   │   └── sra-guardduty-org-main-ssm.json
   |
   ├── policies
   |
   └── templates
      └── sra-easy-setup.yaml

###### manifest.yaml file [**required**]

The manifest file will contain all the high level SRA controls that will be deployed to your environment.
An example manifest file for [sra-easy-setup.yaml](https://github.com/aws-samples/aws-security-reference-architecture-examples/blob/main/aws_sra_examples/easy_setup/customizations_for_aws_control_tower/manifest.yaml)

   - Define all `parameters`, `organizational unit names`, `account names` and `SSM parameters` necessary for the SRA controls that you want to enable and configure here.

   - If you are using a non-standard file structure in your Repo, as outlined above, the [*resource_file* key](https://github.com/aws-samples/aws-security-reference-architecture-examples/blob/main/aws_sra_examples/easy_setup/customizations_for_aws_control_tower/manifest.yaml#L13C5-L13C49) value in your manifest file must reflect the path to your template.

   - Be sure to update the [*accounts* key](https://github.com/aws-samples/aws-security-reference-architecture-examples/blob/main/aws_sra_examples/easy_setup/customizations_for_aws_control_tower/manifest.yaml#L310) to reflect your Management Account name.
   
###### templates [**required**]

The templates directory will contain the actual CloudFormation files that are defined within the manifest file.
We use the sra-easy-setup deployment method as an example for the manifest above, [here's](https://github.com/aws-samples/aws-security-reference-architecture-examples/blob/main/aws_sra_examples/easy_setup/templates/sra-easy-setup.yaml) what the template file looks like.

You can also deploy SRA solutions ADHOC, without the sra-easy-setup, by including their corresponding manifest CFN template entry under the resources list for your manifest.yaml file. Exmaples of manifest files for supported solutions can be found within the `aws_sra_examples` repo [aws_sra_examples/solutions/<< SOLUTION NAME >>/customizations_for_aws_control_tower/manifest.yaml](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions).

   - You shouldn't need to modify much in this template file as all SRA controls and parameters are defined in the manifest and files under the parameters directory, respectively.

###### policies [optional] 

Service control policy JSON files go here. The files under the Policies directory will depend on what SRA controls that you're deploying to your environment. Not all SRA controls will require policies defined here.

###### parameters [optional]

Service control parameter JSON files go here. The files under the Parameters directory will depend on what SRA controls that you're deploying to your environment. Not all SRA controls will require parameters defined here.

Above, we used the [sra-guardduty-org-main-ssm.json](https://github.com/aws-samples/aws-security-reference-architecture-examples/blob/main/aws_sra_examples/solutions/guardduty/guardduty_org/customizations_for_aws_control_tower/parameters/sra-guardduty-org-main-ssm.json) parameters file as an example for our sra-easy-setup deploying GuardDuty controls in AWS. 

You can find examples of parameter files for each security solution that we support within the `aws_sra_examples` repo [aws_sra_examples/solutions/<< SOLUTION NAME >>/customizations_for_aws_control_tower/parameters/](https://github.com/aws-samples/aws-security-reference-architecture-examples/tree/main/aws_sra_examples/solutions).


##### Push To CodeCommit or S3
*Note: If you are using S3, the files above will need to be ZIPPED up and named `custom-control-tower-configuration`.*


### Delete Instructions<!-- omit in toc -->

1. Within the Customizations for AWS Control Tower configuration
   1. (Optional) Change the `Disable <Solution Name>` parameter to `true` and trigger the CFCT pipeline. This will disable the solution within each of the member accounts/regions.
   2. Remove the solution configuration from the `manifest.yaml` file
   3. (Optional) Delete the parameter (Version 1 only) and template files for the solution
2. Deploy the Customizations for AWS Control Tower configuration
3. After the pipeline completes, log into the `management account` and navigate to the `CloudFormation StackSet` page
   1. Delete the Stack Instances from the `CustomControlTower-<solution_name>*` CloudFormation StackSets
   2. After the Stack Instances are deleted, delete the `CustomControlTower-<solution_name>*` CloudFormation StackSets


## References

- [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/)