# AMI Bakery Organization<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Deployed Resource Details](#deployed-resource-details)
- [Implementation Instructions](#implementation-instructions)
- [Customization Instructions](#customization-instructions)
- [Deletion Instructions](#deletion-instructions)
- [References](#references)

---

## Introduction

The AMI Bakery Organization solution will automate creation of standardized and hardened Amazon Machine Operating Images with configurations and services that comply with security standards set by the Government and industry security standards/benchmarks such as and the Security Technical Implementation Guide (STIG) and the Center of Internet Security (CIS).

The solution also provides an easy way to deploy security services such as Amazon Inspector, Amazon Macie, and Amazon GuardDuty that track and report potential vulnerabilities found within the environment. Additionally, the solution, once created, reduces the need to re-create new images when customers move from one multi-account to another as it can be shared and re-used.

**Key solution features:**

- Amazon Linux 2023 STIG hardened image
- Ubuntu Pro CIS Level 1 hardened image
- Microsoft Windows Server 2022 Base STIG hardened image
- Windows CIS Level 1 - `Work on progress`

---

## Deployed Resource Details

![Architecture](./documentation/sra-ami-bakery-org.png)

### 1.0 Organization Management Account<!-- omit in toc -->

#### 1.1 AWS CloudFormation<!-- omit in toc -->

- All resources are deployed via AWS CloudFormation as a `StackSet` and `Stack Instance` within the `management account` or a CloudFormation `Stack` within a specific account.
- The [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) solution deploys all templates as a CloudFormation `StackSet`.
- For parameter details, review the [AWS CloudFormation templates](templates/).

#### 1.2 Lambda Role<!-- omit in toc -->

- The `Organizaton Management Lambda Role` is used by the Lambda function to assume a role in the target region.

#### 1.3 DLQ<!-- omit in toc -->

- SQS dead letter queue used for retaining any failed Lambda events.

#### 1.4 Alarm Topic<!-- omit in toc -->

- SNS Topic used to notify subscribers when messages hit the DLQ.

#### 1.5 Lambda Function<!-- omit in toc -->

- The Lambda function assumes a role in the Image Bakery Account and deploys resources to create Amazon Machine Images (AMIs). These resources include a Code Commit Repository to store CloudFormation Templates for creating AMIs, a Code Pipeline to deploy EC2 Image Builder to create AMIs, and other supporting resources such as an S3 Bucket and IAM Roles. The Lambda function also uploads an initial CloudFormation template to the Code Commit Repository.

#### 1.6 CloudWatch Log Group<!-- omit in toc -->

- All the `AWS Lambda Function` logs are sent to a CloudWatch Log Group `</aws/lambda/<LambdaFunctionName>` to help with debugging and traceability of the actions performed.
- By default the `AWS Lambda Function` will create the CloudWatch Log Group and logs are encrypted with a CloudWatch Logs service managed encryption key.
- Parameters are provided for changing the default log group retention and encryption KMS key.

#### 2.0 Image Bakery Account<!-- omit in toc -->

#### 2.1-2.3 Lambda Roles<!-- omit in toc -->

- The `Configuration Role` is assumed by the Lambda function and used to create resources in the Image Bakery Account such as the Code Commit Repository, Code Pipeline, and S3 Bucket.
- The `Code Pipeline Role` is assumed by te Code Pipeline and used to create resources in the Image Bakery Account such as the EC2 Image Builder.
- The `Cloud Formation Role` is assumed by EC2 Image Builder and used to create Amazon Machine Images (AMIs) in the Image Bakery Account.

#### 2.4 S3 bucket<!-- omit in toc -->

- Amazon S3 Bucket for storing Code Commit artifacts.
  
#### 2.5 Code Commit Repository<!-- omit in toc -->

- A Code Commit Repository to store CloudFormation Templates that define EC2 Image Builder, Recipes, Components, etc.

#### 2.6 CloudFormation<!-- omit in toc -->

- AWS CloudFormation Templates describe the EC2 Image Builder, Recipes, Components, etc. used to build Amazon Machine Images (AMIs).
  
#### 2.7 CodePipeline<!-- omit in toc -->

- AWS CodePipeline monitors the CodeCommit Repository for changes to the CloudFormation Templates. When the Repository is updated, CodePipeline automatically updates EC2 Image builder.

#### 2.8 EC2 Image Builder Pipeline<!-- omit in toc -->

- EC2 ImageBuilder builds new Amazon Machine Images (AMIs) based on the CloudFormation Templates in the CodeCommit Repository.

#### 2.9 Amazon Machine Images<!-- omit in toc -->

- Amazon Machine Images (AMIs) are built by EC2 Image Builder. Then can then be used to launch EC2 Instances.

---

## Implementation Instructions

### Prerequisites<!-- omit in toc -->

1. [Download and Stage the SRA Solutions](../../../docs/DOWNLOAD-AND-STAGE-SOLUTIONS.md). **Note:** This only needs to be done once for all the solutions.
2. Verify that the [SRA Prerequisites Solution](../../common/common_prerequisites/) has been deployed.

### Solution Deployment<!-- omit in toc -->

Choose a Deployment Method:

- [AWS CloudFormation](#aws-cloudformation)
- [Customizations for AWS Control Tower](../../../docs/CFCT-DEPLOYMENT-INSTRUCTIONS.md)

#### AWS CloudFormation<!-- omit in toc -->

In the `management account (home region)`, launch an AWS CloudFormation **Stack** using one of the options below:

- **Option 1:** (Recommended) Use the [sra-ami-bakery-org-main-ssm.yaml](templates/sra-ami-bakery-org-main-ssm.yaml) template. This is a more automated approach where some of the CloudFormation parameters are populated from SSM parameters created by
  the [SRA Prerequisites Solution](../../common/common_prerequisites/).

  ```bash
  aws cloudformation deploy --template-file $HOME/aws-security-reference-architecture-examples/aws_sra_examples/solutions/ami_bakery/ami_bakery_org/templates/sra-ami-bakery-org-main-ssm.yaml --stack-name sra-ami-bakery-org-main-ssm --capabilities CAPABILITY_NAMED_IAM --parameter-overrides pAMIBakeryAccountId=<YOUR_ACCOUNT_ID> pAMIBakeryRegion=<YOUR_REGION> pAMIBakeryFileName=<SOLUTION_FILE_NAME.YAML>

**Note:** Below are available Cloudformation solution file templates, you can change the file names to meet your needs.

1. [sra-ami-bakery-org-amazon-linux-stig-hardened.yaml](lambda/src/sra-ami-bakery-org-amazon-linux-stig-hardened.yaml)
2. [sra-ami-bakery-org-ubuntu-pro-20-04-cis-level-1-hardened.yaml](lambda/src/sra-ami-bakery-org-ubuntu-pro-20-04-cis-level-1-hardened.yaml)
3. [sra-ami-bakery-org-windows-server-2022-stig-hardened.yaml](lambda/src/sra-ami-bakery-org-windows-server-2022-stig-hardened.yaml)

- **Option 2:** Deploy [sra-ami-bakery-org-main-ssm.yaml](templates/sra-ami-bakery-org-main-ssm.yaml) template using [AWS CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stack.html) console - Create Stack.

#### Verify Solution Deployment<!-- omit in toc -->

1. Log into the EC2 ImageBuilder console.
2. Navigate to the `Image pipelines` tab on the top left pane. It will display `sra-ami-bakery-org-image-type-pipeline` under the pipeline name column with Pipeline status set to `Green`.
   `Note:`  
      `i.` You can manually create the image by running the pipeline with the following steps: `Click on Pipeline -> Actions dropdown -> Run  pipeline` OR
      `2.` Leave the Pipeline to automatically create it for you daily at midnight (UTC).
3. Verify that the image has been created by selecting the `Images` tab on the left pane or under the `Output Images` column below the pipeline's Summary  

## Customization Instructions

The AMI Bakery solution can be customized to meet customer needs. This can be done by updating the image recipe of each supplied Cloudformation solution file template with the addition of one or more Amazon-managed or customer-managed components.
**Note:** To avoid errors when updating the recipe, the EC2 Image Builder Recipe version number, i.e, `pSRAAMIBakeryImageRecipeVersionNumber` parameter value in the available Cloudformation solution file templates above must be changed from the default value `1.0.0` to something like `1.1.0` or any version number in `^[0-9]+\.[0-9]+\.[0-9]+$` pattern.
You can make the changes either in the available CloudFormation files BEFORE the deployment OR from inside the CodeCommit repo after the deployment. Once updated from inside the CodeCommit repo console, go back to `AWS CodePipeline console`, open the solution's pipeline, and click `Release change` for the change to take effect.

- **Example 1:** Adding Amazon Managed Microsoft Web Server IIS into [Windows Server 2022 Image](lambda/src/sra-ami-bakery-org-windows-server-2022-stig-hardened.yaml)
  1. Add the Component's ARN as follows: `- ComponentArn: arn:aws:imagebuilder:us-east-1:aws:component/windows-server-iis/x.x.x` under the `rSRAAMIBakeryAMIBakeryImageBuilderRecipe`'s  `Components` property.
  2. You can do the same for all Amazon managed tools/clients found in the EC2 Image Builder component's console for other images (Amazon Linux and Ubuntu Pro 20.04) in your region.
  
- **Example 2:** Adding a custom component (Customer-Managed) for Apache Httpd Web server with PHP and MariaDB into [Amazon Linux 2023 Image](lambda/src/sra-ami-bakery-org-amazon-linux-stig-hardened.yaml)
  1. Copy the code below and paste it into the file right at the top of the `rSRAAMIBakeryAMIBakeryImageBuilderRecipe` resource under the CloudFormation `Resources` section.

      ```cloudformation
      rInstallApachePHPMariaDB:
        Type: AWS::ImageBuilder::Component
        Properties:
            Name: apache-install
            Version: !Ref pSRAAMIBakeryImageRecipeVersionNumber
            Platform: Linux
            Data: |
              name: InstallApachePHPMariaDB 
              description: This will install Apache Httpd Web server with PHP and MariaDB
              schemaVersion: 1.0
              phases:
                  - name: build
                    steps:
                      - name: Install
                        action: ExecuteBash
                        inputs:
                          commands:
                            - sudo yum update -y
                            - sudo yum install -y amazon-linux-extras
                            - sudo amazon-linux-extras install mariadb10.5
                            - sudo amazon-linux-extras install php8.2
                            - sudo yum install -y httpd
                            - sudo systemctl start httpd
                            - sudo systemctl enable httpd
      ```

  2. Add the customized Component's ARN `- ComponentArn: !Ref rInstallApachePHPMariaDB` under the `rSRAAMIBakeryAMIBakeryImageBuilderRecipe`'s  `Components` property.
  
## Deletion Instructions

Choose one of the two options below:

- **Option 1:** Use CloudFormation Console
  
1. In the `account (home region)`, identified by `pAMIBakeryAccountId` parameter, delete the AWS CloudFormation **Stack** (`sra-ami-bakery-org-main-ssm`). **Note:** This will delete all SRA Staging resources
2. In the `account (home region)`, identified by `pAMIBakeryAccountId`, verify that the Lambda function processing is complete by confirming no more CloudWatch logs are generated.
3. In the `account (home region)`, identified by `pAMIBakeryAccountId`, delete the AWS CloudWatch **Log Group** (e.g. /aws/lambda/<solution_name>) for the Lambda function deployed.
4. In the account (home region), identified by pAMIBakeryAccountId parameter, delete the AWS CloudFormation Stack (sra-ami-bakery-org-cloudformation-stack). Note: This will delete your solution with associated resources (IAM roles and policies, EC2 Image Builder resources, S3 Bucket, Codepipeline resources, etc)
5. Delete `sra-ami-bakery-org-cloudformation-role` role in the IAM console in the account (home region), identified by pAMIBakeryAccountId parameter

- **Option 2:** Use AWS CLI
  
1. `aws cloudformation delete-stack --stack-name sra-ami-bakery-org-cloudformation-stack`.  **Note** This will delete your solution with associated resources (IAM roles and policies, EC2 Imagebuilder resources, S3 Bucket, CodepiPeline resources, etc)
2. `aws cloudformation delete-stack --stack-name sra-ami-bakery-org-main-ssm`. **Note:** This will delete all SRA Staging resources

---

## References

- [Managing AWS SDKs in Lambda Functions](https://docs.aws.amazon.com/lambda/latest/operatorguide/sdks-functions.html)
- [Lambda runtimes](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html)
- [Python Boto3 SDK changelog](https://github.com/boto/boto3/blob/develop/CHANGELOG.rst)
- [CIS compliance with Ubuntu LTS](https://ubuntu.com/security/certifications/docs/usg/cis)
- [Creating AMI mappings for CloudFormation](https://octopus.com/blog/ami-mappings-cloudformation)
- [Building an Ubuntu PRO CIS hardened AMI with EC2 Image Builder](https://www.youtube.com/watch?v=ALFuCc5kfpE)
