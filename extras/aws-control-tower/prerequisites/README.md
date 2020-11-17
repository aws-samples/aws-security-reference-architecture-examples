Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----

# Prerequisites for AWS Control Tower solutions

1. Deploy the [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/)
    Solution
2. Required steps to deploy resources into the AWS Control Tower management account (e.g. Primary Account)
   1. Create an Organizational Unit (e.g. Management) for the Primary account
      1. Review the [Manage Accounts Through AWS Organizations](https://docs.aws.amazon.com/controltower/latest/userguide/organizations.html)
        documentation
   2. Move the Primary account into the new Organizational Unit
   3. Create the AWSControlTowerExecution IAM role in the Primary account
      1. Use the [prereq-controltower-execution-role.yaml](prereq-controltower-execution-role.yaml) template to 
         create a CloudFormation stack in the Primary account.
3. Create an S3 bucket for the Lambda source code
    1. Use the [prereq-lambda-s3-bucket.yaml](prereq-lambda-s3-bucket.yaml) template to create a CloudFormation
        StackSet in the Primary account for each region that will deploy custom resources.
4. Package the Lambda code and required libraries (e.g. solution/code/src) into a zip file and upload it to the
   Lambda source S3 bucket.
   1. Use the [packaging script](../../packaging-scripts/package-lambda.sh) to download the required libraries, 
      create a zip file, and upload it to a provided S3 bucket. Usage details are at the top of the script.
5. (Optional) Create SSM parameters for the AWS Account IDs and AWS Organizations ID
   1. Use the [prereq-ssm-account-params.yaml](prereq-ssm-account-params.yaml) template to create a CloudFormation
      stack in the Primary account.
   