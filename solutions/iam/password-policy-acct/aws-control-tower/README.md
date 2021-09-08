Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----
   
# Implementation Instructions

1. Make sure the required [prerequisites](../../../../extras/aws-control-tower/prerequisites/README.md) are completed
2. Package and upload the password-policy-acct Lambda function
   ```shell
    export AWS_ACCESS_KEY_ID=INSERT_AWS_ACCESS_KEY_ID
    export AWS_SECRET_ACCESS_KEY=INSERT_AWS_SECRET_ACCESS_KEY
    export AWS_SESSION_TOKEN=INSERT_AWS_SESSION_TOKEN
   
    export BUCKET=lambda-zips-CHANGE_ME_ACCOUNT_ID-CHANGE_ME_REGION
    sh ~/aws-security-reference-architecture-examples/extras/packaging-scripts/package-lambda.sh \
    --file_name password-policy-acct.zip \
    --bucket $BUCKET \
    --src_dir ~/aws-security-reference-architecture-examples/solutions/iam/password-policy-acct/code/src
   ```
3. Copy the files to the Customizations for AWS Control Tower configuration 
   1. customizations-for-control-tower-configuration
       1. [manifest.yaml](manifest.yaml) -> manifest.yaml
       2. [parameters/password-policy-acct.json](parameters/password-policy-acct.json) 
           -> parameters/password-policy-acct.json
       3. [templates/password-policy-acct.yaml](../templates/password-policy-acct.yaml) 
           -> templates/password-policy-acct.yaml
        
4. Update the parameter files with any specific values for your environment
5. Update the manifest.yaml file with your account names and SSM parameters
6. Deploy the Customizations for AWS Control Tower configuration
7. How to verify after the pipeline completes?
   1. Log into any account within the AWS Organization
      1. Navigate to the IAM -> Account settings page
      2. Verify the custom password policy settings
      
# Delete Instructions

1. Within the Customizations for AWS Control Tower configuration
   1. Remove the Password Policy configuration from the manifest.yaml file
   2. (Optional) Delete the parameter and template files for the Password Policy solution
2. Deploy the Customizations for AWS Control Tower configuration
3. After the pipeline completes, log into the Management account and navigate to the CloudFormation StackSet page
   1. Delete the Stack Instances from the CustomControlTower-PasswordPolicy CloudFormation StackSet
   2. After the Stack Instance deletes, delete the CustomControlTower-PasswordPolicy CloudFormation StackSet
