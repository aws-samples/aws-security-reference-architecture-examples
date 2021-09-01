Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----
   
# Implementation Instructions

1. Make sure the required [prerequisites](../../../../extras/aws-control-tower/prerequisites/README.md) are completed
2. Package and upload the common-register-delegated-administrator Lambda function
   ```shell
    export AWS_ACCESS_KEY_ID=INSERT_AWS_ACCESS_KEY_ID
    export AWS_SECRET_ACCESS_KEY=INSERT_AWS_SECRET_ACCESS_KEY
    export AWS_SESSION_TOKEN=INSERT_AWS_SESSION_TOKEN
   
    export BUCKET=lambda-zips-CHANGE_ME_ACCOUNT_ID-CHANGE_ME_REGION
    sh ~/aws-security-reference-architecture-examples/extras/packaging-scripts/package-lambda.sh \
    --file_name common-register-delegated-admin.zip \
    --bucket $BUCKET \
    --src_dir ~/aws-security-reference-architecture-examples/solutions/common/register-delegated-admninistrator/code/src
   ```
3. Copy the files to the Customizations for AWS Control Tower configuration 
   1. customizations-for-control-tower-configuration
       1. [manifest.yaml](manifest.yaml) -> manifest.yaml 
       2. [common/register-delegated-administrator/aws-control-tower/parameters/common-register-delegated-administrator.json](../../../common/register-delegated-administrator/aws-control-tower/parameters/common-register-delegated-administrator.json) 
          -> parameters/common-register-delegated-administrator.json
       3. [common/register-delegated-administrator/templates/common-register-delegated-administrator.yaml](../../../common/register-delegated-administrator/templates/common-register-delegated-administrator.yaml) 
          -> templates/common-register-delegated-administrator.yaml
4. Add service principals to the pServicePrincipalList parameter in the 
   parameters/common-register-delegated-administrator.json
5. Add the [common/register-delegated-administrator/aws-control-tower/manifest.yaml](../../../common/register-delegated-administrator/aws-control-tower)
   resource configuration to your manifest.yaml file.
   ```yaml
   ...
   cloudformation_resources:
   # -----------------------------------------------------------------------------
   # Common Register Delegated Administrator
   # -----------------------------------------------------------------------------
   - name: CommonRegisterDelegatedAdmin
     template_file: templates/common-register-delegated-administrator.yaml
     parameter_file: parameters/common-register-delegated-administrator.json
     deploy_method: stack_set
     deploy_to_account:
       - REPLACE_ME_ORG_MANAGEMENT_ACCOUNT_NAME
   ...
   ```
6. Update the manifest.yaml file with your account names and SSM parameters
7. Deploy the Customizations for AWS Control Tower configuration
8. How to verify after the pipeline completes?
   1. Export the management account credentials in your local terminal and run the following script:
      ```shell
       for accountId in $(aws organizations list-delegated-administrators --query 'DelegatedAdministrators[*].Id' \
       --output text); do echo -e "$accountId\n Service Principals: " \
       $(aws organizations list-delegated-services-for-account --account-id $accountId \
       --query 'DelegatedServices[*].ServicePrincipal'); done
      ```
   2. Verify that the service principals are listed for the delegated administrator account
      
# Delete Instructions

1. Verify that all solutions related to the service principals are removed before deleting the solution
2. Within the Customizations for AWS Control Tower configuration
   1. Remove the Common Register Delegated Administrator configuration from the manifest.yaml file
   2. (Optional) Delete the parameter and template files for the Common Register Delegated Administrator solution
3. Deploy the Customizations for AWS Control Tower configuration
4. After the pipeline completes, log into the Management account and navigate to the CloudFormation StackSet page
   1. Delete the Stack Instance from the CustomControlTower-CommonRegisterDelegatedAdmin CloudFormation StackSet
   2. After the Stack Instance deletes, delete the CustomControlTower-CommonRegisterDelegatedAdmin CloudFormation 
      StackSet
   