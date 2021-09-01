Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----
   
# Implementation Instructions

1. Make sure the required [prerequisites](../../../../extras/aws-control-tower/prerequisites/README.md) are completed
2. Package and upload the common-register-delegated-administrator Lambda function from the 
   [Common Register Delegated Administrator Solution](../../../common/register-delegated-administrator)
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
       3. [parameters/aggregator-org-configuration.json](parameters/aggregator-org-configuration.json) 
          -> parameters/aggregator-org-configuration.json
       4. [common/register-delegated-administrator/templates/common-register-delegated-administrator.yaml](../../../common/register-delegated-administrator/templates/common-register-delegated-administrator.yaml) 
          -> templates/common-register-delegated-administrator.yaml
       5. [templates/aggregator-org-configuration.yaml](../templates/aggregator-org-configuration.yaml) 
          -> templates/aggregator-org-configuration.yaml
        
4. Update the parameter files with any specific values for your environment
5. Add "access-analyzer.amazonaws.com" to the pServicePrincipalList parameter in the parameters/common-register-delegated-administrator.json
6. Add the [common/register-delegated-administrator/aws-control-tower/manifest.yaml](../../../common/register-delegated-administrator/aws-control-tower)
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
7. Update the manifest.yaml file with your account names and SSM parameters
8. Deploy the Customizations for AWS Control Tower configuration
9. How to verify after the pipeline completes?
   1. Log into the Audit account and navigate to the AWS Config page
      1. Verify the correct AWS Config Aggregator configurations have been applied
      2. Verify all existing accounts have been enabled (This can take a few minutes to complete)
      
# Delete Instructions

1. Within the Customizations for AWS Control Tower configuration
   1. Remove the Aggregator configuration from the manifest.yaml file
   2. (Optional) Delete the parameter and template files for the Aggregator solution
2. Deploy the Customizations for AWS Control Tower configuration
3. After the pipeline completes, log into the Management account and navigate to the CloudFormation StackSet page
   1. Delete the Stack Instance from the CustomControlTower-AggregatorConfiguration CloudFormation StackSet
   2. After the Stack Instance deletes, delete the CustomControlTower-AggregatorConfiguration CloudFormation StackSet
   