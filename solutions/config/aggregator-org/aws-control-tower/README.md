Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----
   
# Implementation Instructions

1. Make sure the required [prerequisites](../../../../extras/aws-control-tower/prerequisites/README.md) are completed
2. Copy the files to the Customizations for AWS Control Tower configuration 
   1. customizations-for-control-tower-configuration
       1. [manifest.yaml](manifest.yaml)
       2. [common/register-delegated-administrator/aws-control-tower/parameters/common-register-delegated-administrator.json](../../../common/register-delegated-administrator/aws-control-tower/parameters/common-register-delegated-administrator.json)
       3. [parameters/aggregator-org-configuration.json](parameters/aggregator-org-configuration.json)
       4. [common/register-delegated-administrator/templates/common-register-delegated-administrator.yaml](../../../common/register-delegated-administrator/templates/common-register-delegated-administrator.yaml)
       5. [templates/aggregator-org-configuration.yaml](../templates/aggregator-org-configuration.yaml)
        
3. Update the parameter files with any specific values for your environment
4. Use the "config.amazonaws.com" value for the pServicePrincipalList
5. Add the [common/register-delegated-administrator/aws-control-tower/manifest.yaml](../../../common/register-delegated-administrator/aws-control-tower)
   resource configuration to your manifest.yaml file.
6. Update the manifest.yaml file with your account names and SSM parameters
7. Deploy the Customizations for AWS Control Tower configuration
8. How to verify after the pipeline completes?
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
   