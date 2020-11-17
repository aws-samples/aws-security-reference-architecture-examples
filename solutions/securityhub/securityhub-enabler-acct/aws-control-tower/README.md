Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----
   
# Implementation Instructions

1. Make sure the required [prerequisites](../../../../extras/aws-control-tower/prerequisites/README.md) are completed
2. Copy the files to the Customizations for AWS Control Tower configuration 
   1. customizations-for-control-tower-configuration
       1. [manifest.yaml](manifest.yaml)
       2. [parameters/securityhub-enabler-acct-role.json](parameters/securityhub-enabler-acct-role.json)
       3. [parameters/securityhub-enabler-acct-role.json](parameters/securityhub-enabler-acct.json)
       4. [templates/securityhub-enabler-acct-role.yaml](../templates/securityhub-enabler-acct-role.yaml)
       5. [templates/securityhub-enabler-acct.yaml](../templates/securityhub-enabler-acct.yaml) 
3. Update the parameter files with any specific values for your environment
4. Update the manifest.yaml file with your account names
5. Deploy the Customizations for AWS Control Tower configuration
6. How to verify after the pipeline completes?
   1. Log into the Audit account and navigate to the Security Hub page
   2. Verify the correct configurations have been applied to each region
      1. Security standards enabled
      2. Settings -> Accounts enabled
      3. Integrations enabled
      
      
# Delete Instructions

1. Within the Customizations for AWS Control Tower configuration
   1. Remove the Security Hub configurations from the manifest.yaml file
   2. (Optional) Delete the parameter and template files for the Security Hub solution
2. Deploy the Customizations for AWS Control Tower configuration
3. After the pipeline completes, log into the Primary account and navigate to the CloudFormation page
   1. Delete the Stack Instance from the CustomControlTower-SecurityHubEnablerService CloudFormation StackSet
   2. After the Stack Instance deletes, delete the CustomControlTower-SecurityHubEnablerService CloudFormation StackSet
   3. Log into the Log Archive account and delete the 2 org-trail-logs S3 buckets
   4. Delete the Stack Instance from the CustomControlTower-SecurityHubEnablerRole CloudFormation StackSet
   5. After the Stack Instance deletes, delete the CustomControlTower-SecurityHubEnablerRole CloudFormation StackSet
   