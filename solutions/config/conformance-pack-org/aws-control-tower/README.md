Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----
   
# Implementation Instructions

1. Make sure the required [prerequisites](../../../../extras/aws-control-tower/prerequisites/README.md) are completed
2. Verify that all accounts in the organization have an AWS Configuration Recorder
   * Run the [list-config-recorder-status.py](../../../../extras/aws-control-tower/helper-scripts/list-config-recorder-status.py) 
     within the Organization Management account to get the list of accounts.
   * Include the Account IDs without an AWS Configuration Recorder in the pExcludedAccounts parameter 
3. Create the Conformance Pack Template S3 bucket within the Security Tooling account using the 
    [create-conformance-pack-templates-bucket.yaml](../documentation/setup/create-conformance-pack-templates-bucket.yaml)
    template
4. Upload the [Operational-Best-Practices-for-Encryption-and-Keys.yaml](../documentation/setup/conformance-pack-templates/Operational-Best-Practices-for-Encryption-and-Keys.yaml) 
   conformance pack template to the Conformance Pack Template S3 bucket created above.
5. Add the /org/config/conformance_pack_templates_bucket SSM Parameter in the Management account
   ```
   aws ssm put-parameter \ 
       --name /org/config/conformance_pack_templates_bucket \ 
       --value conformance-pack-templates-123456789012-us-east-1 \ 
       --description "Conformance pack templates S3 bucket" \
       --tags Key=control-tower,Value=managed-by-control-tower
   ```
6. Copy the files to the Customizations for AWS Control Tower configuration 
   1. customizations-for-control-tower-configuration
       1. [manifest.yaml](manifest.yaml)
       2. [parameters/conformance-pack-org-register-delegated-admin.json](parameters/conformance-pack-org-register-delegated-admin.json)
       3. [parameters/conformance-pack-org-delivery-bucket.json](parameters/conformance-pack-org-delivery-bucket.json)
       4. [parameters/conformance-pack-org-deployment.json](parameters/conformance-pack-org-deployment.json)
       5. [templates/conformance-pack-org-register-delegated-admin.yaml](../templates/conformance-pack-org-register-delegated-admin.yaml)
       6. [templates/conformance-pack-org-delivery-bucket.yaml](../templates/conformance-pack-org-delivery-bucket.yaml) 
       7. [templates/conformance-pack-org-deployment.yaml](../templates/conformance-pack-org-deployment.yaml)
7. Update the parameter files with any specific values for your environment
8. Update the manifest.yaml file with your account names
9. Deploy the Customizations for AWS Control Tower configuration
10. How to verify after the pipeline completes?
   1. Log into the Security Tooling account and navigate to the AWS Config page
   2. Verify the correct configurations have been applied to each region
      1. Conformance packs -> OrgConformsPack-Operational-Best-Practices-for-Encryption-and-Keys-* created in each region
      2. Settings -> Delivery location set to the awsconfigconforms-[Log Archive Account ID]-[Region]
      
      
# Delete Instructions

1. Within the Customizations for AWS Control Tower configuration
   1. Remove the Conformance Pack configurations from the manifest.yaml file
   2. (Optional) Delete the parameter and template files for the Conformance Pack solution
2. Deploy the Customizations for AWS Control Tower configuration
3. After the pipeline completes, log into the Management account and navigate to the CloudFormation page
   1. Delete the CustomControlTower-ConformancePack* CloudFormation StackSets
   