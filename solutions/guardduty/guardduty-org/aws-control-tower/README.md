Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----
   
# Implementation Instructions

1. Make sure the required [prerequisites](../../../../extras/aws-control-tower/prerequisites/README.md) are completed
2. Copy the files to the Customizations for AWS Control Tower configuration 
   1. customizations-for-control-tower-configuration
       1. [manifest.yaml](manifest.yaml)
       2. [parameters/guardduty-org-configuration.json](parameters/guardduty-org-configuration.json)
       3. [parameters/guardduty-org-configuration-role.json](parameters/guardduty-org-configuration-role.json)
       4. [parameters/guardduty-org-delete-detector-role.json](parameters/guardduty-org-delete-detector-role.json)
       5. [parameters/guardduty-org-delivery-kms-key.json](parameters/guardduty-org-delivery-kms-key.json)
       6. [parameters/guardduty-org-delivery-s3-bucket.json](parameters/guardduty-org-delivery-s3-bucket.json)
       7. [templates/guardduty-org-configuration.yaml](../templates/guardduty-org-configuration.yaml)
       8. [templates/guardduty-org-configuration-role.yaml](../templates/guardduty-org-configuration-role.yaml)
       9. [templates/guardduty-org-delete-detector-role.yaml](../templates/guardduty-org-delete-detector-role.yaml)
       10. [templates/guardduty-org-delivery-kms-key.yaml](../templates/guardduty-org-delivery-kms-key.yaml)
       11. [templates/guardduty-org-delivery-s3-bucket.yaml](../templates/guardduty-org-delivery-s3-bucket.yaml) 
3. Update the parameter files with any specific values for your environment
4. Update the manifest.yaml file with your account names
5. Deploy the Customizations for AWS Control Tower configuration
6. How to verify after the pipeline completes?
   1. Log into the Management account and navigate to the GuardDuty page
      1. Validate that the delegated admin account is set for each region
   2. Log into the Audit account and navigate to the GuardDuty page
      1. Verify the correct GuardDuty configurations have been applied to each region
      2. Verify all existing accounts have been enabled
      3. Verify the findings export is configured for the S3 bucket
      4. Generate sample findings to verify S3 delivery
   3. Log into the Log archive account and navigate to the S3 page
      1. Verify the sample findings have been delivered
      
# Delete Instructions

1. Within the Customizations for AWS Control Tower configuration
   1. Remove the GuardDuty configurations from the manifest.yaml file
   2. (Optional) Delete the parameter and template files for the GuardDuty solution
2. Deploy the Customizations for AWS Control Tower configuration
3. After the pipeline completes, log into the Management account and navigate to the CloudFormation page
   1. Delete the Stack Instance from the CustomControlTower-GuardDutyOrgConfiguration CloudFormation StackSet
      1. Verify that the GuardDuty has been disabled in all accounts/regions
   2. After the Stack Instance deletes, delete the CustomControlTower-GuardDutyOrgConfiguration CloudFormation StackSet
   3. Delete the Stack Instance from the CustomControlTower-GuardDutyOrgConfigurationRole CloudFormation StackSet
   4. After the Stack Instance deletes, delete the CustomControlTower-GuardDutyOrgConfigurationRole CloudFormation 
      StackSet
   5. Delete the stack instances from the CustomControlTower-GuardDutyDeleteDetectorRole CloudFormation StackSet
   6. After the stack instances are deleted, delete the CustomControlTower-GuardDutyDeleteDetectorRole CloudFormation 
      StackSet 
   7. Log into the Log Archive account and empty/delete the guardduty-delivery S3 bucket
   8. Delete the Stack Instance from the CustomControlTower-GuardDutyOrgDeliveryS3Bucket CloudFormation StackSet
   9. After the Stack Instance deletes, delete the CustomControlTower-GuardDutyOrgDeliveryS3Bucket CloudFormation 
      StackSet
   10. Delete the Stack Instance from the CustomControlTower-GuardDutyOrgDeliveryKMSKey CloudFormation StackSet
   11. After the Stack Instance deletes, delete the CustomControlTower-GuardDutyOrgDeliveryKMSKey CloudFormation 
       StackSet
   12. Verify that the CloudWatch Log Group "/aws/lambda/...guardduty-org-configuration" was deleted
