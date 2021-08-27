Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----
   
# Implementation Instructions

1. Make sure the required [prerequisites](../../../../extras/aws-control-tower/prerequisites/README.md) are completed
2. Copy the files to the Customizations for AWS Control Tower configuration 
   1. customizations-for-control-tower-configuration
       1. [manifest.yaml](manifest.yaml)
       2. [parameters/macie-org-configuration.json](parameters/macie-org-configuration.json)
       3. [parameters/macie-org-configuration-role.json](parameters/macie-org-configuration-role.json)
       4. [parameters/macie-org-member-disable-role.json](parameters/macie-org-member-disable-role.json)
       5. [parameters/macie-org-kms-key.json](parameters/macie-org-kms-key.json)
       6. [parameters/macie-org-s3-bucket.json](parameters/macie-org-s3-bucket.json)
       7. [templates/macie-org-configuration.yaml](../templates/macie-org-configuration.yaml)
       8. [templates/macie-org-configuration-role.yaml](../templates/macie-org-configuration-role.yaml)
       9. [templates/macie-org-member-disable-role.yaml](../templates/macie-org-member-disable-role.yaml)
       10. [templates/macie-org-kms-key.yaml](../templates/macie-org-kms-key.yaml)
       11. [templates/macie-org-s3-bucket.yaml](../templates/macie-org-s3-bucket.yaml) 
3. Update the parameter files with any specific values for your environment
4. Update the manifest.yaml file with your account names
5. Deploy the Customizations for AWS Control Tower configuration
6. How to verify after the pipeline completes?
   1. Log into the Management account and navigate to the Macie page
      1. Validate that the delegated admin account is set for each region
   2. Log into the Audit account and navigate to the Macie page
      1. Verify the correct Macie configurations have been applied to each region
      2. Verify all existing accounts have been enabled
      3. Verify the findings export is configured for the S3 bucket
      4. Generate sample findings to verify S3 delivery
   3. Log into the Log archive account and navigate to the S3 page
      1. Verify the sample findings have been delivered
      
# Delete Instructions

1. Delete the Stack Instance from the CustomControlTower-MacieOrgConfiguration CloudFormation StackSet
   1. Verify that Macie is disabled in all accounts
2. Within the Customizations for AWS Control Tower configuration
   1. Remove the Macie configurations from the manifest.yaml file
   2. (Optional) Delete the parameter and template files for the Macie solution
3. Deploy the Customizations for AWS Control Tower configuration
4. After the pipeline completes, log into the Management account and navigate to the CloudFormation page 
   1. Delete the CustomControlTower-MacieOrgDeliveryS3Bucket CloudFormation StackSet
   2. Log into the Log Archive account and delete the Macie S3 bucket
   3. Delete the Stack Instance from the CustomControlTower-MacieOrgDeliveryS3Bucket CloudFormation StackSet
   4. After the Stack Instance deletes, delete the CustomControlTower-MacieOrgDeliveryS3Bucket CloudFormation StackSet
   5. Delete the Stack Instance from the CustomControlTower-MacieOrgDeliveryKMSKey CloudFormation StackSet
   6. After the Stack Instance deletes, delete the CustomControlTower-MacieOrgDeliveryKMSKey CloudFormation StackSet
   7. Delete the Stack Instances from the CustomControlTower-MacieOrgMemberDisableRole CloudFormation StackSet
   8. After the Stack Instance deletes, delete the CustomControlTower-MacieOrgMemberDisableRole CloudFormation StackSet
   9. Delete the Lambda CloudWatch Log Group within the Management account
   
   

      