Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----
   
# Implementation Instructions

1. Make sure the required [prerequisites](../../../../extras/aws-control-tower/prerequisites/README.md) are completed
2. Copy the files to the Customizations for AWS Control Tower configuration 
   1. customizations-for-control-tower-configuration
       1. [manifest.yaml](manifest.yaml)
       2. [parameters/cloudtrail-org-bucket.json](parameters/cloudtrail-org-bucket.json)
       3. [parameters/cloudtrail-org-kms.json](parameters/cloudtrail-org-kms.json)
       4. [parameters/cloudtrail-org.json](parameters/cloudtrail-org.json)
       5. [templates/cloudtrail-org-bucket.yaml](../templates/cloudtrail-org-bucket.yaml)
       6. [templates/cloudtrail-org-kms.yaml](../templates/cloudtrail-org-kms.yaml)
       7. [templates/cloudtrail-org.yaml](../templates/cloudtrail-org.yaml) 
3. Update the parameter files with any specific values for your environment
4. Update the manifest.yaml file with your account names
5. Deploy the Customizations for AWS Control Tower configuration
6. How to verify after the pipeline completes?
   1. Log into the Primary account and navigate to the CloudTrail page
   2. Select Trails and select the "control-tower-cloudtrail-org" trail
   3. Verify the correct configurations have been applied
      1. Trail log location
      2. Log file SSE-KMS encryption
      3. Log file validation
      4. CloudWatch Logs
      5. Tags
      6. Management Events
      7. Data Events
      
      
# Delete Instructions

1. Within the Customizations for AWS Control Tower configuration
   1. Remove the CloudTrail configurations from the manifest.yaml file
   2. (Optional) Delete the parameter and template files for the CloudTrail solution
2. Deploy the Customizations for AWS Control Tower configuration
3. After the pipeline completes, log into the Primary account and navigate to the CloudFormation page
   1. Delete the Stack Instance from the CustomControlTower-CloudTrailOrg CloudFormation StackSet
      1. Verify that the CloudTrail created by the solution has been deleted
   2. After the Stack Instance deletes, delete the CustomControlTower-CloudTrailOrg CloudFormation StackSet
   3. Log into the Log Archive account and delete the 2 org-trail-logs S3 buckets
   4. Delete the Stack Instance from the CustomControlTower-CloudTrailOrgS3Buckets CloudFormation StackSet
   5. After the Stack Instance deletes, delete the CustomControlTower-CloudTrailOrgS3Buckets CloudFormation StackSet
   6. Delete the Stack Instance from the CustomControlTower-CloudTrailOrgKMSKey CloudFormation StackSet
   7. After the Stack Instance deletes, delete the CustomControlTower-CloudTrailOrgKMSKey CloudFormation StackSet
   
   

      