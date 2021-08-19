Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----

# Implementation Instructions
> **Core accounts within the manifest.yaml must be listed in the following order for this solution to work:**
1. Security Account (MacieOrgConfigurationRole)
2. Security Account (MacieOrgDeliveryKMSKey)
3. Logging Account (MacieOrgDeliveryS3Bucket)
4. Management Account (MacieOrgConfiguration)
5. All Accounts (MacieOrgMemberDisableRole)

### Pre-requisites
* Disable Macie in all accounts/regions
   
### Instructions
1. Create new or use existing S3 buckets within the ALZ region owned by the Organization Primary Account
   * Example bucket name: lambda-zips-[Management Account ID]-[ALZ Region]
   * [Example CloudFormation Template](../../../../extras/lambda-s3-buckets.yaml)
   * Each bucket must allow the s3:GetObject action to the Organization using a bucket policy like the one below to 
        allow the accounts within the Organization to get the Lambda files.
    ```
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:${AWS::Partition}:s3:::[BUCKET NAME]/*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalOrgID": "[ORGANIZATION ID]"
                    }
                }
            }
        ]
    }
    ```
2. Package the Lambda code into a zip file and upload it to the Lambda source S3 bucket
   * Package and Upload the Lambda zip file to S3 (Packaging script: /extras/packaging-scripts/package-lambda.sh)
3. Create a new folder (e.g. macie-org) in the Landing Zone configuration add-on folder
4. Copy the below folders/files to the new add-on folder excluding the lambda folder
   * aws-landing-zone/add_on_manifest.yaml
   * aws-landing-zone/user-input.yaml
   * aws-landing-zone/parameters/macie-org-configuration.json
   * aws-landing-zone/parameters/macie-org-configuration-role.json
   * aws-landing-zone/parameters/macie-org-kms-key.json
   * aws-landing-zone/parameters/macie-org-s3-bucket.json
   * aws-landing-zone/parameters/macie-org-member-disable-role.json
   * templates/macie-org-configuration.yaml
   * templates/macie-org-configuration-role.yaml
   * templates/macie-org-kms-key.yaml
   * templates/macie-org-s3-bucket.yaml
   * templates/macie-org-member-disable-role.yaml
5. Update the parameter files with any specific values for your Landing Zone implementation
6. Update the add_on_manifest.yaml with any specific values for your Landing Zone configuration
7. Deploy the Landing Zone configuration with the new add-on

### Instructions to remove the solution
1. Manually delete the stack instance from the MacieOrgConfiguration CloudFormation StackSet
   1. Confirm Macie is disabled in all accounts
2. Remove the add-on from the AWS Landing Zone configuration
3. Run the ALZ pipeline
4. Wait until the pipeline finishes
5. Manually delete the stack instances from the Macie StackSets in the below order
   1. MacieOrgConfigurationRole
   2. MacieOrgDeliveryS3Bucket - Manually cleanup the S3 bucket after deleting the StackSet
   3. MacieOrgDeliveryKMSKey
   4. MacieOrgMemberDisableRole
6. Delete all the Macie StackSets
7. Delete the Lambda CloudWatch log group in the management account
