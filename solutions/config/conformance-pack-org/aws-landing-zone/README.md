Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----

# Implementation Instructions
### Pre-requisites
1. Create AWS Config Conformance Pack Templates S3 Bucket in the Security Tooling Account
   * Create an SSM parameter in the Organization Master account (Optional)
   * CloudFormation template to create the S3 bucket - documentation/setup/create-conformance-pack-templates-bucket.yaml
2. Upload documentation/setup/conformance-pack-templates/aws-control-tower-detective-guardrails.yaml to the AWS Config 
   Conformance Pack Templates S3 Bucket
   
### Instructions

> **Core accounts within the manifest.yaml must be listed in the following order for this solution to work:**
> 1. management (ConformancePackDelegatedAdmin)
> 2. log-archive (ConformancePackDeliveryBucket)
> 3. security (ConformancePackDeployment)

1. Create new or use an existing S3 bucket within the ALZ region owned by the Organization Management Account
   * Example bucket name: lambda-zips-[Management Account ID]-[ALZ Region]
   * [Example CloudFormation Template](../../../../extras/lambda-s3-buckets.yaml)
   * Each bucket must allow the s3:GetObject action to the AWS Organization using a bucket policy like the one below 
        to allow the accounts within the Organization to get the Lambda files.
    ```
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:[AWS::Partition]:s3:::[BUCKET NAME]/*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalOrgID": "[ORGANIZATION ID]"
                    }
                }
            }
        ]
    }
    ```
2. Package the Lambda code into a zip file and upload it to the S3 bucket
   * Package and Upload the Lambda zip file to S3 (Example script: /extras/packaging-scripts/package-lambda.sh)
3. Create a new folder (e.g. aws-config-organization-rules) in the AWS Landing Zone configuration add-on folder
4. Copy the below folders/files to the new add-on folder excluding the lambda folder
   * aws-landing-zone/add_on_manifest.yaml
   * aws-landing-zone/user-input.yaml
   * aws-landing-zone/parameters/conformance-pack-org-delivery-bucket.json
   * aws-landing-zone/parameters/conformance-pack-org-deployment.json
   * aws-landing-zone/parameters/conformance-pack-org-register-delegated-admin.json
   * templates/core_accounts/conformance-pack-org-delivery-bucket.yaml
   * templates/core_accounts/conformance-pack-org-deployment.yaml
   * templates/core_accounts/conformance-pack-org-register-delegated-admin.yaml
5. Update the parameter files with any specific values for your AWS Landing Zone implementation
6. Update the add_on_manifest.yaml with OU and accounts for your AWS Landing Zone implementation
7. Update the manifest.yaml file so that the core accounts are listed in this order: 
   1. management
   2. log-archive 
   3. security
   * Reason: The AWS Landing Zone deploys resources for the core accounts in the order that they are listed within 
       the manifest.yaml file and the S3 bucket is needed to create the conformance pack.
8. Deploy the Landing Zone configuration with the new add-on