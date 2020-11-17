Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

# Implementation Instructions

> **Core accounts within the manifest.yaml must be listed in the following order for this solution to work:**
> 1. primary (master) 
> 2. security 

### Pre-requisites
* No existing AWS Config Aggregator
* Make sure there are no SCP statements preventing the following actions:
   * config:DeleteConfigurationAggregator
   * config:PutConfigurationAggregator
   
### Instructions
1. Create new or use existing S3 bucket within the ALZ deployment region owned by the Organization Primary Account. 
The region needs to be the same as the AWS Config Aggregator CloudFormation Stack region. The default ALZ region 
in the manifest.yaml file is used.
   * Example bucket name: lambda-zips-[Primary Account ID]-us-east-1
   * [Example CloudFormation Template](../../../../extras/lambda-s3-buckets.yaml)
   * The bucket must allow the s3:GetObject action to the Organization using a bucket policy like the one below 
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
   * Package and Upload the Lambda zip file to S3 (Packing script: /extras/packaging-scripts/package-lambda.sh)
3. Create a new folder (e.g. aggregator-acct) in the Landing Zone configuration add-on folder
4. Copy the below folders/files to the new add-on folder excluding the lambda folder
   * aws-landing-zone/add_on_manifest.yaml
   * aws-landing-zone/user-input.yaml
   * aws-landing-zone/parameters/aggregator-acct-role.json
   * aws-landing-zone/parameters/aggregator-acct-lambda.json
   * aws-landing-zone/parameters/aggregator-acct-authorization.json
   * templates/aggregator-acct-role.yaml
   * templates/aggregator-acct-lambda.yaml
   * templates/aggregator-acct-authorization.yaml
5. Update the parameter files with any specific values for your implementation
6. Update the add_on_manifest.yaml with the corresponding OUs and AVM templates
7. Deploy the Landing Zone configuration with the new add-on