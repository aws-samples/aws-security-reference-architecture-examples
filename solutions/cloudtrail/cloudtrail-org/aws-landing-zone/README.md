Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----

# Implementation Instructions

> **Core accounts within the manifest.yaml must be listed in the following order for this solution to work:**
> 1. security 
> 2. log-archive 
> 3. primary

1.  Create new or use an existing S3 bucket within the us-east-1 region owned by the Organization Primary Account
   * Example bucket name: lambda-zips-[Master Account ID]-us-east-1
   * [Example CloudFormation Template](../../../../extras/lambda-s3-buckets.yaml)
   * The bucket must allow the s3:GetObject action to the Organization using a bucket policy like the one below to 
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
2. Package the Lambda code into a zip file and upload it to the Lambda source S3 bucket
   * Package and Upload the Lambda zip file to S3 (Packaging script: /extras/packaging-scripts/package-lambda.sh)
3. Create a new folder (e.g. cloudtrail-org) in the Landing Zone configuration add-on folder
4. Copy the below folders/files to the new add-on folder excluding the lambda folder
   * aws-landing-zone/add_on_manifest.yaml
   * aws-landing-zone/user-input.yaml
   * aws-landing-zone/parameters/cloudtrail-org-bucket.json
   * aws-landing-zone/parameters/cloudtrail-org-kms.json
   * aws-landing-zone/parameters/cloudtrail-org.json
   * templates/cloudtrail-org-bucket.yaml
   * templates/cloudtrail-org-kms.yaml
   * templates/cloudtrail-org.yaml
5. Update the parameter files with any specific values for your Landing Zone configuration
6. Update the add_on_manifest.yaml with any specific values for your Landing Zone configuration
7. Deploy the Landing Zone configuration with the new add-on
8. After the AWS Landing Zone pipeline completes, uncomment the encryption statements in the cloudtrail-org-bucket.yaml 
    file and deploy the changes
9. If replacing an existing Organization Trail with this solution:
   * Update any metric filters and any other resources that reference the CloudWatch Log Group
   * If a CloudWatch Log Group Subscription is used for forwarding the logs, remove the Subscription from the old group 
        and add it to the new group
