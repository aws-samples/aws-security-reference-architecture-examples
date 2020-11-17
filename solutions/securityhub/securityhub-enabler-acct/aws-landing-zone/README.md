

----

# Implementation Instructions
### Pre-requisites
* Security Hub disabled in all accounts
* [Enabling AWS Config to support security checks](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-settingup.html#securityhub-enable-config)
   
### Instructions

1. Create a new or use an existing S3 bucket within the AWS Landing Zone deployment region owned by the 
    Organizations Primary Account
   * Example bucket name: lambda-zips-[Primary Account ID]-[AWS Landing Zone Region]
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
2. Package the Lambda code into a zip file and upload it to the S3 bucket
   * Package and Upload the Lambda zip file to S3 (Packaging script: /extras/packaging-scripts/package-lambda.sh)
3. Create a new folder (e.g. securityhub-enabler) in the Landing Zone configuration add-on folder
4. Copy the below folders/files to the new add-on folder excluding the lambda folder
   * aws-landing-zone/add_on_manifest.yaml
   * aws-landing-zone/user-input.yaml
   * aws-landing-zone/parameters/securityhub-enabler-acct.json
   * aws-landing-zone/parameters/securityhub-enabler-acct-role.json
   * templates/securityhub-enabler-acct.yaml
   * templates/securityhub-enabler-acct-role.yaml
5. Update the parameter files with any specific values for your Landing Zone implementation
6. Update the add_on_manifest.yaml file with any specific values for your Landing Zone implementation
    * The default AWS Landing Zone configuration:
       * primary account OU = core
       * baseline Account Vending Machine = AWS-Landing-Zone-Account-Vending-Machine
7. Deploy the Landing Zone configuration with the new add-on configuration
    * The initial run of the Lambda will fail due to an Access Denied error. This is expected due to the role not
     existing in the baseline accounts. 
8. Trigger the Lambda to run after the pipeline finishes by:
    1. Within the Lambda AWS console page
    2. Configure test events
       1. Select the Amazon CloudWatch Event template
       2. Enter an Event name
       3. Click Create
    3. Click Test
    4. Monitor the logs in the CloudWatch log group
    
### Instructions to remove the solution
1. Manually delete the stack instance from the SecurityHubEnablerAcctService CloudFormation StackSet
    1. Verify SecurityHub is no longer enabled within the Security Account
2. Delete the SecurityHubEnablerAcctService StackSet
3. Remove the add-on from the AWS Landing Zone configuration
4. Run the ALZ pipeline