Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----

# Implementation Instructions
> **Core accounts within the manifest.yaml must be listed in the following order for this solution to work:**
> 1. security (GuardDutyOrgConfigurationRole)
> 2. security (GuardDutyOrgDeliveryKMSKey)
> 3. logging (GuardDutyOrgDeliveryS3Bucket)
> 4. management (GuardDutyOrgConfiguration) 
> 5. all accounts (GuardDutyDeleteDetectorRole)

### Pre-requisites
* Disable GuardDuty in all accounts/regions
* AWS Landing Zone specific changes
   * Remove GuardDutyMaster resource from the manifest.yaml file
   * Move the management account above the other core accounts within the manifest.yaml file
      * This is required to allow the Management account StackSet to deploy before the Delegated Admin StackSet
   * Update all AVM templates to remove the following lines
   ```
   {%- for ou in manifest.organizational_units %}
   {%- for account in ou.core_accounts %}
   {%- for resource in account.core_resources %}
   {%- if 'guardduty' in resource.name.lower() %}
   {% if resource.regions %}
       {% set region_list =  resource.regions %}
   {% else %}
       {% set region_list =  [manifest.region] %}
   {%- endif %}
   {%- for region in region_list %       
   #
   # GuardDuty Custom Resource - {{ region }} (depends on release/v2.0)
   
   GuardDutyMemberof{{ account.name.title() | replace("-","") | replace("_","")}}Account{{region.title() | replace("-","") }}:
       DependsOn:
       - Organizations
       Type: Custom::HandShakeStateMachine
       Properties:
       ServiceType: GuardDuty
       HubAccountId: !GetAtt 'SSMGetParameters./org/member/{{ account.name }}/account_id'
       HubRegion: {{ region }}
       SpokeAccountId: !GetAtt 'Organizations.AccountId'
       SpokeRegion: {{ region }}
       SpokeEmailId: !Ref AccountEmail
       ServiceToken: {{ lambda_arn }       
   {%- endfor %}
   {%- endif %}
   {%- endfor %}
   {%- endfor %}
   {%- endfor %}
   ```
   * Run the ALZ pipeline and wait for it to finish
   * Verify that the GuardDuty StackSet does not have any stack instances and delete the StackSet
   
### Instructions
1. Create new or use existing S3 buckets within the ALZ region owned by the Organization Management Account
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
3. Create a new folder (e.g. guardduty-org) in the Landing Zone configuration add-on folder
4. Copy the below folders/files to the new add-on folder excluding the lambda folder
   * aws-landing-zone/add_on_manifest.yaml
   * aws-landing-zone/user-input.yaml
   * aws-landing-zone/parameters/guardduty-org-configuration.json
   * aws-landing-zone/parameters/guardduty-org-configuration-role.json
   * aws-landing-zone/parameters/guardduty-org-delivery-kms-key.json
   * aws-landing-zone/parameters/guardduty-org-delivery-s3-bucket.json
   * aws-landing-zone/parameters/guardduty-org-delete-detector-role.json
   * templates/guardduty-org-configuration.yaml
   * templates/guardduty-org-configuration-role.yaml
   * templates/guardduty-org-delivery-kms-key.yaml
   * templates/guardduty-org-delivery-s3-bucket.yaml
   * templates/guardduty-org-delete-detector-role.yaml
5. Update the parameter files with any specific values for your Landing Zone implementation
6. Update the add_on_manifest.yaml with any specific values for your Landing Zone configuration
7. Deploy the Landing Zone configuration with the new add-on

### Instructions to remove the solution
1. Remove the add-on from the AWS Landing Zone configuration
2. Run the ALZ pipeline
3. Wait until the pipeline finishes
4. Manually delete the stack instance from the GuardDuty StackSets in the below order
   1. GuardDutyOrgConfiguration
   2. GuardDutyOrgConfigurationRole
   3. GuardDutyOrgDeliveryS3Bucket - Manually cleanup the S3 bucket after deleting the StackSet
   4. GuardDutyOrgDeliveryKMSKey
   5. GuardDutyDeleteDetectorRole
4. Delete the GuardDuty StackSets
5. Verify that GuardDuty is no longer enabled within each region
