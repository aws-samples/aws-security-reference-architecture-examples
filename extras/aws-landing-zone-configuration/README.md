Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

# AWS Landing Zone Configuration

This is the AWS Landing Zone configuration used to test the add-on solutions. Please review the modifications made to the default configuration and resources below.

#### Resources

- [CIS AWS Foundations Benchmark controls](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html)

#### Modifications to the default AWS Landing Zone Configuration

- Added Account Vending Machine (AVM) templates for each OU (Provides flexibility with having different resources 
    deployed to each OU)
- Change minimum password length to 14 in the password policy template (CIS 1.9)
- Change password reuse prevention to 24 (CIS 1.10)
- Removed CloudTrail configuration (replaced with cloudtrail-org solution)
- Removed GuardDuty configuration (replaced with guardduty-org solution)
- Removed VPC configuration to allow for customer specific VPC templates
- Removed notification templates to allow for customer specific notifications
- Removed config rule templates to leverage Security Hub standards (see securityhub-acct solution)
- Updated logging template to include additional security configurations
    - Removed server access logging and used CloudTrail S3 data events (see cloudtrail-org solution)
    - Added additional bucket policy statements 
       - Restrict access to the AWS Organization
       - Enforce secure transport
       - Enforce bucket-owner-full-control
- Updated security role template to include additional configuration
    - Changed permissions to use SecurityAudit and SystemAdministrator policies instead of ReadOnlyAccess and 
        Administrator which are less permissive
- Changed AWSLogsS3KeyPrefix references in files to the corresponding prefix (Config, CloudTrail) to allow for 
    specific SQS Queues for external log aggregation
- Created a KMS Key for AWS Landing Zone Logs S3 default encryption
- Commented out regions from manifest that are not enabled (e.g. ap-east-1 and me-south-1)

#### Setup and Deployment Notes

- **Review the deployment order instructions included with each solution to ensure the resources are deployed in the correct order**
