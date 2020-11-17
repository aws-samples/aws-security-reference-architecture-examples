Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

----
   
# Implementation Instructions

1. Make sure the required [prerequisites](../../../../extras/aws-control-tower/prerequisites/README.md) are completed
2. Copy the files to the Customizations for AWS Control Tower configuration 
   1. customizations-for-control-tower-configuration
       1. [manifest.yaml](manifest.yaml)
       2. [parameters/firewall-manager-org-delegate-admin.json](parameters/firewall-manager-org-delegate-admin.json)
       3. [parameters/firewall-manager-org-disassociate-iam-role.json](parameters/firewall-manager-org-disassociate-iam-role.json)
       4. [parameters/firewall-manager-org-sg-policy.json](parameters/firewall-manager-org-sg-policy.json)
       5. [templates/firewall-manager-org-delegate-admin.yaml](../templates/firewall-manager-org-delegate-admin.yaml)
       6. [templates/firewall-manager-org-disassociate-iam-role.yaml](../templates/firewall-manager-org-disassociate-iam-role.yaml) 
       7. [templates/firewall-manager-org-sg-policy.yaml](../templates/firewall-manager-org-sg-policy.yaml)
       8. [templates/firewall-manager-org-waf-policy.yaml](../templates/firewall-manager-org-waf-policy.yaml)
3. Update the parameter files with any specific values for your environment
4. Update the manifest.yaml file with your account names
5. Deploy the Customizations for AWS Control Tower configuration
6. How to verify after the pipeline completes?
   1. Log into the Audit account and navigate to the AWS Firewall Manager page
   2. Verify the correct configurations have been applied
      1. Security policies 
         * security-group-maximum-allowed
         * security-group-common-policy
         * fms-regional-waf-default-policy
         * fms-regional-waf-windows-policy
         * fms-regional-waf-linux-policy
         * fms-regional-waf-posix-policy
      
      
# Delete Instructions

1. Within the Customizations for AWS Control Tower configuration
   1. Remove the Firewall Manager configurations from the manifest.yaml file
   2. (Optional) Delete the parameter and template files for the Firewall Manager solution
2. Deploy the Customizations for AWS Control Tower configuration
3. After the pipeline completes, log into the Primary account and navigate to the CloudFormation page
   1. Delete the CustomControlTower-FirewallManager* CloudFormation StackSets
   