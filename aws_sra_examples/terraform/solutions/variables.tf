########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "account_region" {
  description = "Account Region used for assuming role"
  type        = string
}

variable "account_id" {
  description = "Account ID used for assuming role"
  type        = string
}
########################################################################
# Main Configuration Parameters
########################################################################

variable "customer_control_tower_regions" {
  description = "The name for customer control tower regions."
  type        = string
}

variable "customer_control_tower_regions_without_home_region" {
  description = "The name for customer control tower regions without home region."
  type        = string
}

variable "enabled_regions" {
  description = "The name for enabled regions."
  type        = string
}

variable "enabled_regions_without_home_region" {
  description = "The name for enabled regions without home region."
  type        = string
}

variable "home_region" {
  description = "The name for the home region."
  type        = string
}

variable "audit_account_id" {
  description = "The name for the audit account ID."
  type        = string
}

variable "log_archive_account_id" {
  description = "The name for the log archive account ID."
  type        = string
}

variable "management_account_id" {
  description = "The name for the management account ID."
  type        = string
}

variable "organization_id" {
  description = "The SSM parameter name for the organization ID."
  type        = string
}

variable "root_organizational_unit_id" {
  description = "The name for the root organizational unit ID."
  type        = string
}

variable "sra_alarm_email" {
  description = "(Optional) Email address for receiving DLQ alarms"
  type        = string
  default     = ""
}

########################################################################
# Service Configurations
########################################################################
variable "enable_member_account_parameters" {
  description = "Enable or disable Members Account Paramters module"
  type        = bool
  default     = true
}

variable "enable_gd" {
  description = "Enable or disable Guard Duty module"
  type        = bool
  default     = true
}

variable "enable_sh" {
  description = "Enable or disable Security Hub module"
  type        = bool
  default     = true
}

variable "enable_access_analyzer" {
  description = "Enable or disable IAM Access Analyzer module"
  type        = bool
  default     = true
}

variable "enable_macie" {
  description = "Enable or disable Macie module"
  type        = bool
  default     = true
}

variable "enable_cloudtrail_org" {
  description = "Enable or disable CloudTrail Organization module"
  type        = bool
  default     = true
}

variable "enable_inspector" {
  description = "Enable or disable Inspector module"
  type        = bool
  default     = true
}

variable "enable_iam_password_policy" {
  description = "Enable or disable IAM Password Policy Module"
  type        = bool
  default     = true
}

########################################################################
# Guard Duty Settings
########################################################################
variable "disable_guard_duty" {
  description = "Update to 'true' to disable GuardDuty in all accounts and regions before deleting the TF."
  type        = string
  default     = "false"
}

variable "enable_s3_logs" {
  description = "Auto enable S3 logs"
  type        = string
}

variable "enable_kubernetes_audit_logs" {
  description = "Auto enable Kubernetes Audit Logs"
  type        = string
}

variable "enable_malware_protection" {
  description = "Auto enable Malware Protection"
  type        = string
}

variable "enable_rds_login_events" {
  description = "Auto enable RDS Login Events"
  type        = string
}

variable "enable_runtime_monitoring" {
  description = "Auto enable EKS Runtime Monitoring"
  type        = string
}

variable "enable_ecs_fargate_agent_management" {
  description = "Auto enable ECS Fargate Agent Management"
  type        = string
}

variable "enable_ec2_agent_management" {
  description = "Auto EC2 Agent Management"
  type        = string
}

variable "enable_eks_addon_management" {
  description = "Auto enable EKS Add-on Management"
  type        = string
}

variable "enable_lambda_network_logs" {
  description = "Auto enable Lambda Network Logs"
  type        = string
}

variable "finding_publishing_frequency" {
  description = "Finding publishing frequency"
  type        = string
  default     = "FIFTEEN_MINUTES"
}

variable "guardduty_control_tower_regions_only" {
  description = "Only enable in the Control Tower governed regions"
  type        = string
  default     = "true"
}

########################################################################
# Security Hub Configurations
########################################################################
variable "cis_standard_version" {
  description = "CIS Standard Version"
  type        = string
}

variable "compliance_frequency" {
  description = "Frequency to Check for Organizational Compliance (in days between 1 and 30, default is 7)"
  type        = number
}

variable "securityhub_control_tower_regions_only" {
  description = "Only enable in the Control Tower governed regions"
  type        = bool
}

variable "disable_security_hub" {
  description = "Update to 'true' to disable Security Hub in all accounts and regions before deleting the stack"
  type        = bool
}

variable "enable_cis_standard" {
  description = "Indicates whether to enable the CIS AWS Foundations Benchmark Standard"
  type        = bool
}

variable "enable_pci_standard" {
  description = "Indicates whether to enable the Payment Card Industry Data Security Standard (PCI DSS)"
  type        = bool
}

variable "enable_nist_standard" {
  description = "Indicates whether to enable the National Institute of Standards and Technology (NIST) SP 800-53 Rev. 5"
  type        = bool
}

variable "enable_security_best_practices_standard" {
  description = "Indicates whether to enable the AWS Foundational Security Best Practices Standard"
  type        = bool
}

variable "pci_standard_version" {
  description = "PCI Standard Version"
  type        = string
}

variable "nist_standard_version" {
  description = "NIST Standard Version"
  type        = string
}

variable "security_best_practices_standard_version" {
  description = "SBP Standard Version"
  type        = string
}

########################################################################
# Inspector Configurations
########################################################################
variable "ecr_rescan_duration" {
  description = "ECR Rescan Duration"
  type        = string
  default     = "LIFETIME"
}

variable "scan_components" {
  description = "Components to scan (e.g., 'ec2,ecs')"
  type        = string
  default     = "ec2"
}

variable "inspector_control_tower_regions_only" {
  description = "Only enable in the Control Tower governed regions"
  type        = string
  default     = "true"
}

variable "disable_inspector" {
  description = "Set to true BEFORE removing/destroying the solution to reduce the chance of orphaned resources/configuraitons"
  type        = bool
  default     = false
}

########################################################################
# IAM Password Policy
########################################################################
variable "iam_password_policy_allow_users_to_change_password" {
  type        = string
  description = "You can permit all IAM users in your account to use the IAM console to change their own passwords."
}

variable "iam_password_policy_hard_expiry" {
  type        = string
  description = "You can prevent IAM users from choosing a new password after their current password has expired."
}

variable "iam_password_policy_max_password_age" {
  type        = string
  description = "You can set IAM user passwords to be valid for only the specified number of days."
}

variable "iam_password_policy_minimum_password_length" {
  type        = string
  description = "You can specify the minimum number of characters allowed in an IAM user password."
}

variable "iam_password_policy_password_reuse_prevention" {
  type        = string
  description = "You can prevent IAM users from reusing a specified number of previous passwords."
}

variable "iam_password_policy_require_lowercase_characters" {
  type        = string
  description = "You can require that IAM user passwords contain at least one lowercase character from the ISO basic Latin alphabet (a to z)."
}

variable "iam_password_policy_require_numbers" {
  type        = string
  description = "You can require that IAM user passwords contain at least one numeric character (0 to 9)."
}

variable "iam_password_policy_require_symbols" {
  type        = string
  description = "You can require that IAM user passwords contain at least one of the following nonalphanumeric characters: ! @ # $ % ^ & * ( ) _ + - = [ ] {} | '"
}

variable "iam_password_policy_require_uppercase_characters" {
  type        = string
  description = "You can require that IAM user passwords contain at least one uppercase character from the ISO basic Latin alphabet (A to Z)."
}

########################################################################
# Macie Configurations
########################################################################
variable "macie_finding_publishing_frequency" {
  type        = string
  description = "Macie finding publishing frequency"
}

variable "disable_macie" {
  type        = string
  description = "Update to 'true' to disable Macie in all accounts and regions before deleting the TF."
}

variable "create_macie_job" {
  description = "Indicates whether to create a Macie classification job with a daily schedule."
  type        = string
  default     = "true"
}

variable "macie_job_name" {
  description = "A custom name for the job."
  type        = string
  default     = "sra-macie-classification-job"
}

variable "macie_excludes_tag_key" {
  description = "A key for a tag-based condition that determines which buckets to exclude from the job. To exclude the bucket set the value of this tag to 'True'."
  type        = string
  default     = "sra-exclude-from-default-job"
}

########################################################################
# CloudTrail Configurations
########################################################################

variable "enable_data_events_only" {
  description = "Only Enable Cloud Trail Data Events"
  type        = string
}

variable "enable_lambda_data_events" {
  description = "Enable Cloud Trail Data Events for all Lambda functions"
  type        = string
}

variable "enable_s3_data_events" {
  description = "Enable Cloud Trail S3 Data Events for all buckets"
  type        = string
}

variable "disable_cloudtrail" {
  description = "set to TRUE before disabling the entire solution to remove its configuration before destroying resources"
  type        = bool
  default     = false
}
