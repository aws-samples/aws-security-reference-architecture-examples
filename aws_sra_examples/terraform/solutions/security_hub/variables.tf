########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "management_account_id" {
  description = "Organization Management Account ID"
  type        = string
}

variable "home_region" {
  description = "Name of the Control Tower home region"
  type        = string
}

variable "audit_account_id" {
  description = "AWS Account ID of the Control Tower Audit account."
  type        = string
}

variable "log_archive_account_id" {
  description = "AWS Account ID of the Control Tower Log Archive account."
  type        = string
}

variable "sra_solution_name" {
  type        = string
  description = "The SRA solution name. The default value is the folder name of the solution."
  default     = "sra-securityhub-org"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.sra_solution_name))
    error_message = "Invalid SRA solution name. It must contain only lowercase alphanumeric characters and dashes."
  }
}

variable "cis_standard_version" {
  description = "CIS Standard Version"
  type        = string
  default     = "1.4.0"
}

variable "compliance_frequency" {
  description = "Frequency to Check for Organizational Compliance (in days between 1 and 30, default is 7)"
  type        = number
  default     = 7
}

variable "control_tower_lifecycle_rule_name" {
  description = "The name of the AWS Control Tower Life Cycle Rule"
  type        = string
  default     = "sra-securityhub-org-trigger"
}

variable "securityhub_control_tower_regions_only" {
  description = "Only enable in the Control Tower governed regions"
  type        = bool
  default     = true
}

variable "create_lambda_log_group" {
  description = "Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function"
  type        = bool
  default     = false
}

variable "delegated_admin_account_id" {
  description = "Delegated administrator account ID"
  type        = string
}

variable "disable_security_hub" {
  description = "Update to 'true' to disable Security Hub in all accounts and regions before deleting the stack"
  type        = bool
  default     = false
}

variable "enabled_regions" {
  description = "(Optional) Enabled regions (AWS regions, separated by commas). Leave blank to enable all regions."
  type        = string
}

variable "enable_cis_standard" {
  description = "Indicates whether to enable the CIS AWS Foundations Benchmark Standard"
  type        = bool
  default     = false
}

variable "enable_pci_standard" {
  description = "Indicates whether to enable the Payment Card Industry Data Security Standard (PCI DSS)"
  type        = bool
  default     = false
}

variable "enable_nist_standard" {
  description = "Indicates whether to enable the National Institute of Standards and Technology (NIST) SP 800-53 Rev. 5"
  type        = bool
  default     = false
}

variable "enable_security_best_practices_standard" {
  description = "Indicates whether to enable the AWS Foundational Security Best Practices Standard"
  type        = bool
  default     = true
}

variable "event_rule_role_name" {
  description = "Event rule role name for putting events on the home region event bus"
  type        = string
  default     = "sra-security-hub-global-events"
}

variable "pci_standard_version" {
  description = "PCI Standard Version"
  type        = string
  default     = "3.2.1"
}

variable "nist_standard_version" {
  description = "NIST Standard Version"
  type        = string
  default     = "5.0.0"
}

variable "security_best_practices_standard_version" {
  description = "SBP Standard Version"
  type        = string
  default     = "1.0.0"
}

variable "security_hub_org_lambda_function_name" {
  description = "Lambda function name"
  type        = string
  default     = "sra-securityhub-org"
}

variable "security_hub_org_lambda_role_name" {
  description = "SecurityHub configuration Lambda role name"
  type        = string
  default     = "sra-securityhub-org-lambda"
}

variable "security_hub_configuration_role_name" {
  description = "SecurityHub Configuration role to assume in the delegated administrator account"
  type        = string
  default     = "sra-securityhub-configuration"
}

variable "lambda_log_group_kms_key" {
  description = "(Optional) KMS Key ARN to use for encrypting the Lambda logs data"
  type        = string
  default     = ""
}

variable "lambda_log_group_retention" {
  description = "Specifies the number of days you want to retain log events"
  type        = number
  default     = 14
}

variable "lambda_log_level" {
  description = "Lambda Function Logging Level"
  type        = string
  default     = "INFO"
}

variable "organization_id" {
  description = "AWS Organizations ID"
  type        = string
}

variable "region_linking_mode" {
  description = "Indicates whether to aggregate findings from all of the available Regions in the current partition"
  type        = string
  default     = "SPECIFIED_REGIONS"
}

variable "sra_alarm_email" {
  description = "(Optional) Email address for receiving DLQ alarms"
  type        = string
  default     = ""
}

variable "sechub_rule_name" {
  description = "Eventbridge rule name"
  type        = string
  default     = "sra-config-recorder"
}
