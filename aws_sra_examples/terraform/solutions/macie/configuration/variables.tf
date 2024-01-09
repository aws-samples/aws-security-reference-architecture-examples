########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "p_control_tower_regions_only" {
  description = "Only enable in the Control Tower governed regions"
  type        = string
  default     = "true"
}

variable "p_create_lambda_log_group" {
  description = "Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function, to allow for setting a Log Retention and/or KMS Key for encryption."
  type        = string
  default     = "false"
}

variable "p_management_account_id" {
  description = "Management account ID"
  type        = string
}

variable "p_delegated_admin_account_id" {
  description = "Delegated administrator account ID"
  type        = string
}

variable "p_disable_macie" {
  description = "Update to 'true' to disable Macie in all accounts and regions before deleting the stack."
  type        = string
  default     = "false"
}

variable "p_disable_macie_role_name" {
  description = "Role to assume in each account to disable Macie"
  type        = string
  default     = "sra-macie-org-disable"
}

variable "p_enabled_regions" {
  description = "Enabled regions (AWS regions, separated by commas). Leave blank to enable all regions."
  type        = string
  default     = ""
}

variable "p_finding_publishing_frequency" {
  description = "Specifies how often to publish updates to policy findings for the account."
  type        = string
  default     = "FIFTEEN_MINUTES"
}

variable "p_kms_key_arn" {
  description = "Logging S3 bucket KMS Key ARN"
  type        = string
}

variable "p_lambda_log_group_kms_key" {
  description = "(Optional) KMS Key ARN to use for encrypting the Lambda logs data. If empty, encryption is enabled with CloudWatch Logs managing the server-side encryption keys."
  type        = string
  default     = ""
}

variable "p_lambda_log_group_retention" {
  description = "Specifies the number of days you want to retain log events"
  type        = string
  default     = 14
}

variable "p_lambda_log_level" {
  description = "Lambda Function Logging Level"
  type        = string
  default     = "INFO"
}

variable "p_macie_org_configuration_role_name" {
  description = "Macie Configuration role to assume in the delegated administrator account"
  type        = string
  default     = "sra-macie-org-configuration"
}

variable "p_macie_org_lambda_function_name" {
  description = "Lambda function name"
  type        = string
  default     = "sra-macie-org"
}

variable "p_macie_org_lambda_role_name" {
  description = "Macie configuration Lambda role name"
  type        = string
  default     = "sra-macie-org-lambda"
}

variable "p_organization_id" {
  description = "AWS Organizations ID"
  type        = string
}

variable "p_publishing_destination_bucket_name" {
  description = "Macie classification export S3 bucket name"
  type        = string
}

variable "p_sra_alarm_email" {
  description = "(Optional) Email address for receiving DLQ alarms"
  type        = string
  default     = ""
}

variable "p_sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution"
  type        = string
  default     = "sra-macie-org"
}