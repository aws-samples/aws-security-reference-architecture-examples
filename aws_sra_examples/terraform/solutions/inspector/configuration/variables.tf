########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "compliance_frequency" {
  description = "Frequency (in days between 1 and 30, default is 7) to check organizational compliance"
  type        = number
  default     = 7
}

variable "control_tower_lifecycle_rule_name" {
  description = "The name of the AWS Control Tower Life Cycle Rule."
  type        = string
  default     = "sra-inspector-org-trigger"
}

variable "control_tower_regions_only" {
  description = "Only enable in the Control Tower governed regions"
  type        = bool
}

variable "create_lambda_log_group" {
  description = "Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function."
  type        = bool
  default     = false
}

variable "delegated_admin_account_id" {
  description = "Delegated administrator account ID"
  type        = string
}

variable "enabled_regions" {
  description = "(Optional) Enabled regions (AWS regions, separated by commas). Leave blank to enable all regions."
  type        = string
}

variable "event_rule_role_name" {
  description = "Event rule role name for putting events on the home region event bus"
  type        = string
  default     = "sra-inspector-global-events"
}

variable "inspector_org_lambda_function_name" {
  description = "Lambda function name"
  type        = string
  default     = "sra-inspector-org"
}

variable "inspector_org_lambda_role_name" {
  description = "Inspector configuration Lambda role name"
  type        = string
}

variable "inspector_configuration_role_name" {
  description = "Inspector Configuration role to assume in the delegated administrator account"
  type        = string
}

variable "ecr_rescan_duration" {
  description = "ECR Rescan Duration"
  type        = string
  default     = "LIFETIME"
}

variable "lambda_log_group_kms_key" {
  description = "(Optional) KMS Key ARN to use for encrypting the Lambda logs data."
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

variable "sra_alarm_email" {
  description = "(Optional) Email address for receiving DLQ alarms"
  type        = string
  default     = ""
}

variable "sra_solution_name" {
  description = "Solution name (e.g., 'security-reference-architecture')"
  type        = string
}

variable "scan_components" {
  description = "Components to scan (e.g., 'ec2,ecs')"
  type        = string
  default     = "ec2"
}

variable "create_dlq_alarm" {
  description = "Create a DLQ alarm for the SRA DLQ."
  type        = bool
  default     = false
}

variable "compliance_frequency_single_day" {
  description = "Set to true if the compliance frequency is set to 1 day."
  type        = bool
  default     = false
}

variable "not_global_region_us_east_1" {
  description = "Set to true if the region is not global (us-east-1)."
  type        = bool
  default     = false
}

variable "use_kms_key" {
  description = "Set to true if a KMS key should be used for encrypting Lambda logs."
  type        = bool
  default     = false
}