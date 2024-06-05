########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "p_sra_solution_name" {
  description = "SRA Solution Name"
  type        = string
  default     = "sra-config-org"
}

variable "p_config_org_sns_key_alias" {
  description = "Config SNS KMS Key Alias"
  type        = string
  default     = "sra-config-org-sns-key"
}

variable "p_sra_alarm_email" {
  description = "(Optional) SRA Alarm Email"
  type        = string
  default     = ""
}

variable "p_sra_solution_name" {
  description = "SRA Solution Name"
  type        = string
  default     = "sra-config-org"
}

variable "p_sra_solution_version" {
  description = "SRA Solution Version"
  type        = string
  default     = "v1.0"
}

variable "p_sra_staging_s3_bucket_name" {
  description = "SRA Staging S3 Bucket Name"
  type        = string
  default     = "/sra/staging-s3-bucket-name"
}

variable "p_management_account_id" {
  description = "Management Account ID"
  type        = string
}

variable "p_audit_account_id" {
  description = "Audit Account ID"
  type        = string
}

variable "p_log_archive_account_id" {
  description = "Log Archive Account ID"
  type        = string
}

variable "p_organization_id" {
  description = "Organization ID"
  type        = string
}

variable "p_root_organizational_unit_id" {
  description = "Root Organizational Unit ID"
  type        = string
}

variable "p_home_region" {
  description = "Home Region"
  type        = string
}

variable "p_customer_control_tower_regions" {
  description = "Customer Regions"
  type        = string
  default     = "/sra/regions/customer-control-tower-regions"
}

variable "p_stack_set_admin_role" {
  description = "Stack Set Role"
  type        = string
  default     = "sra-stackset"
}

variable "p_stack_execution_role" {
  description = "Stack execution role"
  type        = string
  default     = "sra-execution"
}

variable "p_control_tower_regions_only" {
  description = "Common Prerequisites Regions Only"
  type        = bool
  default     = true
}

variable "p_enabled_regions" {
  description = "(Optional) Enabled Regions"
  type        = string
  default     = ""
}

variable "p_recorder_name" {
  description = "Recorder Name"
  type        = string
  default     = "sra-ConfigRecorder"
}

variable "p_all_supported" {
  description = "All Supported"
  type        = bool
  default     = true
}

variable "p_include_global_resource_types" {
  description = "Include Global Resource Types"
  type        = bool
  default     = true
}

variable "p_resource_types" {
  description = "(Optional) Resource Types"
  type        = string
  default     = ""
}

variable "p_delivery_channel_name" {
  description = "Delivery Channel Name"
  type        = string
  default     = "sra-config-s3-delivery"
}

variable "p_config_org_delivery_bucket_prefix" {
  description = "Config Delivery Bucket Prefix"
  type        = string
  default     = "sra-config-org-delivery"
}

variable "p_delivery_s3_key_prefix" {
  description = "Delivery S3 Key Prefix"
  type        = string
  default     = "/sra/control-tower/organization-id"
}

variable "p_config_org_delivery_key_alias" {
  description = "Config Delivery KMS Key Alias"
  type        = string
  default     = "sra-config-org-delivery-key"
}

variable "p_frequency" {
  description = "Frequency"
  type        = string
  default     = "1hour"
}

variable "p_kms_key_arn_secret_name" {
  description = "KMS Key Arn Secret Name"
  type        = string
  default     = "sra/config_org_delivery_key_arn"
}

variable "p_config_topic_name" {
  description = "Config SNS Topic Name"
  type        = string
  default     = "sra-ConfigNotifications"
}

variable "p_subscribe_to_configuration_topic" {
  description = "Subscribe to Configuration Topic"
  type        = bool
  default     = false
}

variable "p_configuration_email" {
  description = "Configuration Email"
  type        = string
  default     = ""
}

variable "p_aggregator_name" {
  description = "Config Aggregator Name"
  type        = string
  default     = "sra-config-aggregator-org"
}

variable "p_aggregator_role_name" {
  description = "Config Aggregator Role Name"
  type        = string
  default     = "sra-config-aggregator-org"
}

variable "p_register_delegated_admin_account" {
  description = "Register Delegated Admin Account"
  type        = bool
  default     = true
}

variable "p_create_lambda_log_group" {
  description = "Create Lambda Log Group"
  type        = bool
  default     = false
}

variable "p_lambda_log_group_retention" {
  description = "Lambda Log Group Retention"
  type        = number
  default     = 14
}

variable "p_lambda_log_group_kms_key" {
  description = "(Optional) Lambda Logs KMS Key"
  type        = string
  default     = ""
}

variable "p_lambda_log_level" {
  description = "Lambda Log Level"
  type        = string
  default     = "INFO"
}

variable "p_compliance_frequency" {
  description = "Frequency to Check for Organizational Compliance"
  type        = number
  default     = 7
}

variable "p_control_tower_life_cycle_rule_name" {
  description = "Lifecycle Rule Name"
  type        = string
  default     = "sra-config-org-trigger"
}