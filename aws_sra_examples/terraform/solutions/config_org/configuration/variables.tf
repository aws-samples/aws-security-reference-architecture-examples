########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "p_sra_solution_name" {
  description = "SRA Solution Name"
  type        = string
  default     = "sra-config-org"
}

variable "p_audit_account_id" {
  description = "AWS Account ID of the Audit (Security Tooling) account."
  type        = string
}

variable "p_log_archive_account_id" {
  description = "AWS Account ID of the Log Archive account."
  type        = string
}

variable "p_organization_id" {
  description = "AWS Organizations ID"
  type        = string
}

variable "p_home_region" {
  description = "Name of the home region"
  type        = string
}

variable "p_sra_alarm_email" {
  description = "(Optional) Email address for receiving DLQ alarms"
  type        = string
  default     = ""
}

variable "p_sra_staging_s3_bucket_name" {
  description = "SRA Staging S3 bucket name for the artifacts relevant to solution. (e.g., lambda zips, CloudFormation templates) S3 bucket name can include numbers, lowercase letters, uppercase letters, and hyphens (-). It cannot start or end with a hyphen (-)."
  type        = string
}

variable "p_kms_key_arn" {
  description = "Logging S3 bucket KMS Key ARN"
  type        = string
}

variable "p_recorder_name" {
  description = "Config delivery s3 bucket name"
  type        = string
}

variable "p_all_supported" {
  description = "Indicates whether to record all supported resource types. If set to 'false', then the 'Resource Types' parameter must have a value."
  type        = string
  default     = "true"
}

variable "p_include_global_resource_types" {
  description = "Indicates whether AWS Config records all supported global resource types."
  type        = string
  default     = "true"
}

variable "p_resource_types" {
  description = "(Optional) A list of valid AWS resource types to include in this recording group. Eg. AWS::CloudTrail::Trail. If 'All Supported' parameter is set to 'false', then this parameter becomes required."
  type        = string
  default     = ""
}

variable "p_frequency" {
  description = "The frequency with which AWS Config delivers configuration snapshots. (One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours)"
  type        = string
  default     = "One_Hour"
}

variable "p_config_org_delivery_bucket_prefix" {
  description = "Config Delivery S3 bucket prefix. The account and region will get added to the end. e.g. sra-config-delivery-123456789012-us-east-1"
  type        = string
  default     = "sra-config-org-delivery"
}

variable "p_publishing_destination_bucket_name" {
  description = "Config S3 bucket name"
  type        = string
}

variable "p_delivery_s3_key_prefix" {
  description = "Organization ID to use as the S3 Key prefix for storing the audit logs"
  type        = string
}

variable "p_delivery_channel_name" {
  description = "Config delivery channel name"
  type        = string
  default     = "sra-config-s3-delivery"
}

variable "p_config_topic_name" {
  description = "Configuration Notification SNS Topic in Audit Account that AWS Config delivers notifications to."
  type        = string
  default     = "sra-ConfigNotifications"
}

variable "p_kms_key_arn_secret_name" {
  description = "Secrets Manager secret name"
  type        = string
  default     = "sra/config_org_delivery_key_arn"
}

variable "p_config_org_lambda_role_name" {
  description = "Config configuration Lambda role name"
  type        = string
  default     = "sra-config-org-lambda"
}

variable "p_config_org_lambda_function_name" {
  description = "Lambda function name"
  type        = string
  default     = "sra-config-org"
}

variable "p_config_configuration_role_name" {
  description = "Config Configuration role to assume"
  type        = string
  default     = "sra-config-configuration"
}

variable "p_control_tower_regions_only" {
  description = "Only enable in the Control Tower governed regions"
  type        = string
  default     = "true"
}

variable "p_enabled_regions" {
  description = "(Optional) Enabled regions (AWS regions, separated by commas). Leave blank to enable all regions."
  type        = string
  default     = ""
}

variable "p_create_lambda_log_group" {
  description = "Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function, to allow for setting a Log Retention and/or KMS Key for encryption."
  type        = string
  default     = "false"
}

variable "p_lambda_log_group_retention" {
  description = "Specifies the number of days you want to retain log events"
  type        = string
  default     = 14
}

variable "p_lambda_log_group_kms_key" {
  description = "(Optional) KMS Key ARN to use for encrypting the Lambda logs data. If empty, encryption is enabled with CloudWatch Logs managing the server-side encryption keys."
  type        = string
  default     = ""
}

variable "p_lambda_log_level" {
  description = "Lambda Function Logging Level"
  type        = string
  default     = "INFO"
}

variable "p_compliance_frequency" {
  description = "Frequency (in days between 1 and 30, default is 7) to check organizational compliance"
  type        = number
  default     = 7
}

variable "p_control_tower_life_cycle_rule_name" {
  description = "The name of the AWS Control Tower Life Cycle Rule."
  type        = string
  default     = "sra-config-org-trigger"
}

variable "p_event_rule_role_name" {
  description = "Event rule role name for putting events on the home region event bus"
  type        = string
  default     = "sra-config-global-events"
}
