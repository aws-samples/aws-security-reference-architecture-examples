########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "audit_account_id" {
  description = "AWS Account ID of the Control Tower Audit account."
  type        = string
}

variable "disable_guard_duty" {
  description = "Update to 'true' to disable GuardDuty in all accounts and regions before deleting the TF."
  type        = string
}

variable "finding_publishing_frequency" {
  description = "Finding publishing frequency [FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS]"
  type        = string
  default     = "FIFTEEN_MINUTES"
}

variable "auto_enable_s3_logs" {
  description = "Auto enable S3 logs"
  type        = string
  default     = "true"
}

variable "publishing_destination_bucket_arn" {
  description = "ARN of S3 bucket for Guard Duty"
  type        = string
}

variable "guardduty_control_tower_regions_only" {
  description = "Only enable in the Control Tower governed regions"
  type        = string
  default     = "true"
}

variable "enabled_regions" {
  description = "(Optional) Enabled regions (AWS regions, separated by commas). Leave blank to enable all regions."
  type        = string
  default     = ""
}

variable "delete_detector_role_name" {
  description = "Delete Detector IAM Role Name"
  type        = string
}

variable "guardduty_org_configuration_role_name" {
  description = "GuardDuty Configuration IAM Role Name"
  type        = string
}

variable "guardduty_org_delivery_kms_key_arn" {
  description = "GuardDuty Delivery KMS Key ARN"
  type        = string
}

variable "lambda_log_level" {
  description = "Lambda Function Logging Level."
  type        = string
  default     = "INFO"
}

variable "create_lambda_log_group" {
  description = "Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function"
  type        = bool
  default     = false
}

variable "guardduty_lambda_function_name" {
  description = "Lambda function name"
  type        = string
  default     = "sra-guardduty-org"
}

variable "guardduty_lambda_role_name" {
  description = "GuardDuty configuration Lambda role name"
  type        = string
  default     = "sra-guardduty-org-lambda"
}

variable "lambda_log_group_retention" {
  description = "Specifies the number of days you want to retain log events"
  type        = number
  default     = 14
}

variable "lambda_log_group_kms_key" {
  description = "(Optional) KMS Key ARN to use for encrypting the Lambda logs data"
  type        = string
  default     = ""
}

variable "sra_alarm_email" {
  description = "(Optional) SRA Alarm Email"
  type        = string
  default     = ""
}

variable "sra_solution_name" {
  description = "The SRA solution name"
  type        = string
  default     = "sra-guardduty-org"
}

variable "organization_id" {
  description = "AWS Organization ID"
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
