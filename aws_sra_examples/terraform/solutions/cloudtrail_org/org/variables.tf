########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "cloudtrail_log_group_kms_key" {
  description = "(Optional) KMS Key ARN to use for encrypting the CloudTrail log group data. If empty, encryption is enabled with CloudWatch Logs managing the server-side encryption keys."
  type        = string
  default     = ""
}

variable "cloudtrail_log_group_retention" {
  description = "Specifies the number of days you want to retain log events"
  type        = string
  default     = "400"
}

variable "cloudtrail_name" {
  description = "CloudTrail name"
  type        = string
  default     = "sra-org-trail"
}

variable "cloudtrail_lambda_function_name" {
  description = "Lambda function name for creating and updating the CloudTrail"
  type        = string
  default     = "sra-cloudtrail-org"
}

variable "cloudtrail_lambda_role_name" {
  description = "Lambda role name for creating and updating the CloudTrail"
  type        = string
  default     = "sra-cloudtrail-org-lambda"
}

variable "cloudtrail_s3_bucket_name" {
  description = "CloudTrail S3 Bucket Name"
  type        = string
}

variable "create_cloudtrail_log_group" {
  description = "Indicates whether a CloudWatch Log Group should be created for the CloudTrail"
  type        = string
  default     = "true"
}

variable "create_lambda_log_group" {
  description = "Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function"
  type        = string
  default     = "false"
}

variable "delegated_admin_account_id" {
  description = "Delegated administrator account ID"
  type        = string
}

variable "enable_data_events_only" {
  description = "Only Enable Cloud Trail Data Events"
  type        = string
  default     = "true"
}

variable "enable_lambda_data_events" {
  description = "Enable Cloud Trail Data Events for all Lambda functions"
  type        = string
  default     = "true"
}

variable "enable_s3_data_events" {
  description = "Enable Cloud Trail S3 Data Events for all buckets"
  type        = string
  default     = "true"
}

variable "lambda_log_group_kms_key" {
  description = "(Optional) KMS Key ARN to use for encrypting the Lambda logs data. If empty, encryption is enabled with CloudWatch Logs managing the server-side encryption keys."
  type        = string
  default     = ""
}

variable "lambda_log_group_retention" {
  description = "Specifies the number of days you want to retain log events"
  type        = string
  default     = "14"
}

variable "lambda_log_level" {
  description = "Lambda Function Logging Level"
  type        = string
  default     = "INFO"
}

variable "organization_cloudtrail_kms_key_id" {
  description = "KMS Key ARN to use for encrypting the CloudTrail logs"
  type        = string
}

variable "sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution"
  type        = string
  default     = "sra-cloudtrail-org"
}