########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "control_tower" {
  description = "AWS Control Tower landing zone deployed/in-use"
  default     = "true"
}

variable "governed_regions" {
  description = "AWS regions (comma separated) if not using AWS Control Tower (leave set to ct-regions for AWS Control Tower environments)"
  default     = "ct-regions"
}

variable "security_account_id" {
  description = "Security Tooling Account ID"
  default     = 111111111111
}

variable "log_archive_account_id" {
  description = "Log Archive Account ID"
  default     = 222222222222
}

variable "create_lambda_log_group" {
  description = "Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function, to allow for setting a Log Retention and/or KMS Key for encryption."
  type        = string
  default     = "false"
}

variable "lambda_log_group_kms_key" {
  description = "(Optional) KMS Key ARN to use for encrypting the Lambda logs data. If empty, encryption is enabled with CloudWatch Logs managing the server-side encryption keys."
  type        = string
  default     = ""
}

variable "lambda_log_group_retention" {
  description = "Specifies the number of days you want to retain log events."
  type        = string
  default     = "14"
}

variable "lambda_log_level" {
  description = "Lambda Function Logging Level."
  type        = string
  default     = "INFO"
}

variable "management_account_parameters_lambda_function_name" {
  description = "Lambda function name for creating Control Tower account SSM parameters."
  type        = string
  default     = "sra-management-account-parameters"
}

variable "management_account_parameters_lambda_role_name" {
  description = "Lambda execution role for creating Control Tower account SSM parameters."
  type        = string
  default     = "sra-management-account-parameters-lambda"
}

variable "sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution."
  type        = string
  default     = "sra-common-prerequisites"
}

variable "sra_solution_tag_key" {
  description = "The SRA solution tag key applied to all resources created by the solution that support tagging. The value is the pSRASolutionName."
  type        = string
  default     = "sra-solution"
}

variable "sra_staging_s3_bucket_name" {
  description = "(Optional) SRA Staging S3 bucket name for the artifacts relevant to the solution. (e.g., lambda zips, CloudFormation templates). If empty, the SRA Staging S3 bucket name will be resolved from the SSM Parameter '/sra/staging-s3-bucket-name'."
  type        = string
  default     = ""
}