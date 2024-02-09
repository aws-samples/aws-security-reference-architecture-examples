########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "create_lambda_log_group" {
  description = "Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function"
  type        = string
  default     = "false"
}

variable "delegated_admin_account_id" {
  description = "Delegated Admin Account ID"
  type        = string
}

variable "lambda_log_group_kms_key" {
  description = "(Optional) Lambda Logs KMS Key"
  type        = string
  default     = ""
}

variable "lambda_log_group_retention" {
  description = "Lambda Log Group Retention"
  type        = string
  default     = "14"
}

variable "lambda_log_level" {
  description = "Lambda Log Level"
  type        = string
  default     = "INFO"
}

variable "register_delegated_admin_lambda_role_name" {
  description = "Register Delegated Admin - Lambda Role Name"
  type        = string
  default     = "sra-common-register-delegated-admin-lambda"
}

variable "register_delegated_admin_lambda_function_name" {
  description = "Register Delegated Admin - Lambda Function Name"
  type        = string
  default     = "sra-common-register-delegated-admin"
}

variable "service_principal_list" {
  description = "Comma delimited list of AWS service principals to delegate an administrator account"
  type        = list(string)
  default     = ["access-analyzer.amazonaws.com", "config-multiaccountsetup.amazonaws.com", "config.amazonaws.com"]
}

variable "sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution"
  type        = string
  default     = "sra-common-register-delegated-administrator"
}