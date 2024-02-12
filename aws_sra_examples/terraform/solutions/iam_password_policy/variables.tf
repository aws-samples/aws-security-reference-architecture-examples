########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "home_region" {
  description = "Name of the Control Tower home region"
  type        = string
}

variable "allow_users_to_change_password" {
  default     = "true"
  type        = string
  description = "You can permit all IAM users in your account to use the IAM console to change their own passwords."
}

variable "create_lambda_log_group" {
  default     = "false"
  type        = string
  description = "Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function, to allow for setting a Log Retention and/or KMS Key for encryption."
}

variable "hard_expiry" {
  default     = "false"
  type        = string
  description = "You can prevent IAM users from choosing a new password after their current password has expired."
}

variable "lambda_role_name" {
  default     = "sra-iam-password-policy-lambda"
  type        = string
  description = "Lambda role name"
}

variable "lambda_function_name" {
  default     = "sra-iam-password-policy"
  type        = string
  description = "Lambda function name"
}

variable "lambda_log_group_kms_key" {
  default     = ""
  type        = string
  description = "(Optional) KMS Key ARN to use for encrypting the Lambda logs data. If empty, encryption is enabled with CloudWatch Logs managing the server-side encryption keys."
}

variable "lambda_log_group_retention" {
  default     = "14"
  type        = string
  description = "Specifies the number of days you want to retain log events"
}

variable "lambda_log_level" {
  default     = "INFO"
  type        = string
  description = "Lambda Function Logging Level"
}

variable "max_password_age" {
  default     = 90
  type        = string
  description = "You can set IAM user passwords to be valid for only the specified number of days."
}

variable "minimum_password_length" {
  default     = 14
  type        = string
  description = "You can specify the minimum number of characters allowed in an IAM user password."
}

variable "password_reuse_prevention" {
  default     = 24
  type        = string
  description = "You can prevent IAM users from reusing a specified number of previous passwords."
}

variable "require_lowercase_characters" {
  default     = "true"
  type        = string
  description = "You can require that IAM user passwords contain at least one lowercase character from the ISO basic Latin alphabet (a to z)."
}

variable "require_numbers" {
  default     = "true"
  type        = string
  description = "You can require that IAM user passwords contain at least one numeric character (0 to 9)."
}

variable "require_symbols" {
  default     = "true"
  type        = string
  description = "You can require that IAM user passwords contain at least one of the following nonalphanumeric characters: ! @ # $ % ^ & * ( ) _ + - = [ ] {} | '"
}

variable "require_uppercase_characters" {
  default     = "true"
  type        = string
  description = "You can require that IAM user passwords contain at least one uppercase character from the ISO basic Latin alphabet (A to Z)."
}

variable "sra_solution_name" {
  default     = "sra-iam-password-policy"
  type        = string
  description = "The SRA solution name. The default value is the folder name of the solution"
}
