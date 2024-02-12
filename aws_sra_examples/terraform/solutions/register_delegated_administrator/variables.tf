########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "register_delegated_admin_lambda_role_name" {
  description = "Register Delegated Admin - Lambda Role Name"
  type        = string
  default     = "sra-common-register-delegated-admin-lambda"
}

variable "delegated_admin_account_id" {
  description = "Delegated Admin Account ID"
  type        = string
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