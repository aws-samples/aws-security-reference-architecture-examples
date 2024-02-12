########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "delegated_admin_account_id" {
  description = "Delegated administrator account ID"
  type        = string
  validation {
    condition     = length(var.delegated_admin_account_id) == 12 && can(regex("^\\d{12}$", var.delegated_admin_account_id))
    error_message = "Must be 12 digits"
  }
}

variable "management_account_id" {
  description = "Organization Management Account ID"
  type        = string
  validation {
    condition     = length(var.management_account_id) == 12 && can(regex("^\\d{12}$", var.management_account_id))
    error_message = "Must be 12 digits"
  }
}

variable "securityhub_org_lambda_role_name" {
  description = "Lambda Role Name"
  type        = string
  validation {
    condition     = can(regex("^[\\w+=,.@-]{1,64}$", var.securityhub_org_lambda_role_name))
    error_message = "Max 64 alphanumeric characters. Also special characters supported [+, =, ., @, -]"
  }
  default = "sra-securityhub-org-lambda"
}

variable "securityhub_configuration_role_name" {
  description = "SecurityHub Configuration IAM Role Name"
  type        = string
  validation {
    condition     = can(regex("^[\\w+=,.@-]{1,64}$", var.securityhub_configuration_role_name))
    error_message = "Max 64 alphanumeric characters. Also special characters supported [+, =, ., @, -]"
  }
  default = "sra-securityhub-configuration"
}

variable "sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution"
  type        = string
}