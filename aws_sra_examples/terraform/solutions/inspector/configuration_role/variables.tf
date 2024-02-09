########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "management_account_id" {
  type        = string
  description = "Organization Management Account ID"
}

variable "inspector_org_lambda_role_name" {
  type        = string
  description = "Inspector Configuration IAM Role Name"
}

variable "inspector_configuration_role_name" {
  type        = string
  description = "Inspector Configuration IAM Role Name"
  default     = "sra-inspector-configuration"
}

variable "management_account_role_name" {
  type        = string
  description = "Management Account IAM Role Name"
  default     = "sra-management-account"
}

variable "sra_solution_name" {
  type        = string
  description = "The SRA solution name. The default value is the folder name of the solution"
  default     = "sra-inspector-org"
}