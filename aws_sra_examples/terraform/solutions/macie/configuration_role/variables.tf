########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "macie_org_configuration_role_name" {
  description = "Configuration IAM Role Name"
  type        = string
}

variable "macie_org_lambda_role_name" {
  description = "Lambda Role Name"
  type        = string
}

variable "audit_account_id" {
  description = "Audit Account ID"
  type        = string
}

variable "management_account_id" {
  description = "Organization Management Account ID"
  type        = string
}

variable "sra_solution_name" {
  description = "The SRA solution name"
  type        = string
  default     = "sra-macie-org"
}