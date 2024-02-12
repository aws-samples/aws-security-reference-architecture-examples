########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "disable_macie_role_name" {
  description = "Disable Macie IAM Role Name"
  type        = string
  default     = "sra-macie-org-disable"
}

variable "macie_org_lambda_role_name" {
  description = "Lambda Role Name"
  type        = string
  default     = "sra-macie-org-lambda"
}

variable "management_account_id" {
  description = "Management Account ID"
  type        = string
}

variable "sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution"
  type        = string
  default     = "sra-macie-org"
}
