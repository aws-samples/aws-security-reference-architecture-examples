########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "guardduty_org_configuration_role_name" {
  description = "GuardDuty Configuration IAM Role Name"
  type        = string
  default     = "sra-guardduty-org-configuration"
}

variable "management_account_id" {
  description = "Organization Management Account ID"
  type        = string
}

variable "guardduty_org_lambda_role_name" {
  description = "Lambda Role Name"
  type        = string
  default     = "sra-guardduty-org-lambda"
}

variable "sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution"
  type        = string
  default     = "sra-guardduty-org"
}