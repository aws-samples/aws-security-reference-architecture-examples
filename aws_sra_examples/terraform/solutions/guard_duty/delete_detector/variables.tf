########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "delete_detector_role_name" {
  description = "Delete Detector IAM Role Name"
  type        = string
  default     = "sra-guardduty-delete-detector"
}

variable "guardduty_org_lambda_role_name" {
  description = "Lambda Role Name"
  type        = string
  default     = "sra-guardduty-org-lambda"
}

variable "management_account_id" {
  description = "Organization Management Account ID"
  type        = string
}

variable "sra_solution_name" {
  description = "The SRA solution name"
  type        = string
  default     = "sra-guardduty-org"
}
