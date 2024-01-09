########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "management_account_id" {
  description = "Management Account ID"
  type        = string
}

variable "log_archive_account_id" {
  description = "Log Archive Account ID"
  type        = string
}

variable "org_cloudtrail_key_alias" {
  description = "SRA Organization CloudTrail KMS Key Alias"
  type        = string
  default     = "sra-cloudtrail-org-key"
}

variable "secrets_key_alias_arn" {
  description = "(Optional) SRA Secrets Manager KMS Key Alias ARN"
  type        = string
}

variable "sra_solution_name" {
  description = "The SRA solution name."
  type        = string
  default     = "sra-cloudtrail-org"
}