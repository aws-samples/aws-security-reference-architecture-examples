########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "log_archive_account_id" {
  description = "Log Archive Account ID"
  type        = string
}

variable "macie_delivery_key_alias" {
  description = "Macie Delivery KMS Key Alias"
  type        = string
  default     = "sra-macie-org-delivery-key"
}

variable "management_account_id" {
  description = "Organization Management Account ID"
  type        = string
}

variable "secrets_key_alias_arn" {
  description = "(Optional) SRA Secrets Manager KMS Key Alias ARN"
  type        = string
}

variable "solution_name" {
  description = "SRA Solution Name"
  type        = string
  default     = "sra-macie-org"
}