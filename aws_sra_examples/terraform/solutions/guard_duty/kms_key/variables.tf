########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "guardduty_org_delivery_key_alias" {
  description = "GuardDuty Delivery KMS Key Alias"
  type        = string
  default     = "sra-guardduty-org-delivery-key"
}

variable "log_archive_account_id" {
  description = "AWS Account ID of the Control Tower Log Archive account."
  type        = string
}

variable "management_account_id" {
  description = "Management Account ID"
  type        = string
}

variable "sra_secrets_key_alias_arn" {
  description = "(Optional) SRA Secrets Manager KMS Key Alias ARN"
  type        = string
  default     = ""
}

variable "sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution"
  type        = string
  default     = "sra-guardduty-org"
}

variable "create_secret" {
  description = "Whether to create the GuardDuty Delivery Key Secret"
  type        = bool
  default     = false
}
