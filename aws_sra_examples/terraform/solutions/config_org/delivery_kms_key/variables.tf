########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "p_config_org_delivery_key_alias" {
  type        = string
  description = "Config Delivery KMS Key Alias"
  default     = "sra-config-org-delivery-key"
}

variable "p_log_archive_account_id" {
  type        = string
  description = "AWS Account ID of the Log Archive account."
}

variable "p_management_account_id" {
  type        = string
  description = "Management Account ID"
}

variable "p_sras_secrets_key_alias_arn" {
  type        = string
  description = "(Optional) SRA Secrets Manager KMS Key Alias ARN"
}

variable "p_sra_solution_name" {
  type        = string
  description = "The SRA solution name. The default value is the folder name of the solution"
  default     = "sra-config-org"
}

variable "p_sra_solution_name_key" {
  type        = string
  description = "The key used for tagging resources with the SRA solution name."
  default     = "sra-solution"
}