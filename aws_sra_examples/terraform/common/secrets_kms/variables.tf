########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "management_account_id" {
  description = "Organization Management Account ID"
  type        = string
}

variable "organization_id" {
  description = "AWS Organizations ID"
  type        = string
}

variable "sra_secrets_key_alias" {
  description = "The SRA secrets KMS key alias."
  type        = string
  default     = "sra-secrets-key"
}

variable "sra_secrets_prefix" {
  description = "Prefix used for SRA secrets"
  type        = string
  default     = "sra"
}