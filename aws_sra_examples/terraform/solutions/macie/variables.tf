########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "management_account_id" {
  description = "Organization Management Account ID"
  type        = string
}

variable "home_region" {
  description = "Name of the Control Tower home region"
  type        = string
}

variable "audit_account_id" {
  description = "AWS Account ID of the Control Tower Audit account."
  type        = string
}

variable "log_archive_account_id" {
  description = "AWS Account ID of the Control Tower Log Archive account."
  type        = string
}

variable "macie_org_lambda_role_name" {
  description = "Lambda Role Name"
  type        = string
  default     = "sra-macie-org-lambda"
}

variable "macie_org_configuration_role_name" {
  description = "Configuration IAM Role Name"
  type        = string
  default     = "sra-macie-org-configuration"
}

variable "secrets_key_alias_arn" {
  description = "(Optional) SRA Secrets Manager KMS Key Alias ARN"
  type        = string
  default     = ""
}

variable "organization_id" {
  description = "AWS Organization ID"
  type        = string
}

variable "p_disable_macie" {
  description = "Disabled Macie SRA solution"
  type        = string
}

variable "macie_finding_publishing_frequency" {
  description = "Macie finding publishing frequency"
  type        = string
}
