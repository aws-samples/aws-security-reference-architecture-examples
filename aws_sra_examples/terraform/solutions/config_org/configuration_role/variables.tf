########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "p_sra_solution_name" {
  description = "SRA Solution Name"
  type        = string
  default     = "sra-config-org"
}

variable "p_config_configuration_role_name" {
  type        = string
  description = "Config Configuration IAM Role Name"
  default     = "sra-config-configuration"
}

variable "p_config_org_lambda_role_name" {
  type        = string
  description = "Lambda Role Name"
  default     = "sra-config-org-lambda"
}

variable "p_management_account_id" {
  type        = string
  description = "Organization Management Account ID"
}

variable "p_sra_solution_tag_key" {
  type        = string
  description = "The SRA solution tag key applied to all resources created by the solution that support tagging."
  default     = "sra-solution"
}

variable "p_audit_account_id" {
  type        = string
  description = "AWS Account ID of the Audit account."
}

variable "p_home_region" {
  type        = string
  description = "Name of the home region"
}

variable "p_kms_key_arn_secret_name" {
  type        = string
  description = "Secrets Manager secret name"
  default     = "sra/config_org_delivery_key_arn"
}