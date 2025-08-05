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

variable "disable_macie" {
  description = "Disabled Macie SRA solution"
  type        = string
}

variable "macie_finding_publishing_frequency" {
  description = "Macie finding publishing frequency"
  type        = string
}

variable "create_macie_job" {
  description = "Indicates whether to create a Macie classification job with a daily schedule."
  type        = string
  default     = "true"
}

variable "macie_job_name" {
  description = "A custom name for the job."
  type        = string
  default     = "sra-macie-classification-job"
}

variable "macie_excludes_tag_key" {
  description = "A key for a tag-based condition that determines which buckets to exclude from the job. To exclude the bucket set the value of this tag to 'True'."
  type        = string
  default     = "sra-exclude-from-default-job"
}