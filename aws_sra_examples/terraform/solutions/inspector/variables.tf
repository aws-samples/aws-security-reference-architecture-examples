########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "organization_id" {
  description = "AWS Organizations ID"
  type        = string
}

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

variable "sra_solution_name" {
  type        = string
  description = "The SRA solution name. The default value is the folder name of the solution."
  default     = "sra-inspector-org"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.sra_solution_name))
    error_message = "Invalid SRA solution name. It must contain only lowercase alphanumeric characters and dashes."
  }
}

variable "inspector_org_lambda_function_name" {
  description = "Lambda function name"
  type        = string
  default     = "sra-inspector-org"
}

variable "inspector_org_lambda_role_name" {
  description = "Inspector configuration Lambda role name"
  type        = string
  default     = "sra-inspector-org-lambda"
}

variable "inspector_configuration_role_name" {
  description = "Inspector Configuration role to assume in the delegated administrator account"
  type        = string
  default     = "sra-inspector-configuration"
}

variable "inspector_control_tower_regions_only" {
  description = "Only enable in the Control Tower governed regions"
  type        = bool
  default     = true
}

variable "enabled_regions" {
  description = "(Optional) Enabled regions (AWS regions, separated by commas). Leave blank to enable all regions."
  type        = string
  default     = ""
}

variable "ecr_rescan_duration" {
  description = "ECR Rescan Duration"
  type        = string
}

variable "scan_components" {
  description = "Components to scan (e.g., 'ec2,ecs')"
  type        = string
}
