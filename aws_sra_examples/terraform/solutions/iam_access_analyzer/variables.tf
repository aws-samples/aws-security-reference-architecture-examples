########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "account_id" {
  description = "Current Account ID"
  type        = string
}

variable "access_analyzer_name_prefix" {
  type        = string
  default     = "sra-account-access-analyzer"
  description = "Access Analyzer Name Prefix. The Account ID will be appended to the name."
}

variable "org_access_analyzer_name" {
  description = "Organization Access Analyzer Name"
  type        = string
  default     = "sra-organization-access-analyzer"
}

variable "sra_solution_name" {
  type        = string
  default     = "sra-iam-access-analyzer"
  description = "The SRA solution name. The default value is the folder name of the solution"
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