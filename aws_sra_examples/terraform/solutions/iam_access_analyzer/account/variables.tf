########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "access_analyzer_name_prefix" {
  type        = string
  default     = "sra-account-access-analyzer"
  description = "Access Analyzer Name Prefix. The Account ID will be appended to the name."
}

variable "sra_solution_name" {
  type        = string
  default     = "sra-iam-access-analyzer"
  description = "The SRA solution name. The default value is the folder name of the solution"
}