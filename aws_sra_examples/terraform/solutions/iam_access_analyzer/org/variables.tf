########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "org_access_analyzer_name" {
  description = "Organization Access Analyzer Name"
  type        = string
  default     = "sra-organization-access-analyzer"
}

variable "sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution"
  type        = string
  default     = "sra-iam-access-analyzer"
}