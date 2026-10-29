########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "p_aggregator_name" {
  type        = string
  description = "Config Aggregator Name"
  default     = "sra-config-aggregator-org"
}

variable "p_aggregator_role_name" {
  type        = string
  description = "Config Aggregator Role Name"
  default     = "sra-config-aggregator-org"
}

variable "p_sra_solution_name" {
  type        = string
  description = "The SRA solution name. The default value is the folder name of the solution"
  default     = "sra-config-aggregator-org"
}

variable "p_sra_solution_name_key" {
  type        = string
  description = "The key used for tagging resources with the SRA solution name."
  default     = "sra-solution"
}