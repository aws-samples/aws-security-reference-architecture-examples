########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "p_sra_solution_name" {
  description = "SRA Solution Name"
  type        = string
  default     = "sra-config-org"
}

variable "p_config_org_sns_key_alias" {
  default     = "sra-config-org-sns-key"
  description = "Config SNS KMS Key Alias"
  type        = string
}

variable "p_sra_solution_name" {
  default     = "sra-config-org"
  description = "The SRA solution name. The default value is the folder name of the solution"
  type        = string
}