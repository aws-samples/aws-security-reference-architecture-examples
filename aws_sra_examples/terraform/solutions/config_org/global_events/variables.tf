########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "p_event_rule_role_name" {
  type        = string
  description = "Event rule role name for putting events on the home region event bus"
  default     = "sra-config-global-events"
}

variable "p_home_region" {
  type        = string
  description = "Name of the Control Tower home region"
  default     = "us-east-1"
}

variable "p_sra_solution_name" {
  type        = string
  description = "The SRA solution name. The default value is the folder name of the solution."
  default     = "sra-config-org"
}