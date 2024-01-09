########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "event_rule_role_name" {
  description = "Event rule role name for putting events on the home region event bus"
  type        = string
  default     = "sra-securityhub-config-recorder-start"
  validation {
    condition     = can(regex("^[\\w+=,.@-]{1,64}$", var.event_rule_role_name))
    error_message = "Max 64 alphanumeric characters. Also special characters supported [+, =, ., @, -]."
  }
}

variable "sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution."
  type        = string
  default     = "sra-securityhub-org"
  validation {
    condition     = can(index(["sra-securityhub-org"], var.sra_solution_name))
    error_message = "Invalid solution name"
  }
}

variable "management_account_id" {
  description = "Management Account Id"
  type        = string
}