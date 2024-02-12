########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "management_account_id" {
  default     = "333333333333"
  description = "AWS Account ID of the Management account (12 digits)"
  validation {
    condition     = length(var.management_account_id) == 12 && can(regex("^\\d{12}$", var.management_account_id))
    error_message = "Must be 12 digits."
  }
  type = string
}

variable "aws_partition" {
  description = "AWS Partition (e.g., aws or aws-cn)"
  default     = "aws"
}

variable "execution_role_name" {
  default     = "sra-execution"
  description = "Name of the SRA execution role"
  type        = string
}

variable "solution_name" {
  default     = "sra-create-deployment-roles"
  description = "Name of the SRA solution"
  type        = string
}