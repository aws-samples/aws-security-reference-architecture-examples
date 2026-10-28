########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "dynamodb_name" {
  description = "DynamoDB Table Name for state locking"
  type        = string
  default     = "sra-tfstate-lock"
}

variable "sra_solution_name" {
  description = "SRA Solution Name"
  type        = string
  default     = "sra-tfstate-s3"
}