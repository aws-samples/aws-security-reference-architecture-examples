########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "account_region" {
  type = string
  description = "Default Account Region to deploy in"
  default     = "us-east-1"
}

variable "control_tower" {
  description = "AWS Control Tower landing zone deployed/in-use"
  default     = "false"
}

variable "governed_regions" {
  description = "AWS regions (comma separated) if not using AWS Control Tower (leave set to ct-regions for AWS Control Tower environments)"
  default     = "us-east-1,us-west-2"
}

variable "security_account_id" {
  description = "Security Tooling Account ID"
  type        = string
  default     = "654654614633"
}

variable "log_archive_account_id" {
  description = "Log Archive Account ID"
  type        = string
  default     = "533267136266"
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
