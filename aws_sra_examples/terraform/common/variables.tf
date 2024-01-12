########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "control_tower" {
  description = "AWS Control Tower landing zone deployed/in-use"
  default     = "false"
}

variable "governed_regions" {
  description = "AWS regions (comma separated) if not using AWS Control Tower (leave set to ct-regions for AWS Control Tower environments)"
  default     = "us-west-2,us-west-1,ap-northeast-3,ap-south-1,eu-central-1"
}

variable "security_account_id" {
  description = "Security Tooling Account ID"
  type        = string
  default     = "111111111111"
}

variable "log_archive_account_id" {
  description = "Log Archive Account ID"
  type        = string
  default     = "222222222222"
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
