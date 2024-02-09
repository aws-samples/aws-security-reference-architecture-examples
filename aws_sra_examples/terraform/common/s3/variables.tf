########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "sra_state_bucket_prefix" {
  description = "SRA State Bucket Prefix"
  type        = string
  default     = "sra-tfstate-files"
}

variable kms_key_id {
  description = "KMS Key ID"
  type        = string
}

variable "sra_solution_name" {
  description = "SRA Solution Name"
  type        = string
  default     = "sra-tfstate-s3"
}