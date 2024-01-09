########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "delegated_admin_account_id" {
  description = "Delegated administrator account ID"
  type        = string
}

variable "macie_delivery_bucket_prefix" {
  description = "Macie Delivery S3 bucket prefix. The account and region will get added to the end."
  type        = string
  default     = "sra-macie-org-delivery"
}

variable "macie_delivery_kms_key_arn" {
  description = "KMS Key ARN to use for encrypting Macie classifications sent to S3"
  type        = string
}

variable "sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution"
  type        = string
  default     = "sra-macie-org"
}