########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "guardduty_org_delivery_bucket_prefix" {
  description = "GuardDuty Delivery Bucket Prefix"
  type        = string
  default     = "sra-guardduty-org-delivery"
}

variable "guardduty_org_delivery_kms_key_arn" {
  description = "GuardDuty Delivery KMS Key ARN"
  type        = string
}

variable "sra_solution_name" {
  description = "SRA Solution Name"
  type        = string
  default     = "sra-guardduty-org"
}