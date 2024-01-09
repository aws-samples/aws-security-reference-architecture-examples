########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

variable "bucket_name_prefix" {
  description = "S3 bucket prefix. The account and region will get added to the end."
  default     = "sra-org-trail-logs"
}

variable "cloudtrail_name" {
  description = "CloudTrail name"
  default     = "sra-org-trail"
}

variable "management_account_id" {
  description = "Management Account ID"
}

variable "organization_cloudtrail_kms_key_id" {
  description = "KMS Key ARN to use for encrypting the CloudTrail S3 Bucket"
}

variable "organization_id" {
  description = "AWS Organizations ID"
}

variable "sra_secrets_key_alias_arn" {
  description = "(Optional) SRA Secrets Manager KMS Key Alias ARN"
}

variable "sra_solution_name" {
  description = "The SRA solution name. The default value is the folder name of the solution"
  default     = "sra-cloudtrail-org"
}