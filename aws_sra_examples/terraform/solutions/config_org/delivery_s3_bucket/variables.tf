########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "p_config_org_delivery_bucket_prefix" {
  type        = string
  description = "Config Delivery S3 bucket prefix. The account and region will get added to the end."
  default     = "sra-config-org-delivery"
}

variable "p_organization_id" {
  type        = string
  description = "SSM Parameter for AWS Organizations ID"
}

variable "p_config_org_delivery_kms_key_arn" {
  type        = string
  description = "KMS Key ARN to use for encrypting Config snapshots sent to S3"
}

variable "p_sra_solution_name" {
  type        = string
  description = "The SRA solution name. The default value is the folder name of the solution"
  default     = "sra-config-org"
}

variable "p_s3_key_prefix" {
  type        = string
  description = "Organization ID to use as the S3 Key prefix for storing the audit logs"
  default     = "/sra/control-tower/organization-id"
}