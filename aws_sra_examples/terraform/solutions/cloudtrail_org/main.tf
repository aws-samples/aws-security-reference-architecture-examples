########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
locals {
  is_audit_account = data.aws_caller_identity.current.account_id == var.audit_account_id
  is_log_account   = data.aws_caller_identity.current.account_id == var.log_archive_account_id
  is_home_region   = data.aws_region.current.name == var.home_region
}

module "kms" {
  count = local.is_audit_account && local.is_home_region ? 1 : 0

  providers = {
    aws = aws.main
  }

  source = "./kms"

  management_account_id  = var.management_account_id
  log_archive_account_id = var.log_archive_account_id
  secrets_key_alias_arn  = var.secrets_key_alias_arn
}

module "s3_bucket" {
  count = local.is_audit_account && local.is_home_region ? 1 : 0

  providers = {
    aws = aws.log_archive
  }

  source = "./s3"

  management_account_id              = var.management_account_id
  sra_secrets_key_alias_arn          = var.secrets_key_alias_arn
  organization_id                    = var.organization_id
  organization_cloudtrail_kms_key_id = module.kms[0].cloudtrail_kms_key_arn
}

module "cloudtrail_org" {
  count = local.is_audit_account && local.is_home_region ? 1 : 0

  providers = {
    aws = aws.management
  }

  source = "./org"

  delegated_admin_account_id         = var.audit_account_id
  organization_cloudtrail_kms_key_id = module.kms[0].cloudtrail_kms_key_arn
  cloudtrail_s3_bucket_name          = module.s3_bucket[0].cloudtrail_org_bucket_name
}