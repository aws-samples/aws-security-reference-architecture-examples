########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
locals {
  is_audit_account = data.aws_caller_identity.current.account_id == var.audit_account_id
  is_log_account   = data.aws_caller_identity.current.account_id == var.log_archive_account_id
  is_home_region   = data.aws_region.current.name == var.home_region
}

module "disable_role" {
  count = local.is_home_region ? 1 : 0

  providers = {
    aws = aws.main
  }

  source = "./disable_role"

  management_account_id      = var.management_account_id
  macie_org_lambda_role_name = var.macie_org_lambda_role_name
}

module "configuration_role" {
  count = local.is_audit_account && local.is_home_region ? 1 : 0

  providers = {
    aws = aws.main
  }

  source = "./configuration_role"

  audit_account_id                  = var.audit_account_id
  management_account_id             = var.management_account_id
  macie_org_lambda_role_name        = var.macie_org_lambda_role_name
  macie_org_configuration_role_name = var.macie_org_configuration_role_name
}

module "delivery_kms_key" {
  count = local.is_audit_account && local.is_home_region ? 1 : 0

  providers = {
    aws = aws.main
  }

  source = "./delivery_kms_key"

  management_account_id  = var.management_account_id
  log_archive_account_id = var.log_archive_account_id
  secrets_key_alias_arn  = var.secrets_key_alias_arn
}

module "delivery_s3_bucket" {
  count = local.is_audit_account && local.is_home_region ? 1 : 0

  providers = {
    aws = aws.log_archive
  }

  source = "./delivery_s3_bucket"

  delegated_admin_account_id = var.audit_account_id
  macie_delivery_kms_key_arn = module.delivery_kms_key[0].macie_delivery_kms_key_arn
}

module "macie_configuration" {
  count = local.is_audit_account && local.is_home_region ? 1 : 0

  providers = {
    aws = aws.management
  }

  source = "./configuration"

  p_delegated_admin_account_id         = var.audit_account_id
  p_kms_key_arn                        = module.delivery_kms_key[0].macie_delivery_kms_key_arn
  p_organization_id                    = var.organization_id
  p_management_account_id              = var.management_account_id
  p_publishing_destination_bucket_name = module.delivery_s3_bucket[0].macie_delivery_bucket_name
  disable_macie                        = var.disable_macie
  p_finding_publishing_frequency       = var.macie_finding_publishing_frequency
}
