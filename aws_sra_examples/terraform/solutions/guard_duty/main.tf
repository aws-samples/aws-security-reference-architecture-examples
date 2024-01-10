########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

locals {
  is_audit_account = var.account_id == var.audit_account_id
  is_log_account   = var.account_id == var.log_archive_account_id
  is_home_region   = data.aws_region.current.name == var.home_region
}

module "guardduty_delete_role" {
  count = data.aws_region.current.name == var.home_region ? 1 : 0

  providers = {
    aws = aws.main
  }

  source = "./delete_detector"

  management_account_id = var.management_account_id
}

module "guardduty_configuration_role" {
  count = local.is_home_region && local.is_audit_account ? 1 : 0

  providers = {
    aws = aws.main
  }

  source = "./configuration_role"

  management_account_id = var.management_account_id
}

module "guardduty_delivery_key" {
  count = local.is_home_region && local.is_audit_account ? 1 : 0

  providers = {
    aws = aws.main
  }

  source                 = "./kms_key"
  log_archive_account_id = var.log_archive_account_id
  management_account_id  = var.management_account_id
}

module "guardduty_s3_bucket" {
  count = local.is_home_region && local.is_audit_account ? 1 : 0

  providers = {
    aws = aws.log_archive
  }

  source                             = "./s3"
  guardduty_org_delivery_kms_key_arn = module.guardduty_delivery_key[0].guardduty_kms_key_arn
}

module "guardduty_configuration" {
  count = local.is_home_region && local.is_audit_account ? 1 : 0

  providers = {
    aws = aws.management
  }

  source = "./gd_configuration"

  publishing_destination_bucket_arn     = module.guardduty_s3_bucket[0].publishing_destination_bucket_arn
  delete_detector_role_name             = module.guardduty_delete_role[0].delete_detector_role_name
  guardduty_org_configuration_role_name = module.guardduty_configuration_role[0].guardduty_org_configuration_role_name
  guardduty_org_delivery_kms_key_arn    = module.guardduty_delivery_key[0].guardduty_kms_key_arn
  audit_account_id                      = var.audit_account_id
  organization_id                       = var.organization_id
  disable_guard_duty                    = var.disable_guard_duty

  auto_enable_s3_logs                  = var.enable_s3_logs
  enable_kubernetes_audit_logs         = var.enable_kubernetes_audit_logs
  enable_malware_protection            = var.enable_malware_protection
  enable_rds_login_events              = var.enable_rds_login_events
  enable_eks_runtime_monitoring        = var.enable_eks_runtime_monitoring
  enable_eks_addon_management          = var.enable_eks_addon_management
  enable_lambda_network_logs           = var.enable_lambda_network_logs
  finding_publishing_frequency         = var.finding_publishing_frequency
  guardduty_control_tower_regions_only = var.guardduty_control_tower_regions_only
}
