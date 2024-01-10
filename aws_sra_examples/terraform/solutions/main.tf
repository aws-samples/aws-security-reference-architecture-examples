########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

locals {
  management_account_id                              = var.management_account_id
  audit_account_id                                   = var.audit_account_id
  log_archive_account_id                             = var.log_archive_account_id
  home_region                                        = var.home_region
  enabled_regions                                    = var.enabled_regions
  enabled_regions_without_home_region                = var.enabled_regions_without_home_region
  customer_control_tower_regions                     = var.customer_control_tower_regions
  customer_control_tower_regions_without_home_region = var.customer_control_tower_regions_without_home_region
  root_organizational_unit_id                        = var.root_organizational_unit_id
  organization_id                                    = var.organization_id

  is_management_account = var.management_account_id == var.account_id
  is_audit_account      = var.audit_account_id == var.account_id
  is_home_region        = data.aws_region.current.name == var.account_region
}

module "guard_duty" {
  count = var.enable_gd ? 1 : 0

  providers = {
    aws.main        = aws.target
    aws.log_archive = aws.log_archive
    aws.management  = aws.management
  }
  source = "./guard_duty"

  account_id             = var.account_id
  management_account_id  = local.management_account_id
  log_archive_account_id = local.log_archive_account_id
  audit_account_id       = local.audit_account_id
  home_region            = local.home_region
  organization_id        = var.organization_id
  disable_guard_duty     = var.disable_guard_duty

  enable_s3_logs                       = var.enable_s3_logs
  enable_kubernetes_audit_logs         = var.enable_kubernetes_audit_logs
  enable_malware_protection            = var.enable_malware_protection
  enable_rds_login_events              = var.enable_rds_login_events
  enable_eks_runtime_monitoring        = var.enable_eks_runtime_monitoring
  enable_eks_addon_management          = var.enable_eks_addon_management
  enable_lambda_network_logs           = var.enable_lambda_network_logs
  finding_publishing_frequency         = var.finding_publishing_frequency
  guardduty_control_tower_regions_only = var.guardduty_control_tower_regions_only
}

module "security_hub" {
  count = var.enable_sh ? 1 : 0
  providers = {
    aws.main        = aws.target
    aws.log_archive = aws.log_archive
    aws.management  = aws.management
  }

  delegated_admin_account_id = local.audit_account_id
  management_account_id      = local.management_account_id
  log_archive_account_id     = local.log_archive_account_id
  audit_account_id           = local.audit_account_id
  home_region                = local.home_region
  organization_id            = var.organization_id
  disable_security_hub       = var.disable_security_hub
  enabled_regions            = local.enabled_regions

  cis_standard_version                     = var.cis_standard_version
  compliance_frequency                     = var.compliance_frequency
  securityhub_control_tower_regions_only   = var.securityhub_control_tower_regions_only
  enable_cis_standard                      = var.enable_cis_standard
  enable_pci_standard                      = var.enable_pci_standard
  enable_nist_standard                     = var.enable_nist_standard
  enable_security_best_practices_standard  = var.enable_security_best_practices_standard
  pci_standard_version                     = var.pci_standard_version
  nist_standard_version                    = var.nist_standard_version
  security_best_practices_standard_version = var.security_best_practices_standard_version
  sra_alarm_email                          = var.sra_alarm_email

  source = "./security_hub"
}

module "register_delegated_admin" {
  count = var.enable_access_analyzer && local.is_audit_account && local.is_home_region ? 1 : 0

  providers = {
    aws = aws.management
  }

  source = "./register_delegated_administrator"

  register_delegated_admin_lambda_role_name     = "sra-iam-access-analyzer-delegated-admin-lambda"
  register_delegated_admin_lambda_function_name = "sra-iam-access-analyzer-delegated-admin"
  service_principal_list                        = ["access-analyzer.amazonaws.com"]
  delegated_admin_account_id                    = local.audit_account_id
}

module "access_analyzer" {
  count      = var.enable_access_analyzer ? 1 : 0
  depends_on = [module.register_delegated_admin]

  providers = {
    aws = aws.target
  }

  source                 = "./iam_access_analyzer"
  account_id             = var.account_id
  log_archive_account_id = local.log_archive_account_id
  audit_account_id       = local.audit_account_id
  home_region            = local.home_region
}

module "macie" {
  count = var.enable_macie ? 1 : 0
  providers = {
    aws.main        = aws.target
    aws.management  = aws.management
    aws.log_archive = aws.log_archive
  }

  source = "./macie"

  management_account_id              = local.management_account_id
  audit_account_id                   = local.audit_account_id
  log_archive_account_id             = local.log_archive_account_id
  home_region                        = local.home_region
  organization_id                    = var.organization_id
  macie_finding_publishing_frequency = var.macie_finding_publishing_frequency
  disable_macie                      = var.disable_macie
}

module "cloudtrail" {
  count = var.enable_cloudtrail_org ? 1 : 0
  providers = {
    aws.main        = aws.target
    aws.management  = aws.management
    aws.log_archive = aws.log_archive
  }

  source = "./cloudtrail_org"

  management_account_id     = local.management_account_id
  audit_account_id          = local.audit_account_id
  log_archive_account_id    = local.log_archive_account_id
  home_region               = local.home_region
  organization_id           = var.organization_id
  enable_data_events_only   = var.enable_data_events_only
  enable_lambda_data_events = var.enable_lambda_data_events
  enable_s3_data_events     = var.enable_s3_data_events
}

module "inspector" {
  count = var.enable_inspector ? 1 : 0
  providers = {
    aws.main        = aws.target
    aws.management  = aws.management
    aws.log_archive = aws.log_archive
  }

  source = "./inspector"

  management_account_id  = local.management_account_id
  audit_account_id       = local.audit_account_id
  log_archive_account_id = local.log_archive_account_id
  home_region            = local.home_region
  organization_id        = var.organization_id

  ecr_rescan_duration                  = var.ecr_rescan_duration
  scan_components                      = var.scan_components
  inspector_control_tower_regions_only = var.inspector_control_tower_regions_only
}

module "iam_password_policy" {
  count = var.enable_iam_password_policy ? 1 : 0

  providers = {
    aws.main        = aws.target
    aws.management  = aws.management
    aws.log_archive = aws.log_archive
  }

  source = "./iam_password_policy"

  home_region                    = var.home_region
  allow_users_to_change_password = var.iam_password_policy_allow_users_to_change_password
  hard_expiry                    = var.iam_password_policy_hard_expiry
  max_password_age               = var.iam_password_policy_max_password_age
  minimum_password_length        = var.iam_password_policy_minimum_password_length
  password_reuse_prevention      = var.iam_password_policy_password_reuse_prevention
  require_lowercase_characters   = var.iam_password_policy_require_lowercase_characters
  require_numbers                = var.iam_password_policy_require_numbers
  require_symbols                = var.iam_password_policy_require_symbols
  require_uppercase_characters   = var.iam_password_policy_require_uppercase_characters
}
