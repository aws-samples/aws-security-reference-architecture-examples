########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

locals {
  is_management_account = data.aws_caller_identity.current.account_id == var.management_account_id
  is_audit_account      = data.aws_caller_identity.current.account_id == var.audit_account_id
  is_log_account        = data.aws_caller_identity.current.account_id == var.log_archive_account_id
  is_home_region        = data.aws_region.current.name == var.home_region
}

module "securityhub_configuration_role" {
  count = local.is_home_region ? 1 : 0

  providers = {
    aws = aws.main
  }

  source = "./configuration_role"

  management_account_id      = var.management_account_id
  delegated_admin_account_id = var.audit_account_id
  sra_solution_name          = var.sra_solution_name
}

module "security_hub" {
  count = local.is_home_region && local.is_audit_account ? 1 : 0

  providers = {
    aws = aws.management
  }

  source = "./configuration"

  cis_standard_version                     = var.cis_standard_version
  compliance_frequency                     = var.compliance_frequency
  securityhub_control_tower_regions_only   = var.securityhub_control_tower_regions_only
  create_lambda_log_group                  = var.create_lambda_log_group
  delegated_admin_account_id               = var.delegated_admin_account_id
  disable_security_hub                     = var.disable_security_hub
  enabled_regions                          = var.enabled_regions
  enable_cis_standard                      = var.enable_cis_standard
  enable_pci_standard                      = var.enable_pci_standard
  enable_nist_standard                     = var.enable_nist_standard
  enable_security_best_practices_standard  = var.enable_security_best_practices_standard
  event_rule_role_name                     = var.event_rule_role_name
  pci_standard_version                     = var.pci_standard_version
  nist_standard_version                    = var.nist_standard_version
  security_best_practices_standard_version = var.security_best_practices_standard_version
  security_hub_org_lambda_function_name    = var.security_hub_org_lambda_function_name
  security_hub_org_lambda_role_name        = var.security_hub_org_lambda_role_name
  security_hub_configuration_role_name     = var.security_hub_configuration_role_name
  organization_id                          = var.organization_id
  sra_solution_name                        = var.sra_solution_name
  lambda_log_group_kms_key                 = var.lambda_log_group_kms_key
  sra_alarm_email                          = var.sra_alarm_email
}

module "recorder_start_event" {
  count = local.is_home_region && local.is_management_account == false ? 1 : 0

  providers = {
    aws = aws.main
  }

  source = "./recorder_start_event"

  event_rule_role_name  = var.event_rule_role_name
  sra_solution_name     = var.sra_solution_name
  management_account_id = var.management_account_id
}
