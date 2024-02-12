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

module "inspector_configuration_role" {
  count = local.is_home_region ? 1 : 0

  providers = {
    aws = aws.main
  }

  source = "./configuration_role"

  management_account_id             = var.management_account_id
  inspector_org_lambda_role_name    = var.inspector_org_lambda_role_name
  inspector_configuration_role_name = var.inspector_configuration_role_name
  sra_solution_name                 = var.sra_solution_name
}

module "inspector_configuration" {
  count = local.is_home_region && local.is_audit_account ? 1 : 0

  providers = {
    aws = aws.management
  }

  source = "./configuration"

  delegated_admin_account_id = var.audit_account_id
  sra_solution_name          = var.sra_solution_name
  organization_id            = var.organization_id

  inspector_org_lambda_function_name   = var.inspector_org_lambda_function_name
  inspector_org_lambda_role_name       = var.inspector_org_lambda_role_name
  inspector_configuration_role_name    = var.inspector_configuration_role_name
  inspector_control_tower_regions_only = var.inspector_control_tower_regions_only
  enabled_regions                      = var.enabled_regions
  ecr_rescan_duration                  = var.ecr_rescan_duration
  scan_components                      = var.scan_components
  disable_inspector                    = var.disable_inspector
}
