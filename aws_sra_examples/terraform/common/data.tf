########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

data "aws_caller_identity" "current" {}

data "aws_ssm_parameter" "customer_control_tower_regions" {
  depends_on = [module.mangement_account_parameters]
  name       = "/sra/regions/customer-control-tower-regions"
}

data "aws_ssm_parameter" "customer_control_tower_regions_without_home_region" {
  depends_on = [module.mangement_account_parameters]
  name       = "/sra/regions/customer-control-tower-regions-without-home-region"
}

data "aws_ssm_parameter" "enabled_regions" {
  depends_on = [module.mangement_account_parameters]
  name       = "/sra/regions/enabled-regions"
}

data "aws_ssm_parameter" "enabled_regions_without_home_region" {
  depends_on = [module.mangement_account_parameters]
  name       = "/sra/regions/enabled-regions-without-home-region"
}

data "aws_ssm_parameter" "home_region" {
  depends_on = [module.mangement_account_parameters]
  name       = "/sra/control-tower/home-region"
}

data "aws_ssm_parameter" "audit_account_id" {
  depends_on = [module.mangement_account_parameters]
  name       = "/sra/control-tower/audit-account-id"
}

data "aws_ssm_parameter" "log_archive_account_id" {
  depends_on = [module.mangement_account_parameters]
  name       = "/sra/control-tower/log-archive-account-id"
}

data "aws_ssm_parameter" "management_account_id" {
  depends_on = [module.mangement_account_parameters]
  name       = "/sra/control-tower/management-account-id"
}

data "aws_ssm_parameter" "organization_id" {
  depends_on = [module.mangement_account_parameters]
  name       = "/sra/control-tower/organization-id"
}

data "aws_ssm_parameter" "root_organizational_unit_id" {
  depends_on = [module.mangement_account_parameters]
  name       = "/sra/control-tower/root-organizational-unit-id"
}
