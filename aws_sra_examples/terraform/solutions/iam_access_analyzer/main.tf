########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
locals {
  is_audit_account = var.account_id == var.audit_account_id
  is_log_account   = var.account_id == var.log_archive_account_id
  is_home_region   = data.aws_region.current.name == var.home_region
}

module "account_analyzer" {
  source = "./account"

  access_analyzer_name_prefix = var.access_analyzer_name_prefix
}

module "org_analyzer" {
  count = local.is_audit_account ? 1 : 0

  source = "./org"

  org_access_analyzer_name = var.org_access_analyzer_name
}