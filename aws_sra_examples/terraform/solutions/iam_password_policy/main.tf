########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

locals {
  is_home_region = data.aws_region.current.name == var.home_region
}

module "iam_password_policy_configuration" {
  count = local.is_home_region ? 1 : 0

  providers = {
    aws = aws.main
  }

  source = "./configuration"

  allow_users_to_change_password = var.allow_users_to_change_password
  create_lambda_log_group        = var.create_lambda_log_group
  hard_expiry                    = var.hard_expiry
  lambda_role_name               = var.lambda_role_name
  lambda_function_name           = var.lambda_function_name
  lambda_log_group_kms_key       = var.lambda_log_group_kms_key
  lambda_log_group_retention     = var.lambda_log_group_retention
  lambda_log_level               = var.lambda_log_level
  max_password_age               = var.max_password_age
  minimum_password_length        = var.minimum_password_length
  password_reuse_prevention      = var.password_reuse_prevention
  require_lowercase_characters   = var.require_lowercase_characters
  require_numbers                = var.require_numbers
  require_symbols                = var.require_symbols
  require_uppercase_characters   = var.require_uppercase_characters
  sra_solution_name              = var.sra_solution_name
}
