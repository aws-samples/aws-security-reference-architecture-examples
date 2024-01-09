########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
module "register_delegated_admin" {
  source = "./register_admin"

  register_delegated_admin_lambda_role_name     = var.register_delegated_admin_lambda_role_name
  register_delegated_admin_lambda_function_name = var.register_delegated_admin_lambda_function_name
  service_principal_list                        = var.service_principal_list
  delegated_admin_account_id                    = var.delegated_admin_account_id
}