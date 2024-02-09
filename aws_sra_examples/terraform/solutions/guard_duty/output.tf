########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

output "guard_duty_results" {
  value = local.is_home_region && local.is_audit_account ? module.guardduty_configuration[0].lambda_result_entry : null
}