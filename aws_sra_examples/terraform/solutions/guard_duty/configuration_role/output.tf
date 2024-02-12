########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

output "guardduty_org_configuration_role_name" {
  value = aws_iam_role.configuration_role.name
}