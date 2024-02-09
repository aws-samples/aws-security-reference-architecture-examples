########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

output "delete_detector_role_name" {
  value = aws_iam_role.delete_detector_role.name
}