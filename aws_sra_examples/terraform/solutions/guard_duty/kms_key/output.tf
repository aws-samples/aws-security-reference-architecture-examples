########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

output "guardduty_kms_key_arn" {
  value = aws_kms_key.guardduty_delivery_key.arn
}