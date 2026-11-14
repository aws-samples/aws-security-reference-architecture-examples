########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

output "kms_key_arn" {
  value = aws_kms_key.sra_secrets_key.arn
}