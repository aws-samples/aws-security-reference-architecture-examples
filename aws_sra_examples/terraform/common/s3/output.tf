########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

output "bucket_name" {
  value = aws_s3_bucket.sra_state_bucket.id
}