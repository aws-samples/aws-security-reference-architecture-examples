########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
output "config_delivery_bucket_name" {
  value = aws_s3_bucket.r_config_delivery_s3_bucket.id
}