########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
output "cloudtrail_org_bucket_name" {
  value = aws_s3_bucket.org_trail_bucket.id
}