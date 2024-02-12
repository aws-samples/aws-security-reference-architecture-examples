########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

output "publishing_destination_bucket_arn" {
  value = aws_s3_bucket.guardduty_delivery_bucket.arn
}