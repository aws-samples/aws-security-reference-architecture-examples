########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

data "aws_partition" "current" {
  provider = aws.main
}
data "aws_caller_identity" "current" {
  provider = aws.main
}
data "aws_region" "current" {
  provider = aws.main
}