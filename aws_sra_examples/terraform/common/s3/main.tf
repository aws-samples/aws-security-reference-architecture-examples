########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_s3_bucket" "sra_state_bucket" {
  bucket        = "${var.sra_state_bucket_prefix}-${data.aws_region.current.name}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sra_state_bucket_see" {
  bucket = aws_s3_bucket.sra_state_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_id
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "sra_state_bucket_versioning" {
  bucket = aws_s3_bucket.sra_state_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "sra_state_bucket_ownership_control" {
  bucket = aws_s3_bucket.sra_state_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "sra_state_bucket_public_access_block" {
  bucket = aws_s3_bucket.sra_state_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}