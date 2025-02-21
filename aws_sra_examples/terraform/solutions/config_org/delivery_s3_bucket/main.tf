########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
resource "aws_s3_bucket" "r_config_delivery_s3_bucket" {
  #checkov:skip=CKV2_AWS_61: Ensure that an S3 bucket has a lifecycle configuration
  #checkov:skip=CKV_AWS_18: Ensure the S3 bucket has access logging enabled
  #checkov:skip=CKV2_AWS_62: Ensure S3 buckets should have event notifications enabled
  #checkov:skip=CKV_AWS_144: Ensure that S3 bucket has cross-region replication enabled
  bucket = "${var.p_config_org_delivery_bucket_prefix}-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  tags = {
    "sra-solution" = var.p_sra_solution_name
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "r_config_delivery_s3_bucket" {
  bucket = aws_s3_bucket.r_config_delivery_s3_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.p_config_org_delivery_kms_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "r_config_delivery_s3_bucket" {
  bucket = aws_s3_bucket.r_config_delivery_s3_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "r_config_delivery_s3_bucket" {
  bucket = aws_s3_bucket.r_config_delivery_s3_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "r_config_delivery_s3_bucket" {
  #checkov:skip=CKV2_AWS_65: Ensure access control lists for S3 buckets are disabled
  bucket = aws_s3_bucket.r_config_delivery_s3_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_policy" "r_config_s3_bucket_policy" {
  bucket = aws_s3_bucket.r_config_delivery_s3_bucket.id

  policy = data.aws_iam_policy_document.r_config_s3_bucket_policy.json
}

data "aws_iam_policy_document" "r_config_s3_bucket_policy" {
  statement {
    sid    = "AllowSSLRequestsOnly"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      "${aws_s3_bucket.r_config_delivery_s3_bucket.arn}",
      "${aws_s3_bucket.r_config_delivery_s3_bucket.arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "AWSBucketPermissionsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = ["${aws_s3_bucket.r_config_delivery_s3_bucket.arn}"]
  }

  statement {
    sid    = "AWSConfigBucketExistenceCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:ListBucket"]
    resources = ["${aws_s3_bucket.r_config_delivery_s3_bucket.arn}"]
  }

  statement {
    sid    = "AWSBucketDeliveryForConfig"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.r_config_delivery_s3_bucket.arn}/${var.p_organization_id}/AWSLogs/*/*"]
  }
}