########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_s3_bucket" "guardduty_delivery_bucket" {
  #checkov:skip=CKV2_AWS_61: Ensure that an S3 bucket has a lifecycle configuration
  #checkov:skip=CKV_AWS_18: Ensure the S3 bucket has access logging enabled
  #checkov:skip=CKV2_AWS_62: Ensure S3 buckets should have event notifications enabled
  #checkov:skip=CKV_AWS_144: Ensure that S3 bucket has cross-region replication enabled
  bucket        = "${var.guardduty_org_delivery_bucket_prefix}-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  force_destroy = true

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_see" {
  #checkov:skip=CKV2_AWS_67: Ensure AWS S3 bucket encrypted with Customer Managed Key (CMK) has regular rotation
  bucket = aws_s3_bucket.guardduty_delivery_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.guardduty_org_delivery_kms_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "guardduty_versioning" {
  bucket = aws_s3_bucket.guardduty_delivery_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "guardduty_ownership_control" {
  #checkov:skip=CKV2_AWS_65: Ensure access control lists for S3 buckets are disabled
  bucket = aws_s3_bucket.guardduty_delivery_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "guardduty_public_access_block" {
  bucket = aws_s3_bucket.guardduty_delivery_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "guardduty_delivery_bucket_policy" {
  bucket = aws_s3_bucket.guardduty_delivery_bucket.id
  policy = data.aws_iam_policy_document.guardduty_delivery_bucket_policy.json
}

data "aws_iam_policy_document" "guardduty_delivery_bucket_policy" {
  statement {
    sid     = "DenyPutObjectUnlessGuardDuty"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    resources = [
      aws_s3_bucket.guardduty_delivery_bucket.arn,
      "${aws_s3_bucket.guardduty_delivery_bucket.arn}/*",
    ]
    condition {
      test     = "ForAnyValue:StringNotEquals"
      variable = "aws:CalledVia"
      values   = ["guardduty.amazonaws.com"]
    }
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }

  statement {
    sid     = "SecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.guardduty_delivery_bucket.arn,
      "${aws_s3_bucket.guardduty_delivery_bucket.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }

  statement {
    sid       = "AWSBucketPermissionsCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl", "s3:GetBucketLocation", "s3:ListBucket"]
    resources = [aws_s3_bucket.guardduty_delivery_bucket.arn]
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }

  statement {
    sid       = "AWSBucketDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.guardduty_delivery_bucket.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }

  statement {
    sid       = "DenyUnencryptedObjectUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.guardduty_delivery_bucket.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }

  statement {
    sid       = "DenyIncorrectEncryptionHeader"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.guardduty_delivery_bucket.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [var.guardduty_org_delivery_kms_key_arn]
    }
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }
}
