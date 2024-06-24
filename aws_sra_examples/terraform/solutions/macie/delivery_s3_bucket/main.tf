########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
resource "aws_s3_bucket" "macie_delivery_s3_bucket" {
  #checkov:skip=CKV2_AWS_61: Ensure that an S3 bucket has a lifecycle configuration
  #checkov:skip=CKV_AWS_18: Ensure the S3 bucket has access logging enabled
  #checkov:skip=CKV2_AWS_62: Ensure S3 buckets should have event notifications enabled
  #checkov:skip=CKV_AWS_144: Ensure that S3 bucket has cross-region replication enabled
  bucket = "${var.macie_delivery_bucket_prefix}-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  tags = {
    "sra-solution" = var.sra_solution_name
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  #checkov:skip=CKV2_AWS_67: Ensure AWS S3 bucket encrypted with Customer Managed Key (CMK) has regular rotation
  bucket = aws_s3_bucket.macie_delivery_s3_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.macie_delivery_kms_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.macie_delivery_s3_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.macie_delivery_s3_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  #checkov:skip=CKV2_AWS_65: Ensure access control lists for S3 buckets are disabled
  bucket = aws_s3_bucket.macie_delivery_s3_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_policy" "macie_delivery_s3_bucket_policy" {
  bucket = aws_s3_bucket.macie_delivery_s3_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "DenyPutObjectUnlessMacie",
        Effect = "Deny",
        Action = "s3:PutObject",
        Condition = {
          "ForAnyValue:StringNotEquals" : {
            "aws:CalledVia" = "macie.amazonaws.com"
          }
        },
        Resource = [
          "${aws_s3_bucket.macie_delivery_s3_bucket.arn}",
          "${aws_s3_bucket.macie_delivery_s3_bucket.arn}/*",
        ],
        Principal = "*",
      },
      {
        Sid    = "SecureTransport",
        Effect = "Deny",
        Action = "s3:*",
        Condition = {
          "Bool" : {
            "aws:SecureTransport" = "false"
          }
        },
        Resource = [
          "${aws_s3_bucket.macie_delivery_s3_bucket.arn}",
          "${aws_s3_bucket.macie_delivery_s3_bucket.arn}/*",
        ],
        Principal = "*",
      },
      {
        Sid    = "AWSBucketPermissionsCheck",
        Effect = "Allow",
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
          "s3:ListBucket",
        ],
        Resource = "${aws_s3_bucket.macie_delivery_s3_bucket.arn}",
        Principal = {
          Service = "macie.amazonaws.com"
        },
      },
      {
        Sid    = "AWSBucketDelivery",
        Effect = "Allow",
        Action = "s3:PutObject",
        Condition = {
          "StringEquals" : {
            "s3:x-amz-acl" : "bucket-owner-full-control"
          }
        },
        Resource = "${aws_s3_bucket.macie_delivery_s3_bucket.arn}/*",
        Principal = {
          Service = "macie.amazonaws.com"
        },
      },
      {
        Sid    = "DenyUnencryptedObjectUploads",
        Effect = "Deny",
        Action = "s3:PutObject",
        Condition = {
          "StringNotEquals" : {
            "s3:x-amz-server-side-encryption" : "aws:kms"
          }
        },
        Resource = "${aws_s3_bucket.macie_delivery_s3_bucket.arn}/*",
        Principal = {
          Service = "macie.amazonaws.com"
        },
      },
      {
        Sid    = "DenyIncorrectEncryptionHeader",
        Effect = "Deny",
        Action = "s3:PutObject",
        Condition = {
          "StringNotEquals" : {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" : var.macie_delivery_kms_key_arn
          }
        },
        Resource = "${aws_s3_bucket.macie_delivery_s3_bucket.arn}/*",
        Principal = {
          Service = "macie.amazonaws.com"
        },
      },
      {
        Sid    = "AllowDelegatedAdminReadAccess",
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
        ],
        Resource = [
          "${aws_s3_bucket.macie_delivery_s3_bucket.arn}",
          "${aws_s3_bucket.macie_delivery_s3_bucket.arn}/*",
        ],
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${var.delegated_admin_account_id}:root"
        },
      },
    ]
  })
}
