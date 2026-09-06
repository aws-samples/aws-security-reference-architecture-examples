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
    bucket_key_enabled = true
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
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "sra_state_bucket_public_access_block" {
  bucket = aws_s3_bucket.sra_state_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "sra_state_bucket_lifecycle" {
  bucket = aws_s3_bucket.sra_state_bucket.id

  rule {
    id     = "cleanup-old-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_logging" "sra_state_bucket_logging" {
  bucket = aws_s3_bucket.sra_state_bucket.id

  target_bucket = aws_s3_bucket.sra_state_bucket_logs.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket" "sra_state_bucket_logs" {
  bucket        = "${var.sra_state_bucket_prefix}-logs-${data.aws_region.current.name}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sra_state_bucket_logs_see" {
  bucket = aws_s3_bucket.sra_state_bucket_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_id
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "sra_state_bucket_logs_versioning" {
  bucket = aws_s3_bucket.sra_state_bucket_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "sra_state_bucket_logs_ownership_control" {
  bucket = aws_s3_bucket.sra_state_bucket_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "sra_state_bucket_logs_public_access_block" {
  bucket = aws_s3_bucket.sra_state_bucket_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "sra_state_bucket_logs_lifecycle" {
  bucket = aws_s3_bucket.sra_state_bucket_logs.id

  rule {
    id     = "logs-cleanup"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "sra_state_bucket_policy" {
  bucket = aws_s3_bucket.sra_state_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.sra_state_bucket.arn,
          "${aws_s3_bucket.sra_state_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "sra_state_bucket_logs_policy" {
  bucket = aws_s3_bucket.sra_state_bucket_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.sra_state_bucket_logs.arn,
          "${aws_s3_bucket.sra_state_bucket_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
