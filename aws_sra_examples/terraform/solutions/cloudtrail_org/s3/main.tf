########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
resource "aws_s3_bucket" "org_trail_bucket" {
  bucket = "${var.bucket_name_prefix}-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  tags = {
    "sra-solution" = var.sra_solution_name
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.org_trail_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.organization_cloudtrail_kms_key_id
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.org_trail_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.org_trail_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.org_trail_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_policy" "org_trail_bucket_policy" {
  bucket = aws_s3_bucket.org_trail_bucket.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "DenyExternalPrincipals",
        Effect = "Deny",
        Action = [
          "s3:GetObject*",
          "s3:ListBucket",
          "s3:PutObject",
        ],
        Principal = "*",
        Resource = [
          "${aws_s3_bucket.org_trail_bucket.arn}",
          "${aws_s3_bucket.org_trail_bucket.arn}/*",
        ],
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = var.organization_id
          },
          Bool = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      },
      {
        Sid    = "AWSBucketPermissionsCheck",
        Effect = "Allow",
        Action = [
          "s3:GetBucketAcl",
          "s3:ListBucket",
        ],
        Resource = aws_s3_bucket.org_trail_bucket.arn,
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      },
      {
        Sid    = "AWSCloudTrailAccountWrite",
        Effect = "Allow",
        Action = "s3:PutObject",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control",
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${var.management_account_id}:trail/${var.cloudtrail_name}",
          }
        },
        Resource = "${aws_s3_bucket.org_trail_bucket.arn}/AWSLogs/${var.management_account_id}/*",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      },
      {
        Sid    = "AWSCloudTrailOrgWrite",
        Effect = "Allow",
        Action = "s3:PutObject",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control",
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${var.management_account_id}:trail/${var.cloudtrail_name}",
          }
        },
        Resource = "${aws_s3_bucket.org_trail_bucket.arn}/AWSLogs/${var.organization_id}/*",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      },
      {
        Sid    = "SecureTransport",
        Effect = "Deny",
        Action = "s3:*",
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        },
        Resource = [
          aws_s3_bucket.org_trail_bucket.arn,
          "${aws_s3_bucket.org_trail_bucket.arn}/*",
        ],
        Principal = "*"
      }
    ]
  })
}

resource "aws_secretsmanager_secret" "org_trail_s3_bucket_secret" {
  #checkov:skip=CKV_AWS_149: Ensure that Secrets Manager secret is encrypted using KMS CMK
  count = var.sra_secrets_key_alias_arn != "" ? 1 : 0

  name        = "sra/cloudtrail_org_s3_bucket"
  description = "Organization CloudTrail S3 Bucket"

  kms_key_id = var.sra_secrets_key_alias_arn

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_secretsmanager_secret_policy" "org_trail_s3_bucket_secret_policy" {
  count = var.sra_secrets_key_alias_arn != "" ? 1 : 0

  secret_arn = aws_secretsmanager_secret.org_trail_s3_bucket_secret[0].id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "secretsmanager:GetSecretValue",
        Effect = "Allow",
        Principal = {
          AWS = "${data.aws_partition.current.partition}:iam::${var.management_account_id}:root",
        },
        Resource = "*",
        Condition = {
          StringEquals = {
            "secretsmanager:VersionStage" = "AWSCURRENT"
          }
        }
      }
    ]
  })
}
