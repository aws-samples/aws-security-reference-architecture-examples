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
    bucket_key_enabled = true
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
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.org_trail_bucket.id

  rule {
    id     = "cloudtrail-logs-lifecycle"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years for compliance
    }
  }
}

resource "aws_s3_bucket_logging" "this" {
  bucket = aws_s3_bucket.org_trail_bucket.id

  target_bucket = aws_s3_bucket.org_trail_logs_bucket.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket" "org_trail_logs_bucket" {
  bucket = "${var.bucket_name_prefix}-logs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.org_trail_logs_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.organization_cloudtrail_kms_key_id
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.org_trail_logs_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.org_trail_logs_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.org_trail_logs_bucket.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.org_trail_logs_bucket.id

  rule {
    id     = "logs-cleanup"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "org_trail_logs_bucket_policy" {
  bucket = aws_s3_bucket.org_trail_logs_bucket.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "DenyInsecureTransport",
        Effect    = "Deny",
        Principal = "*",
        Action    = "s3:*",
        Resource = [
          aws_s3_bucket.org_trail_logs_bucket.arn,
          "${aws_s3_bucket.org_trail_logs_bucket.arn}/*"
        ],
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
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
  count = var.sra_secrets_key_alias_arn != "" ? 1 : 0

  name                    = "sra/cloudtrail_org_s3_bucket"
  description             = "Organization CloudTrail S3 Bucket"
  kms_key_id              = var.sra_secrets_key_alias_arn
  recovery_window_in_days = 30

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_secretsmanager_secret_rotation" "org_trail_s3_bucket_rotation" {
  count               = var.sra_secrets_key_alias_arn != "" ? 1 : 0
  secret_id           = aws_secretsmanager_secret.org_trail_s3_bucket_secret[0].id
  rotation_lambda_arn = aws_lambda_function.rotation_lambda[0].arn

  rotation_rules {
    automatically_after_days = 90
  }
}

resource "aws_lambda_function" "rotation_lambda" {
  count         = var.sra_secrets_key_alias_arn != "" ? 1 : 0
  function_name = "sra-cloudtrail-secret-rotation"
  role          = aws_iam_role.lambda_role[0].arn
  handler       = "index.lambda_handler"
  runtime       = "python3.9"
  timeout       = 30

  environment {
    variables = {
      SECRET_ARN = aws_secretsmanager_secret.org_trail_s3_bucket_secret[0].arn
    }
  }

  filename         = "${path.module}/lambda_function.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda_function.zip")
}

resource "aws_iam_role" "lambda_role" {
  count = var.sra_secrets_key_alias_arn != "" ? 1 : 0
  name  = "sra-cloudtrail-secret-rotation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  count = var.sra_secrets_key_alias_arn != "" ? 1 : 0
  name  = "sra-cloudtrail-secret-rotation-policy"
  role  = aws_iam_role.lambda_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Effect   = "Allow"
        Resource = aws_secretsmanager_secret.org_trail_s3_bucket_secret[0].arn
      },
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_secretsmanager_secret_version" "org_trail_s3_bucket_secret_version" {
  count = var.sra_secrets_key_alias_arn != "" ? 1 : 0

  secret_id = aws_secretsmanager_secret.org_trail_s3_bucket_secret[0].id
  secret_string = jsonencode({
    "CloudTrailS3BucketArn" : aws_s3_bucket.org_trail_bucket.arn
  })
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
          AWS = "arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:root"
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
