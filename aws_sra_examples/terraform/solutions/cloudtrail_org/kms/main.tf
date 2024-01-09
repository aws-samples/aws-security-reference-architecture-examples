########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
resource "aws_kms_key" "organization_cloudtrail_key" {
  description         = "Organization CloudTrail Key"
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17",
    Id      = var.org_cloudtrail_key_alias,
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions",
        Effect    = "Allow",
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" },
        Action    = "kms:*",
        Resource  = "*",
      },
      {
        Sid       = "AllowCloudTrailToEncryptLogs",
        Effect    = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "kms:GenerateDataKey*",
        Resource  = "*",
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${data.aws_partition.current.partition}:cloudtrail:*:${var.management_account_id}:trail/*",
          },
        },
      },
      {
        Sid       = "AllowCloudTrailToDecryptLogFiles",
        Effect    = "Allow",
        Principal = { AWS = ["arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:root"] },
        Action    = "kms:Decrypt",
        Resource  = "*",
        Condition = {
          "Null" : {
            "kms:EncryptionContext:aws:cloudtrail:arn" : "false"
          }
        }
      },
      {
        Sid       = "AllowCloudTrailToDescribeKey",
        Effect    = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "kms:DescribeKey",
        Resource  = "*",
      },
      {
        Sid       = "AllowAliasCreationDuringSetup",
        Effect    = "Allow",
        Principal = { AWS = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"] },
        Action    = "kms:CreateAlias",
        Resource  = "*",
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}",
            "kms:ViaService"    = "cloudformation.${data.aws_region.current.name}.amazonaws.com",
          }
        }
      },
      {
        Sid       = "AllowLogArchiveAndPrimaryAccountAccess",
        Effect    = "Allow",
        Principal = { AWS = ["arn:${data.aws_partition.current.partition}:iam::${var.log_archive_account_id}:root", "arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:root"] },
        Action    = "kms:Decrypt",
        Resource  = "*",
        Condition = {
          "Null" : {
            "kms:EncryptionContext:aws:cloudtrail:arn" : "false"
          }
        }
      },
      {
        Sid       = "AllowAccountAccess",
        Effect    = "Allow",
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" },
        Action    = ["kms:DescribeKey", "kms:Decrypt"],
        Resource  = "*",
      },
    ],
  })

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_kms_alias" "organization_cloudtrail_key_alias" {
  name          = "alias/${var.org_cloudtrail_key_alias}"
  target_key_id = aws_kms_key.organization_cloudtrail_key.key_id
}

resource "aws_secretsmanager_secret" "organization_cloudtrail_key_secret" {
  count = var.secrets_key_alias_arn != "" ? 1 : 0

  name        = "sra/cloudtrail-org-key-arn"
  description = "Organization CloudTrail KMS Key ARN"

  kms_key_id = var.secrets_key_alias_arn

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_secretsmanager_secret_version" "macie_delivery_key_secret_version" {
  count     = var.secrets_key_alias_arn != "" ? 1 : 0
  secret_id = aws_secretsmanager_secret.organization_cloudtrail_key_secret[0].id

  secret_string = jsonencode({
    OrganizationCloudTrailKeyArn = aws_kms_key.organization_cloudtrail_key.arn,
  })
}

resource "aws_secretsmanager_secret_policy" "organization_cloudtrail_key_secret_policy" {
  count = var.secrets_key_alias_arn != "" ? 1 : 0

  secret_arn = aws_secretsmanager_secret.organization_cloudtrail_key_secret[0].id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "secretsmanager:GetSecretValue",
        Effect    = "Allow",
        Principal = { AWS = ["arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:root"] },
        Resource  = "*",
        Condition = {
          StringEquals = {
            "secretsmanager:VersionStage" = "AWSCURRENT",
          },
        },
      },
    ],
  })

  block_public_policy = true
}