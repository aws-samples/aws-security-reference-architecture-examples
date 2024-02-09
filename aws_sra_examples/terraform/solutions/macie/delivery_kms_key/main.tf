########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

locals {
  aws_partition          = data.aws_partition.current.partition
  aws_account_id         = data.aws_caller_identity.current.account_id
  aws_region             = data.aws_region.current.name
  key_alias              = var.macie_delivery_key_alias
  log_archive_account_id = var.log_archive_account_id
  management_account_id  = var.management_account_id
}

resource "aws_kms_key" "macie_delivery_key" {
  description         = "Macie Delivery Key"
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17",
    Id      = local.key_alias,
    Statement = [
      {
        Sid      = "Enable IAM User Permissions",
        Effect   = "Allow",
        Action   = "kms:*",
        Resource = "*",
        Principal = {
          AWS = format("arn:${local.aws_partition}:iam::${local.aws_account_id}:root")
        }
      },
      {
        Sid      = "Allow Macie to encrypt logs",
        Effect   = "Allow",
        Action   = "kms:GenerateDataKey",
        Resource = "*",
        Principal = {
          Service = "macie.amazonaws.com"
        }
      },
      {
        Sid      = "Allow alias creation during setup",
        Effect   = "Allow",
        Action   = "kms:CreateAlias",
        Resource = "*",
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.aws_account_id,
            "kms:ViaService"    = format("cloudformation.${local.aws_region}.amazonaws.com")
          }
        },
        Principal = {
          AWS = format("arn:${local.aws_partition}:iam::${local.aws_account_id}:root")
        }
      },
      {
        Sid      = "Allow Log Archive and Management account access",
        Effect   = "Allow",
        Action   = "kms:Decrypt",
        Resource = "*",
        Principal = {
          AWS = [
            format("arn:${local.aws_partition}:iam::${local.log_archive_account_id}:root"),
            format("arn:${local.aws_partition}:iam::${local.management_account_id}:root")
          ]
        }
      },
      {
        Sid    = "Allow account access",
        Effect = "Allow",
        Action = [
          "kms:DescribeKey",
          "kms:Decrypt"
        ],
        Resource = "*",
        Principal = {
          AWS = format("arn:${local.aws_partition}:iam::${local.aws_account_id}:root")
        }
      }
    ]
  })

  tags = {
    "sra-solution" = var.solution_name
  }
}

resource "aws_kms_alias" "macie_delivery_key_alias" {
  name          = "alias/${var.macie_delivery_key_alias}"
  target_key_id = aws_kms_key.macie_delivery_key.key_id
}

resource "aws_secretsmanager_secret" "macie_delivery_key_secret" {
  #checkov:skip=CKV_AWS_149: Ensure that Secrets Manager secret is encrypted using KMS CMK
  #checkov:skip=CKV2_AWS_57: Ensure Secrets Manager secrets should have automatic rotation enabled
  
  count       = var.secrets_key_alias_arn != "" ? 1 : 0
  name        = "sra/macie_org_delivery_key_arn"
  description = "Macie Delivery KMS Key ARN"
  kms_key_id  = var.secrets_key_alias_arn

  tags = {
    "sra-solution" = var.solution_name
  }
}

resource "aws_secretsmanager_secret_version" "macie_delivery_key_secret_version" {
  count     = var.secrets_key_alias_arn != "" ? 1 : 0
  secret_id = aws_secretsmanager_secret.macie_delivery_key_secret[0].id

  secret_string = jsonencode({
    MacieOrgDeliveryKeyArn = aws_kms_key.macie_delivery_key.arn
  })
}

resource "aws_secretsmanager_secret_policy" "macie_delivery_key_secret_policy" {
  count      = var.secrets_key_alias_arn != "" ? 1 : 0
  secret_arn = aws_secretsmanager_secret.macie_delivery_key_secret[0].arn

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "secretsmanager:GetSecretValue",
        Effect = "Allow",
        Principal = {
          AWS = [
            format("arn:${local.aws_partition}:iam::${local.management_account_id}:root")
          ]
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