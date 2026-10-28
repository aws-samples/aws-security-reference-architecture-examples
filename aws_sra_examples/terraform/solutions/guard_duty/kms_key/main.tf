########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
data "aws_iam_policy_document" "kms_policy" {
  statement {
    sid       = "EnableIAMUserPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowGuardDutyToEncryptLogs"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowAliasCreationDuringSetup"
    effect    = "Allow"
    actions   = ["kms:CreateAlias"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["cloudformation.${data.aws_region.current.name}.amazonaws.com"]
    }
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowLogArchiveAndManagementAccountAccess"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = [
        "arn:${data.aws_partition.current.partition}:iam::${var.log_archive_account_id}:root",
        "arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:root",
      ]
    }
  }

  statement {
    sid    = "AllowAccountAccess"
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:Decrypt"
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "guardduty_delivery_key" {
  description             = "SRA GuardDuty Delivery Key"
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_policy.json
  deletion_window_in_days = 30

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_kms_alias" "guardduty_delivery_key_alias" {
  name          = "alias/${var.guardduty_org_delivery_key_alias}"
  target_key_id = aws_kms_key.guardduty_delivery_key.key_id
}

resource "aws_secretsmanager_secret" "guardduty_delivery_key_secret" {
  count                   = var.create_secret ? 1 : 0
  name                    = "sra/guardduty_org_delivery_key_arn"
  description             = "GuardDuty Delivery KMS Key ARN"
  kms_key_id              = var.sra_secrets_key_alias_arn
  recovery_window_in_days = 30

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_secretsmanager_secret_rotation" "guardduty_delivery_key_rotation" {
  count               = var.create_secret ? 1 : 0
  secret_id           = aws_secretsmanager_secret.guardduty_delivery_key_secret[0].id
  rotation_lambda_arn = aws_lambda_function.rotation_lambda[0].arn

  rotation_rules {
    automatically_after_days = 90
  }
}

resource "aws_lambda_function" "rotation_lambda" {
  count         = var.create_secret ? 1 : 0
  function_name = "sra-guardduty-key-rotation"
  role          = aws_iam_role.lambda_role[0].arn
  handler       = "index.lambda_handler"
  runtime       = "python3.9"
  timeout       = 30

  environment {
    variables = {
      SECRET_ARN = aws_secretsmanager_secret.guardduty_delivery_key_secret[0].arn
    }
  }

  filename         = "${path.module}/lambda_function.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda_function.zip")
}

resource "aws_iam_role" "lambda_role" {
  count = var.create_secret ? 1 : 0
  name  = "sra-guardduty-key-rotation-role"

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
  count = var.create_secret ? 1 : 0
  name  = "sra-guardduty-key-rotation-policy"
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
        Resource = aws_secretsmanager_secret.guardduty_delivery_key_secret[0].arn
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

resource "aws_secretsmanager_secret_version" "secret_string" {
  count     = var.create_secret ? 1 : 0
  secret_id = aws_secretsmanager_secret.guardduty_delivery_key_secret[0].id
  secret_string = jsonencode({
    "GuardDutyDeliveryKeyArn" : aws_kms_key.guardduty_delivery_key.arn
  })
}

data "aws_iam_policy_document" "secretsmanager_policy" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    effect  = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:root"]
    }
    resources = ["*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "secretsmanager:VersionStage"
      values   = ["AWSCURRENT"]
    }
  }
}

resource "aws_secretsmanager_secret_policy" "guardduty_delivery_key_secret_policy" {
  count      = var.create_secret ? 1 : 0
  secret_arn = aws_secretsmanager_secret.guardduty_delivery_key_secret[0].arn
  policy     = data.aws_iam_policy_document.secretsmanager_policy.json
}
