########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
resource "aws_kms_key" "r_config_delivery_key" {
  description         = "SRA Config Delivery Key"
  enable_key_rotation = true

  policy = data.aws_iam_policy_document.r_config_delivery_key_policy.json

  tags = {
    "${var.p_sra_solution_name_key}" = var.p_sra_solution_name
  }
}

resource "aws_kms_alias" "r_config_delivery_key_alias" {
  name          = "alias/${var.p_config_org_delivery_key_alias}"
  target_key_id = aws_kms_key.r_config_delivery_key.key_id
}

resource "aws_secretsmanager_secret" "r_config_delivery_key_secret" {
  #checkov:skip=CKV_AWS_149: Ensure that Secrets Manager secret is encrypted using KMS CMK
  #checkov:skip=CKV2_AWS_57: Ensure Secrets Manager secrets should have automatic rotation enabled

  name        = "sra/config_org_delivery_key_arn"
  description = "Config Delivery KMS Key ARN"

  tags = {
    "sra-solution" = var.p_sra_solution_name
  }
}

resource "aws_secretsmanager_secret_version" "r_config_delivery_key_secret_version" {
  secret_id = aws_secretsmanager_secret.r_config_delivery_key_secret.id

  secret_string = jsonencode({
    ConfigDeliveryKeyArn = aws_kms_key.r_config_delivery_key.arn
  })
}

resource "aws_secretsmanager_secret_policy" "r_config_delivery_key_secret_policy" {
  secret_arn = aws_secretsmanager_secret.r_config_delivery_key_secret.arn
  policy     = data.aws_iam_policy_document.r_config_delivery_key_secret_policy.json
}

data "aws_iam_policy_document" "r_config_delivery_key_policy" {
  statement {
    sid       = "EnableIAMUserPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowConfigToEncryptLogs"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }

  statement {
    sid     = "AllowAliasCreationDuringSetup"
    effect  = "Allow"
    actions = ["kms:CreateAlias"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = ["${data.aws_caller_identity.current.account_id}"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["cloudformation.${data.aws_region.current.name}.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowLogArchiveAndManagementAccountAccess"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${var.p_log_archive_account_id}:root",
        "arn:aws:iam::${var.p_management_account_id}:root"
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
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

data "aws_iam_policy_document" "r_config_delivery_key_secret_policy" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    effect    = "Allow"
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.p_management_account_id}:root"]
    }
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "secretsmanager:VersionStage"
      values   = ["AWSCURRENT"]
    }
  }
}