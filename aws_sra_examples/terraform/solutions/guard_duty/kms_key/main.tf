########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
data "aws_iam_policy_document" "kms_policy" {
  #checkov:skip=CKV_AWS_111: Ensure IAM policies does not allow write access without constraints
  #checkov:skip=CKV_AWS_356: Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions
  #checkov:skip=CKV_AWS_109: Ensure IAM policies does not allow permissions management / resource exposure without constraints

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
      values   = ["${data.aws_caller_identity.current.account_id}"]
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
    sid       = "AllowLogArchiveAndManagementAccountAccess"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
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
    sid       = "AllowAccountAccess"
    effect    = "Allow"
    actions   = ["kms:DescribeKey", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "guardduty_delivery_key" {
  description         = "SRA GuardDuty Delivery Key"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.kms_policy.json

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_kms_alias" "guardduty_delivery_key_alias" {
  name          = "alias/${var.guardduty_org_delivery_key_alias}"
  target_key_id = aws_kms_key.guardduty_delivery_key.key_id
}

resource "aws_secretsmanager_secret" "guardduty_delivery_key_secret" {
  #checkov:skip=CKV2_AWS_57: Ensure Secrets Manager secrets should have automatic rotation enabled
  
  count       = var.create_secret ? 1 : 0
  name        = "sra/guardduty_org_delivery_key_arn"
  description = "GuardDuty Delivery KMS Key ARN"

  kms_key_id = var.sra_secrets_key_alias_arn

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_secretsmanager_secret_version" "secret_string" {
  count = var.create_secret ? 1 : 0

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