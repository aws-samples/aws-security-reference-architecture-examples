########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
locals {
  is_audit_account = data.aws_caller_identity.current.account_id == var.delegated_admin_account_id
}

resource "aws_iam_role" "configuration_role" {
  name               = var.securityhub_configuration_role_name
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_iam_policy" "config_policy" {
  name        = "sra-securityhub-org-policy-config"
  policy      = data.aws_iam_policy_document.config_policy.json
  description = "Policy for Config"
}

resource "aws_iam_policy" "organizations_policy" {
  name        = "sra-securityhub-org-policy-organizations"
  policy      = data.aws_iam_policy_document.organizations_policy.json
  description = "Policy for organizations"
}

resource "aws_iam_policy" "securityhub_policy" {
  name        = "sra-securityhub-org-policy-securityhub"
  policy      = data.aws_iam_policy_document.securityhub_policy.json
  description = "Policy for SecurityHub"
}

resource "aws_iam_policy" "securityhub_delegated_admin_policy" {
  count = local.is_audit_account ? 1 : 0

  name        = "sra-securityhub-org-policy-securityhub-delegated-admin"
  policy      = data.aws_iam_policy_document.securityhub_delegated_adminpolicy[0].json
  description = "Policy for SecurityHub Delegated Admin"
}

resource "aws_iam_policy" "iam_policy" {
  name        = "sra-securityhub-org-policy-iam"
  policy      = data.aws_iam_policy_document.iam_policy.json
  description = "Policy for IAM"
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:root"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:role/${var.securityhub_org_lambda_role_name}"]
    }
  }
}

data "aws_iam_policy_document" "config_policy" {
  statement {
    sid    = "AllowConfigDescribeActions"
    effect = "Allow"
    actions = [
      "config:DescribeConfigurationRecorderStatus",
      "config:DescribeConfigurationRecorders"
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "organizations_policy" {
  statement {
    sid       = "OrganizationsListAccounts"
    effect    = "Allow"
    actions   = ["organizations:ListAccounts"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "securityhub_policy" {
  statement {
    sid       = "SecurityHubWildcardResource"
    effect    = "Allow"
    actions   = ["securityhub:ListFindingAggregators"]
    resources = ["*"]
  }

  statement {
    sid    = "SecurityHubWithResource"
    effect = "Allow"
    actions = [
      "securityhub:BatchDisableStandards",
      "securityhub:BatchEnableStandards",
      "securityhub:CreateActionTarget",
      "securityhub:DisableImportFindingsForProduct",
      "securityhub:DisableSecurityHub",
      "securityhub:DisassociateMembers",
      "securityhub:EnableImportFindingsForProduct",
      "securityhub:EnableSecurityHub",
      "securityhub:GetEnabledStandards",
      "securityhub:GetFindings",
      "securityhub:GetMasterAccount",
      "securityhub:ListMembers",
      "securityhub:TagResource",
      "securityhub:UntagResource",
      "securityhub:UpdateSecurityHubConfiguration",
      "securityhub:UpdateStandardsControl"
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:securityhub:*:${data.aws_caller_identity.current.account_id}:hub/default",
      "arn:${data.aws_partition.current.partition}:securityhub:*:${data.aws_caller_identity.current.account_id}:/accounts"
    ]
  }

  statement {
    sid    = "SecurityHubFindingAggregator"
    effect = "Allow"
    actions = [
      "securityhub:CreateFindingAggregator",
      "securityhub:DeleteFindingAggregator",
      "securityhub:GetFindingAggregator",
      "securityhub:UpdateFindingAggregator"
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:securityhub:*:${data.aws_caller_identity.current.account_id}:finding-aggregator/*",
      "arn:${data.aws_partition.current.partition}:securityhub:*:${data.aws_caller_identity.current.account_id}:/findingAggregator/*"
    ]
  }
}

data "aws_iam_policy_document" "securityhub_delegated_adminpolicy" {
  count = local.is_audit_account ? 1 : 0

  statement {
    sid    = "SecurityHubDelegatedAdminActions"
    effect = "Allow"
    actions = [
      "securityhub:CreateMembers",
      "securityhub:DeleteMembers",
      "securityhub:GetMembers",
      "securityhub:UpdateOrganizationConfiguration"
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:securityhub:*:${data.aws_caller_identity.current.account_id}:hub/default",
      "arn:${data.aws_partition.current.partition}:securityhub:*:${data.aws_caller_identity.current.account_id}:/accounts"
    ]
  }
}

data "aws_iam_policy_document" "iam_policy" {
  statement {
    sid       = "AllowReadIamActions"
    effect    = "Allow"
    actions   = ["iam:GetRole"]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/*"]
  }

  statement {
    sid     = "AllowCreateServiceLinkedRole"
    effect  = "Allow"
    actions = ["iam:CreateServiceLinkedRole"]
    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"
      values   = ["securityhub.amazonaws.com"]
    }
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/securityhub.amazonaws.com/AWSServiceRoleForSecurityHub"]
  }

  statement {
    sid       = "AllowPolicyActions"
    effect    = "Allow"
    actions   = ["iam:PutRolePolicy"]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/securityhub.amazonaws.com/AWSServiceRoleForSecurityHub"]
  }
}

resource "aws_iam_role_policy_attachment" "config_attachment" {
  policy_arn = aws_iam_policy.config_policy.arn
  role       = aws_iam_role.configuration_role.name
}

resource "aws_iam_role_policy_attachment" "organizations_attachment" {
  policy_arn = aws_iam_policy.organizations_policy.arn
  role       = aws_iam_role.configuration_role.name
}

resource "aws_iam_role_policy_attachment" "securityhub_attachment" {
  policy_arn = aws_iam_policy.securityhub_policy.arn
  role       = aws_iam_role.configuration_role.name
}

resource "aws_iam_role_policy_attachment" "securityhub_delegated_admin_attachment" {
  count = local.is_audit_account ? 1 : 0

  policy_arn = aws_iam_policy.securityhub_delegated_admin_policy[0].arn
  role       = aws_iam_role.configuration_role.name
}


resource "aws_iam_role_policy_attachment" "iam_attachment" {
  policy_arn = aws_iam_policy.iam_policy.arn
  role       = aws_iam_role.configuration_role.name
}
