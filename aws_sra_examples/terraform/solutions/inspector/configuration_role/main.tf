########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
resource "aws_iam_role" "inspector_configuration_role" {
  name               = var.inspector_configuration_role_name
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json

  tags = {
    "sra-solution" = var.sra_solution_name
  }
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
      values   = ["arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:role/${var.inspector_org_lambda_role_name}"]
    }
  }
}


data "aws_iam_policy_document" "organizations_policy" {
  statement {
    actions   = ["organizations:ListAccounts"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "inspector_policy" {
  statement {
    actions = [
      "inspector2:UpdateOrganizationConfiguration",
      "inspector2:Disable",
      "inspector2:DescribeOrganizationConfiguration",
      "inspector2:GetMember",
      "inspector2:DisassociateMember",
      "inspector2:BatchGetAccountStatus",
      "inspector2:AssociateMember",
      "inspector2:Enable",
      "inspector2:UpdateConfiguration",
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "iam_policy" {
  statement {
    actions = ["iam:GetRole"]
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/*",
    ]
  }

  statement {
    actions = ["iam:CreateServiceLinkedRole"]
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/inspector2.amazonaws.com/AWSServiceRoleForAmazonInspector2",
    ]

    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"
      values   = ["inspector2.amazonaws.com"]
    }
  }

  statement {
    actions = ["iam:PutRolePolicy"]
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/inspector2.amazonaws.com/AWSServiceRoleForAmazonInspector2",
    ]
  }

  statement {
    actions = ["iam:DeleteServiceLinkedRole"]
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/inspector2.amazonaws.com/AWSServiceRoleForAmazonInspector2",
    ]
  }
}

resource "aws_iam_policy" "organizations_policy" {
  name        = "sra-inspector-org-organizations-policy"
  description = "IAM policy for Organizations"
  policy      = data.aws_iam_policy_document.organizations_policy.json
}

resource "aws_iam_policy" "inspector_policy" {
  name        = "sra-inspector-org-inspector-policy"
  description = "IAM policy for Inspector"
  policy      = data.aws_iam_policy_document.inspector_policy.json
}

resource "aws_iam_policy" "iam_policy" {
  name        = "sra-inspector-org-iam-policy"
  description = "IAM policy for IAM"
  policy      = data.aws_iam_policy_document.iam_policy.json
}

# Attach policies to the IAM role
resource "aws_iam_role_policy_attachment" "organizations_attachment" {
  policy_arn = aws_iam_policy.organizations_policy.arn
  role       = aws_iam_role.inspector_configuration_role.name
}

resource "aws_iam_role_policy_attachment" "inspector_attachment" {
  policy_arn = aws_iam_policy.inspector_policy.arn
  role       = aws_iam_role.inspector_configuration_role.name
}

resource "aws_iam_role_policy_attachment" "iam_attachment" {
  policy_arn = aws_iam_policy.iam_policy.arn
  role       = aws_iam_role.inspector_configuration_role.name
}