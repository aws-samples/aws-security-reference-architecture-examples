########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_iam_role" "configuration_role" {
  name               = var.guardduty_org_configuration_role_name
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_iam_policy" "organizations_policy" {
  name        = "sra-guardduty-org-policy-organizations"
  policy      = data.aws_iam_policy_document.organizations_policy.json
  description = "Policy for organizations"
}

resource "aws_iam_policy" "guardduty_policy" {
  name        = "sra-guardduty-org-policy-guardduty"
  policy      = data.aws_iam_policy_document.guardduty_policy.json
  description = "Policy for GuardDuty"
}

resource "aws_iam_policy" "iam_policy" {
  name        = "sra-guardduty-org-policy-iam"
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
      values   = ["arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:role/${var.guardduty_org_lambda_role_name}"]
    }
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

data "aws_iam_policy_document" "guardduty_policy" {
  statement {
    sid       = "GuardDutyNoResource"
    effect    = "Allow"
    actions   = ["guardduty:ListDetectors"]
    resources = ["*"]
  }

  statement {
    sid    = "GuardDutyWithResource"
    effect = "Allow"
    actions = [
      "guardduty:CreateMembers",
      "guardduty:CreatePublishingDestination",
      "guardduty:DeleteDetector",
      "guardduty:DeleteMembers",
      "guardduty:DisassociateMembers",
      "guardduty:ListMembers",
      "guardduty:ListPublishingDestinations",
      "guardduty:UpdateDetector",
      "guardduty:UpdateMemberDetectors",
      "guardduty:UpdateOrganizationConfiguration",
      "guardduty:UpdatePublishingDestination",
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:guardduty:*:${data.aws_caller_identity.current.account_id}:/detector/*",
      "arn:${data.aws_partition.current.partition}:guardduty:*:${data.aws_caller_identity.current.account_id}:detector/*",
    ]
  }
}

data "aws_iam_policy_document" "iam_policy" {
  #checkov:skip=CKV_AWS_111: Ensure IAM policies does not allow write access without constraints
  statement {
    sid       = "AllowReadIamActions"
    effect    = "Allow"
    actions   = ["iam:GetRole"]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/*"]
  }

  statement {
    sid    = "AllowCreateDeleteServiceLinkedRole"
    effect = "Allow"
    actions = [
      "iam:CreateServiceLinkedRole",
      "iam:DeleteServiceLinkedRole",
    ]
    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"
      values   = ["guardduty.amazonaws.com", "malware-protection.guardduty.amazonaws.com"]
    }
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role//malware-protection.guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDutyMalwareProtection"
    ]
  }

  statement {
    sid    = "AllowEnableMalwareProtection"
    effect = "Allow"
    actions = [
      "organizations:EnableAWSServiceAccess",
      "organizations:RegisterDelegatedAdministrator",
      "organizations:ListDelegatedAdministrators",
      "organizations:ListAWSServiceAccessForOrganization",
      "organizations:DescribeOrganizationalUnit",
      "organizations:DescribeAccount",
      "organizations:DescribeOrganization"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowGetRoleMalwareProtection"
    effect = "Allow"
    actions = [
      "iam:GetRole",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role//malware-protection.guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDutyMalwareProtection"]
  }

  statement {
    sid    = "AllowPolicyActions"
    effect = "Allow"
    actions = [
      "iam:DeleteRolePolicy",
      "iam:PutRolePolicy",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty"]
  }
}

resource "aws_iam_role_policy_attachment" "organizations_attachment" {
  policy_arn = aws_iam_policy.organizations_policy.arn
  role       = aws_iam_role.configuration_role.name
}

resource "aws_iam_role_policy_attachment" "guardduty_attachment" {
  policy_arn = aws_iam_policy.guardduty_policy.arn
  role       = aws_iam_role.configuration_role.name
}

resource "aws_iam_role_policy_attachment" "iam_attachment" {
  policy_arn = aws_iam_policy.iam_policy.arn
  role       = aws_iam_role.configuration_role.name
}
