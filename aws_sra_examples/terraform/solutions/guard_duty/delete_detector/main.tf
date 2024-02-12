########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

data "aws_iam_policy_document" "delete_detector_policy" {
  statement {
    sid       = "GuardDutyNoResource"
    effect    = "Allow"
    actions   = ["guardduty:ListDetectors"]
    resources = ["*"]
  }

  statement {
    sid       = "GuardDutyWithResource"
    effect    = "Allow"
    actions   = ["guardduty:DeleteDetector"]
    resources = ["arn:${data.aws_partition.current.partition}:guardduty:*:${data.aws_caller_identity.current.account_id}:detector/*"]
  }
}

resource "aws_iam_policy" "delete_detector_policy" {
  name        = "sra-guardduty-org-policy-guardduty-delete"
  policy      = data.aws_iam_policy_document.delete_detector_policy.json
  description = "Policy for deleting GuardDuty detectors in the organization"
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

resource "aws_iam_role" "delete_detector_role" {
  name = var.delete_detector_role_name

  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_iam_role_policy_attachment" "delete_detector_policy_attachment" {
  policy_arn = aws_iam_policy.delete_detector_policy.arn
  role       = aws_iam_role.delete_detector_role.name
}