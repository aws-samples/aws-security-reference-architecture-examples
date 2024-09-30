########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_iam_role" "macie_org_configuration_role" {
  name = var.macie_org_configuration_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "sts:AssumeRole",
        Condition = {
          StringEquals = {
            "aws:PrincipalArn" = "arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:role/${var.macie_org_lambda_role_name}"
          }
        },
        Principal = {
          AWS = [
            "arn:${data.aws_partition.current.partition}:iam::${var.management_account_id}:root"
          ]
        }
      }
    ]
  })

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_iam_policy" "macie_org_policy" {
  name        = "sra-macie-org-policy"
  description = "Policy for Macie Org Configuration Role"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "Organizations",
        Effect   = "Allow",
        Action   = "organizations:ListAccounts",
        Resource = "*"
      },
      {
        Sid    = "MacieNoResource",
        Effect = "Allow",
        Action = [
          "macie2:DescribeBuckets",
          "macie2:DescribeOrganizationConfiguration",
          "macie2:DisableMacie",
          "macie2:DisableOrganizationAdminAccount",
          "macie2:DisassociateFromMasterAccount",
          "macie2:EnableMacie",
          "macie2:EnableOrganizationAdminAccount",
          "macie2:GetClassificationExportConfiguration",
          "macie2:GetMasterAccount",
          "macie2:ListMembers",
          "macie2:ListOrganizationAdminAccounts",
          "macie2:PutClassificationExportConfiguration",
          "macie2:UpdateMacieSession",
          "macie2:UpdateOrganizationConfiguration",
          "macie2:TagResource"
        ],
        Resource = "*"
      },
      {
        Sid    = "MacieMember",
        Effect = "Allow",
        Action = [
          "macie2:CreateMember",
          "macie2:DeleteMember",
          "macie2:DisassociateMember",
          "macie2:GetMember"
        ],
        Resource = "arn:${data.aws_partition.current.partition}:macie2:*:${var.audit_account_id}:*"
      },
      {
        Sid    = "MacieClassifications",
        Effect = "Allow",
        Action = [
          "macie2:CreateClassificationJob",
        ],
        Resource = "*",
        Condition = {
          StringEquals = {
            "aws:ResourceTag/sra-solution" = var.sra_solution_name
          }
        }        
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "macie_org_policy_attachment" {
  name       = "sra-macie-org-policy-attachment"
  roles      = [aws_iam_role.macie_org_configuration_role.name]
  policy_arn = aws_iam_policy.macie_org_policy.arn
}