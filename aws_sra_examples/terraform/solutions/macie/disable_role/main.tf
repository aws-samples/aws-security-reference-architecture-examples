########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
resource "aws_iam_role" "disable_macie_role" {
  name = var.disable_macie_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = format("arn:${data.aws_partition.current.partition}:iam::%s:root", var.management_account_id)
        },
        Action = "sts:AssumeRole",
        Condition = {
          StringEquals = {
            "aws:PrincipalArn" = format("arn:${data.aws_partition.current.partition}:iam::%s:role/%s", var.management_account_id, var.macie_org_lambda_role_name),
          }
        }
      }
    ]
  })

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_iam_policy" "disable_macie_policy" {
  name = "sra-macie-org-policy-disable"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "DisableMacie",
        Effect = "Allow",
        Action = [
          "macie2:DisableMacie",
          "macie2:GetAdministratorAccount",
        ],
        Resource = "*",
      }
    ]
  })

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_iam_policy_attachment" "disable_macie_role_attachment" {
  name       = "disable_macie_role_attachment"
  roles      = [aws_iam_role.disable_macie_role.name]
  policy_arn = aws_iam_policy.disable_macie_policy.arn
}
