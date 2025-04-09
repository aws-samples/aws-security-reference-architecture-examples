########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_iam_role" "sra_execution_role" {
  #checkov:skip=CKV_AWS_274:  Disallow IAM roles, users, and groups from using the AWS AdministratorAccess policy
  name = var.execution_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        AWS = format("arn:%s:iam::%s:root", var.aws_partition, var.management_account_id)
      }
    }]
  })

  tags = {
    "sra-solution" = var.solution_name
  }
}

resource "aws_iam_role_policy_attachment" "sra_execution_role_admin_policy" {
  role       = aws_iam_role.sra_execution_role.name
  policy_arn = format("arn:%s:iam::aws:policy/AdministratorAccess", var.aws_partition)
}