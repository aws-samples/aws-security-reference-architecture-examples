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
        AWS = "arn:${var.aws_partition}:iam::${var.management_account_id}:root"
      }
    }]
  })

  managed_policy_arns = [
    "arn:${var.aws_partition}:iam::aws:policy/AdministratorAccess"
  ]

  tags = {
    "sra-solution" = var.solution_name
  }
}