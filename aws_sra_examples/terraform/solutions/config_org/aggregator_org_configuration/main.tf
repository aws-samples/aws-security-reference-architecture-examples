########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
resource "aws_iam_role" "r_config_aggregator_role" {
  name = var.p_aggregator_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
  ]

  tags = {
    "${var.p_sra_solution_name_key}" = var.p_sra_solution_name
  }
}

resource "aws_config_configuration_aggregator" "r_organization_config_aggregator" {
  name = var.p_aggregator_name

  account_aggregation_source {
    account_ids = [data.aws_caller_identity.current.account_id]
    all_regions = true
  }
}