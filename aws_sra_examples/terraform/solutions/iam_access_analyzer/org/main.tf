########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_accessanalyzer_analyzer" "rOrganizationAccessAnalyzer" {
  analyzer_name = var.org_access_analyzer_name

  tags = {
    "sra-solution" = var.sra_solution_name
  }

  type = "ORGANIZATION"
}