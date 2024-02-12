########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_accessanalyzer_analyzer" "account_access_analyzer" {
  analyzer_name = "${var.access_analyzer_name_prefix}-${data.aws_caller_identity.current.account_id}"

  tags = {
    "sra-solution" = var.sra_solution_name
  }

  type = "ACCOUNT"
}