########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_lambda_invocation" "lambda_invoke" {
  function_name = aws_lambda_function.management_account_parameters.function_name

  input = jsonencode({
    "ResourceType" : "Custom::LambdaCustomResource",
    "ResourceProperties" : {
      "ServiceToken" : "${aws_lambda_function.management_account_parameters.arn}",
      "TAG_KEY" : "sra-solution",
      "TAG_VALUE" : "sra-common-prerequisites",
      "CONTROL_TOWER" : "${var.control_tower}",
      "OTHER_REGIONS" : "${var.governed_regions}",
      "OTHER_SECURITY_ACCT" : "${var.security_account_id}",
      "OTHER_LOG_ARCHIVE_ACCT" : "${var.log_archive_account_id}",
      "Action" : "Created",
    }
  })

  lifecycle_scope = "CREATE_ONLY"
}