########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_lambda_invocation" "lambda_invoke" {
  function_name = aws_lambda_function.iam_password_policy_lambda_function.function_name

  input = jsonencode({
    "RequestType" : "Create",
    "ResourceType" : "Terraform",
    "ResourceProperties" : {
      "ServiceToken" : "${aws_lambda_function.iam_password_policy_lambda_function.arn}",
      "HARD_EXPIRY" : "${var.hard_expiry}",
      "MAX_PASSWORD_AGE" : "${var.max_password_age}",
      "PASSWORD_REUSE_PREVENTION" : "${var.password_reuse_prevention}",
      "MINIMUM_PASSWORD_LENGTH" : "${var.minimum_password_length}",
      "REQUIRE_LOWERCASE_CHARACTERS" : "${var.require_lowercase_characters}",
      "REQUIRE_NUMBERS" : "${var.require_numbers}",
      "REQUIRE_SYMBOLS" : "${var.require_symbols}",
      "REQUIRE_UPPERCASE_CHARACTERS" : "${var.require_uppercase_characters}",
      "ALLOW_USERS_TO_CHANGE_PASSWORD" : "${var.allow_users_to_change_password}",
    }
  })
}