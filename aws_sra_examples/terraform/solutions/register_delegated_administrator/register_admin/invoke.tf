########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_lambda_invocation" "lambda_invoke" {
  function_name = aws_lambda_function.register_delegated_admin_lambda_function.function_name

  input = jsonencode({
    "RequestType" : "Create",
    "ResourceType" : "Custom::LambdaCustomResource",
    "ResourceProperties" : {
      "ServiceToken" : "${aws_lambda_function.register_delegated_admin_lambda_function.arn}",
      "AWS_SERVICE_PRINCIPAL_LIST" : "${var.service_principal_list}",
      "DELEGATED_ADMIN_ACCOUNT_ID" : "${var.delegated_admin_account_id}",
    },
    "StackId" : "dummystackid/dummystack",
    "RequestId" : ""
  })
}