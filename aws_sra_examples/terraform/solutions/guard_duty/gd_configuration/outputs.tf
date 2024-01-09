########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

# Results from lambda function
output "lambda_result_entry" {
  value = jsondecode(aws_lambda_invocation.lambda_invoke.result)
}