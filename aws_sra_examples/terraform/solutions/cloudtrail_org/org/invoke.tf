########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

locals {
  cloudwatch_log_group_arn      = var.create_cloudtrail_log_group == "true" ? aws_cloudwatch_log_group.cloudtrail_log_group[0].arn : ""
  cloudwatch_log_group_role_arn = var.create_cloudtrail_log_group == "true" ? aws_iam_role.cloudtrail_log_group_role[0].arn : ""
}

resource "aws_lambda_invocation" "lambda_invoke" {
  count         = var.disable_cloudtrail ? 0 : 1
  function_name = aws_lambda_function.cloudtrail_org_lambda_function.function_name

  input = jsonencode({
    "RequestType" : "Create",
    "ResourceType" : "Custom::LambdaCustomResource",
    "ResourceProperties" : {
      "ServiceToken" : "${aws_lambda_function.cloudtrail_org_lambda_function.arn}",
      "AWS_PARTITION" : "${data.aws_partition.current.partition}",
      "CLOUDTRAIL_NAME" : "${var.cloudtrail_name}",
      "CLOUDWATCH_LOG_GROUP_ARN" : "${local.cloudwatch_log_group_arn}:*",
      "CLOUDWATCH_LOG_GROUP_ROLE_ARN" : "${local.cloudwatch_log_group_role_arn}",
      "ENABLE_DATA_EVENTS_ONLY" : "${var.enable_data_events_only}",
      "ENABLE_LAMBDA_DATA_EVENTS" : "${var.enable_lambda_data_events}",
      "ENABLE_S3_DATA_EVENTS" : "${var.enable_s3_data_events}",
      "KMS_KEY_ID" : "${var.organization_cloudtrail_kms_key_id}",
      "S3_BUCKET_NAME" : "${var.cloudtrail_s3_bucket_name}",
      "SRA_SOLUTION_NAME" : "${var.sra_solution_name}",
      "DELEGATED_ADMIN_ACCOUNT_ID" : "${var.delegated_admin_account_id}",
    }
  })
}

resource "aws_lambda_invocation" "lambda_disable_invoke" {
  count         = var.disable_cloudtrail ? 1 : 0
  function_name = aws_lambda_function.cloudtrail_org_lambda_function.function_name

  input = jsonencode({
    "RequestType" : "Delete",
    "ResourceType" : "Custom::LambdaCustomResource",
    "ResourceProperties" : {
      "ServiceToken" : "${aws_lambda_function.cloudtrail_org_lambda_function.arn}",
      "AWS_PARTITION" : "${data.aws_partition.current.partition}",
      "CLOUDTRAIL_NAME" : "${var.cloudtrail_name}",
      "CLOUDWATCH_LOG_GROUP_ARN" : "${local.cloudwatch_log_group_arn}:*",
      "CLOUDWATCH_LOG_GROUP_ROLE_ARN" : "${local.cloudwatch_log_group_role_arn}",
      "ENABLE_DATA_EVENTS_ONLY" : "${var.enable_data_events_only}",
      "ENABLE_LAMBDA_DATA_EVENTS" : "${var.enable_lambda_data_events}",
      "ENABLE_S3_DATA_EVENTS" : "${var.enable_s3_data_events}",
      "KMS_KEY_ID" : "${var.organization_cloudtrail_kms_key_id}",
      "S3_BUCKET_NAME" : "${var.cloudtrail_s3_bucket_name}",
      "SRA_SOLUTION_NAME" : "${var.sra_solution_name}",
      "DELEGATED_ADMIN_ACCOUNT_ID" : "${var.delegated_admin_account_id}",
    }
  })
}
