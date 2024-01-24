########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_lambda_invocation" "lambda_invoke" {
  count         = var.disable_macie ? 0 : 1
  function_name = aws_lambda_function.r_macie_org_lambda_function.function_name

  input = jsonencode({
    "RequestType" : "Create",
    "ResourceType" : "Custom::LambdaCustomResource",
    "ResourceProperties" : {
      "ServiceToken" : "${aws_lambda_function.r_macie_org_lambda_function.arn}",
      "DELEGATED_ADMIN_ACCOUNT_ID" : "${var.p_delegated_admin_account_id}",
      "DISABLE_MACIE" : "${var.disable_macie}",
      "DISABLE_MACIE_ROLE_NAME" : "${var.disable_macie_role_name}",
      "PUBLISHING_DESTINATION_BUCKET_NAME" : "${var.p_publishing_destination_bucket_name}",
      "SNS_TOPIC_ARN" : "${aws_sns_topic.r_macie_org_topic.arn}",
      "KMS_KEY_ARN" : "${var.p_kms_key_arn}",
      "CONTROL_TOWER_REGIONS_ONLY" : "${var.p_control_tower_regions_only}",
      "MANAGEMENT_ACCOUNT_ID" : "${var.p_management_account_id}",
      "CONFIGURATION_ROLE_NAME" : "${var.p_macie_org_configuration_role_name}",
      "FINDING_PUBLISHING_FREQUENCY" : "${var.p_finding_publishing_frequency}",
      "ENABLED_REGIONS" : "${var.p_enabled_regions}"
    }
  })
}

resource "aws_lambda_invocation" "lambda_disable_invoke" {
  count         = var.disable_macie ? 1 : 0
  function_name = aws_lambda_function.r_macie_org_lambda_function.function_name

  input = jsonencode({
    "RequestType" : "Update",
    "ResourceType" : "Custom::LambdaCustomResource",
    "ResourceProperties" : {
      "ServiceToken" : "${aws_lambda_function.r_macie_org_lambda_function.arn}",
      "DELEGATED_ADMIN_ACCOUNT_ID" : "${var.p_delegated_admin_account_id}",
      "DISABLE_MACIE" : "${var.disable_macie}",
      "DISABLE_MACIE_ROLE_NAME" : "${var.disable_macie_role_name}",
      "PUBLISHING_DESTINATION_BUCKET_NAME" : "${var.p_publishing_destination_bucket_name}",
      "SNS_TOPIC_ARN" : "${aws_sns_topic.r_macie_org_topic.arn}",
      "KMS_KEY_ARN" : "${var.p_kms_key_arn}",
      "CONTROL_TOWER_REGIONS_ONLY" : "${var.p_control_tower_regions_only}",
      "MANAGEMENT_ACCOUNT_ID" : "${var.p_management_account_id}",
      "CONFIGURATION_ROLE_NAME" : "${var.p_macie_org_configuration_role_name}",
      "FINDING_PUBLISHING_FREQUENCY" : "${var.p_finding_publishing_frequency}",
      "ENABLED_REGIONS" : "${var.p_enabled_regions}"
    }
  })
}
