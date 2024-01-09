########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_lambda_invocation" "lambda_invoke" {
  function_name = aws_lambda_function.inspector_org_lambda_function.function_name

  input = jsonencode({
    "RequestType" : "Update",
    "ResourceType" : "Terraform",
    "ResourceProperties" : {
      "ServiceToken" : "${aws_lambda_function.inspector_org_lambda_function.arn}",
      "LOG_LEVEL" : "${var.lambda_log_level}",
      "AWS_PARTITION" : "${local.partition}",
      "CONFIGURATION_ROLE_NAME" : "${var.inspector_configuration_role_name}",
      "CONTROL_TOWER_REGIONS_ONLY" : "${var.control_tower_regions_only}",
      "DELEGATED_ADMIN_ACCOUNT_ID" : "${var.delegated_admin_account_id}",
      "ENABLED_REGIONS" : "${var.enabled_regions}",
      "MANAGEMENT_ACCOUNT_ID" : "${local.current_account}",
      "SNS_TOPIC_ARN" : "${aws_sns_topic.inspector_org_topic.arn}",
      "SCAN_COMPONENTS" : "${var.scan_components}",
      "ECR_SCAN_DURATION" : "${var.ecr_rescan_duration}",
    }
  })
}