########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_lambda_invocation" "new_lambda_invoke" {
  function_name = aws_lambda_function.r_config_org_lambda_function.function_name

  input = jsonencode({
    "Terraform" : "true",
    "RequestType" : "Create",
    "ResourceType" : "Custom::LambdaCustomResource",
    "ResourceProperties" : {
      "ServiceToken" : "${aws_lambda_function.r_config_org_lambda_function.arn}",
      "AUDIT_ACCOUNT" : "${var.p_audit_account_id}",
      "CONFIGURATION_ROLE_NAME" : "${var.p_config_configuration_role_name}",
      "CONTROL_TOWER_REGIONS_ONLY" : "${var.p_control_tower_regions_only}",
      "ENABLED_REGIONS" : "${var.p_enabled_regions}",
      "ALL_SUPPORTED" : "${var.p_all_supported}",
      "INCLUDE_GLOBAL_RESOURCE_TYPES" : "${var.p_include_global_resource_types}",
      "DELIVERY_CHANNEL_NAME" : "${var.p_delivery_channel_name}",
      "FREQUENCY" : "${var.p_frequency}",
      "RESOURCE_TYPES" : "${var.p_resource_types}",
      "RECORDER_NAME" : "${var.p_recorder_name}",
      "KMS_KEY_SECRET_NAME" : "${var.p_kms_key_arn_secret_name}",
      "HOME_REGION" : "${var.p_home_region}",
      "SNS_TOPIC_ARN_FANOUT" : "${aws_sns_topic.r_config_org_topic.arn}",
      "PUBLISHING_DESTINATION_BUCKET_ARN" : "arn:aws:s3:::${var.p_publishing_destination_bucket_name}"
    }
  })
}