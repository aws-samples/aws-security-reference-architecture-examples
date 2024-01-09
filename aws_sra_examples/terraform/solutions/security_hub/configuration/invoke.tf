########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

# resource "aws_lambda_invocation" "lambda_invoke" {
#   function_name = aws_lambda_function.guardduty_lambda_function.function_name

#   input = jsonencode({
#     "RequestType" : "Update",
#     "ResourceType" : "Custom::LambdaCustomResource",
#     "ResourceProperties" : {
#       "ServiceToken" : "${aws_lambda_function.guardduty_lambda_function.arn}",
#       "DELEGATED_ADMIN_ACCOUNT_ID" : "${var.audit_account_id}",
#       "SNS_TOPIC_ARN" : "${aws_sns_topic.guardduty_topic.arn}",
#       "KMS_KEY_ARN" : "${var.guardduty_org_delivery_kms_key_arn}",
#       "CONTROL_TOWER_REGIONS_ONLY" : "${var.control_tower_region_only}",
#       "DELETE_DETECTOR_ROLE_NAME" : "${var.delete_detector_role_name}",
#       "CONFIGURATION_ROLE_NAME" : "${var.guardduty_org_configuration_role_name}",
#       "DISABLE_GUARD_DUTY" : "${var.disable_guard_duty}",
#       "FINDING_PUBLISHING_FREQUENCY" : "${var.finding_publishing_frequency}",
#       "AUTO_ENABLE_S3_LOGS" : "${var.auto_enable_s3_logs}",
#       "PUBLISHING_DESTINATION_BUCKET_ARN" : "${var.publishing_destination_bucket_arn}",
#       "ENABLED_REGIONS" : "${var.enabled_regions}"
#     }
#   })
# }