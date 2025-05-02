########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_lambda_invocation" "lambda_invoke" {
  function_name = aws_lambda_function.guardduty_lambda_function.function_name

  input = jsonencode({
    "RequestType" : "Update",
    "ResourceType" : "Custom::LambdaCustomResource",
    "ResourceProperties" : {
      "RequestType" : "Update",
      "ServiceToken" : "${aws_lambda_function.guardduty_lambda_function.arn}",
      "DELEGATED_ADMIN_ACCOUNT_ID" : "${var.audit_account_id}",
      "SNS_TOPIC_ARN" : "${aws_sns_topic.guardduty_topic.arn}",
      "KMS_KEY_ARN" : "${var.guardduty_org_delivery_kms_key_arn}",
      "CONTROL_TOWER_REGIONS_ONLY" : "${var.guardduty_control_tower_regions_only}",
      "DELETE_DETECTOR_ROLE_NAME" : "${var.delete_detector_role_name}",
      "CONFIGURATION_ROLE_NAME" : "${var.guardduty_org_configuration_role_name}",
      "DISABLE_GUARD_DUTY" : "${var.disable_guard_duty}",
      "FINDING_PUBLISHING_FREQUENCY" : "${var.finding_publishing_frequency}",
      "AUTO_ENABLE_S3_LOGS" : "${var.auto_enable_s3_logs}",
      "PUBLISHING_DESTINATION_BUCKET_ARN" : "${var.publishing_destination_bucket_arn}",
      "ENABLED_REGIONS" : "${var.enabled_regions}",
      "ENABLE_EKS_AUDIT_LOGS" : "${var.enable_kubernetes_audit_logs}",
      "AUTO_ENABLE_MALWARE_PROTECTION" : "${var.enable_malware_protection}",
      "ENABLE_RDS_LOGIN_EVENTS" : "${var.enable_rds_login_events}",
      "ENABLE_RUNTIME_MONITORING" : "${var.enable_runtime_monitoring}",
      "ENABLE_ECS_FARGATE_AGENT_MANAGEMENT" : "${var.enable_ecs_fargate_agent_management}",
      "ENABLE_EC2_AGENT_MANAGEMENT" : "${var.enable_ec2_agent_management}",
      "ENABLE_EKS_ADDON_MANAGEMENT" : "${var.enable_eks_addon_management}",
      "ENABLE_LAMBDA_NETWORK_LOGS" : "${var.enable_lambda_network_logs}",
    }
  })
}
