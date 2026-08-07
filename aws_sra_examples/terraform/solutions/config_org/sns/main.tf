########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
resource "aws_sns_topic" "config_org_topic" {
  name              = var.p_config_topic_name
  display_name      = var.p_config_topic_name
  kms_master_key_id = "arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/${var.p_config_org_sns_key_alias}"
  tags = {
    "sra-solution" = var.p_sra_solution_name
  }
}

resource "aws_sns_topic_policy" "sns_all_configuration_topic_policy" {
  arn    = aws_sns_topic.config_org_topic.arn
  policy = data.aws_iam_policy_document.sns_policy.json
}

data "aws_iam_policy_document" "sns_policy" {
  statement {
    actions   = ["sns:Publish"]
    effect    = "Allow"
    resources = [aws_sns_topic.config_org_topic.arn]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic_subscription" "sns_all_configuration_email_notification" {
  count     = var.p_subscribe_to_configuration_topic ? 1 : 0
  topic_arn = aws_sns_topic.config_org_topic.arn
  protocol  = "email"
  endpoint  = var.p_configuration_email
}