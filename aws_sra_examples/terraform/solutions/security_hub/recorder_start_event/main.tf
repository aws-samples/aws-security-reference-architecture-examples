########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_iam_role" "event_bridge_rule_role" {
  name = var.event_rule_role_name

  assume_role_policy = data.aws_iam_policy_document.event_bridge_rule_assume_role.json

  tags = {
    Name = var.event_rule_role_name
  }
}

data "aws_iam_policy_document" "event_bridge_rule_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "event_bridge_policy" {
  statement {
    effect    = "Allow"
    actions   = ["events:PutEvents"]
    resources = ["arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.name}:${var.management_account_id}:event-bus/default"]
  }
}

resource "aws_iam_policy" "event_bridge_policy" {
  name        = "sra-events-policy"
  description = "Policy for forwarding config recorder start events"

  policy = data.aws_iam_policy_document.event_bridge_policy.json
}

resource "aws_iam_policy_attachment" "event_bridge_policy_attachment" {
  name       = "sra-events-policy-attachment"
  policy_arn = aws_iam_policy.event_bridge_policy.arn
  roles      = [aws_iam_role.event_bridge_rule_role.name]
}

resource "aws_cloudwatch_event_rule" "organizations_rule" {
  name        = "${var.sra_solution_name}-forward-config-recorder-start"
  description = "SRA Security Hub Forward config recorder start events to home region"

  event_pattern = jsonencode({
    source        = ["aws.config"],
    "detail-type" = ["AWS API Call via CloudTrail"],
    detail = {
      eventSource = ["config.amazonaws.com"],
      eventName   = ["StartConfigurationRecorder"]
    }
  })
}

resource "aws_cloudwatch_event_target" "recorder_start_rule_target" {
  rule = aws_cloudwatch_event_rule.organizations_rule.name

  target_id = "${var.sra_solution_name}-config-recorder-start-to-home-region"
  arn       = "arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.name}:${var.management_account_id}:event-bus/default"
  role_arn  = aws_iam_role.event_bridge_rule_role.arn
}
