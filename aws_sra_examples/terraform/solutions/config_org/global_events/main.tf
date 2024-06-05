########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
resource "aws_cloudwatch_event_rule" "r_organizations_rule" {
  name        = "${var.p_sra_solution_name}-forward-org-events"
  description = "SRA Config Forward Organizations events to home region."

  event_pattern = jsonencode({
    source = ["aws.organizations"],
    "detail-type" = ["AWS Service Event via CloudTrail"],
    detail = {
      eventSource = ["organizations.amazonaws.com"],
      eventName = [
        "AcceptHandshake",
        "CreateAccountResult"
      ]
    }
  })

  role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.p_event_rule_role_name}"
  state    = "ENABLED"
}

resource "aws_cloudwatch_event_target" "r_organizations_rule_target" {
  rule      = aws_cloudwatch_event_rule.r_organizations_rule.name
  arn       = "arn:aws:events:${var.p_home_region}:${data.aws_caller_identity.current.account_id}:event-bus/default"
  target_id = "${var.p_sra_solution_name}-org-events-to-home-region"
  role_arn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.p_event_rule_role_name}"
}