########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
locals {
  #TODO: Figure out?
  graviton_regions = [
    "ap-northeast-1",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "us-east-1",
    "us-east-2",
    "us-west-2",
  ]
  create_dlq_alarm = var.sra_alarm_email != "" ? true : false
  src_path         = "${path.root}/../../solutions/securityhub/securityhub_org/lambda/src/"
}

########################################################################
# Lambda Policies Documents
########################################################################

data "aws_iam_policy_document" "security_hub_org_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "security_hub_org_lambda_role" {
  name        = var.security_hub_org_lambda_role_name
  description = "Role for '${var.security_hub_org_lambda_role_name}' Lambda function"

  assume_role_policy = data.aws_iam_policy_document.security_hub_org_assume_role.json

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

data "aws_iam_policy_document" "security_hub_org_policy_cloudformation" {
  statement {
    sid       = "CloudFormation"
    effect    = "Allow"
    actions   = ["cloudformation:ListStackInstances"]
    resources = ["arn:${data.aws_partition.current.partition}:cloudformation:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:stackset/AWSControlTowerBP-*"]
  }
}

data "aws_iam_policy_document" "security_hub_org_policy_ssm_access" {
  statement {
    sid    = "SSMAccess"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/sra*"]
  }
}

data "aws_iam_policy_document" "security_hub_org_policy_securityhub" {
  #checkov:skip=CKV_AWS_111: Ensure IAM policies does not allow write access without constraints
  #checkov:skip=CKV_AWS_356: Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions

  statement {
    sid    = "SecurityHubNoResource"
    effect = "Allow"
    actions = [
      "securityhub:DisableOrganizationAdminAccount",
      "securityhub:EnableOrganizationAdminAccount",
      "securityhub:ListOrganizationAdminAccounts",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "SecurityHubWithResource"
    effect = "Allow"
    actions = [
      "securityhub:EnableSecurityHub",
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:securityhub:*:${data.aws_caller_identity.current.account_id}:hub/default",
      "arn:${data.aws_partition.current.partition}:securityhub:*:${data.aws_caller_identity.current.account_id}:/accounts",
    ]
  }
}

data "aws_iam_policy_document" "security_hub_org_policy_iam" {
  statement {
    sid       = "AllowReadIamActions"
    effect    = "Allow"
    actions   = ["iam:GetRole"]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/*"]
  }

  statement {
    sid     = "AllowCreateServiceLinkedRole"
    effect  = "Allow"
    actions = ["iam:CreateServiceLinkedRole"]
    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"
      values   = ["securityhub.amazonaws.com"]
    }
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/securityhub.amazonaws.com/AWSServiceRoleForSecurityHub"]
  }

  statement {
    sid       = "AllowPolicyActions"
    effect    = "Allow"
    actions   = ["iam:PutRolePolicy"]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/securityhub.amazonaws.com/AWSServiceRoleForSecurityHub"]
  }

  statement {
    sid     = "AssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgId"
      values   = [var.organization_id]
    }
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::*:role/${var.security_hub_configuration_role_name}",
    ]
  }
}

data "aws_iam_policy_document" "security_hub_org_policy_logs" {
  statement {
    sid       = "CreateLogGroupAndEvents"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.security_hub_org_lambda_function_name}:log-stream:*"]
  }
}

data "aws_iam_policy_document" "security_hub_org_policy_organizations" {
  statement {
    sid    = "OrganizationsReadAccess"
    effect = "Allow"
    actions = [
      "organizations:DescribeOrganization",
      "organizations:ListAWSServiceAccessForOrganization",
      "organizations:ListAccounts",
      "organizations:ListDelegatedAdministrators",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AWSServiceAccess"
    effect = "Allow"
    actions = [
      "organizations:DisableAWSServiceAccess",
      "organizations:EnableAWSServiceAccess",
    ]
    condition {
      test     = "StringLikeIfExists"
      variable = "organizations:ServicePrincipal"
      values   = ["securityhub.amazonaws.com"]
    }
    resources = ["*"]
  }

  statement {
    sid    = "RegisterDeregisterDelegatedAdministrator"
    effect = "Allow"
    actions = [
      "organizations:DeregisterDelegatedAdministrator",
      "organizations:RegisterDelegatedAdministrator",
    ]
    condition {
      test     = "StringLikeIfExists"
      variable = "organizations:ServicePrincipal"
      values   = ["securityhub.amazonaws.com"]
    }
    resources = ["arn:${data.aws_partition.current.partition}:organizations::*:account/o-*/*"]
  }
}

data "aws_iam_policy_document" "security_hub_org_policy_sns" {
  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish", "sns:PublishBatch"]
    resources = [aws_sns_topic.securityhub_org_topic.arn]
  }
}

data "aws_iam_policy_document" "security_hub_org_policy_sqs" {
  statement {
    sid       = "SQSSendMessage"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.securityhub_org_dlq.arn]
  }
}

########################################################################
# Lambda Policies
########################################################################

resource "aws_iam_policy" "security_hub_org_policy_logs" {
  name   = "sra-security-hub-org-policy-logs"
  policy = data.aws_iam_policy_document.security_hub_org_policy_logs.json
}

resource "aws_iam_policy" "security_hub_org_policy_securityhub" {
  name   = "sra-security-hub-org-policy-securityhub"
  policy = data.aws_iam_policy_document.security_hub_org_policy_securityhub.json
}

resource "aws_iam_policy" "security_hub_org_policy_iam" {
  name   = "sra-security-hub-org-policy-iam"
  policy = data.aws_iam_policy_document.security_hub_org_policy_iam.json
}

resource "aws_iam_policy" "security_hub_org_policy_cloudformation" {
  name   = "sra-security-hub-org-policy-cloudformation"
  policy = data.aws_iam_policy_document.security_hub_org_policy_cloudformation.json
}

resource "aws_iam_policy" "security_hub_org_policy_ssm_access" {
  name   = "sra-security-hub-org-policy-ssm-access"
  policy = data.aws_iam_policy_document.security_hub_org_policy_ssm_access.json
}

resource "aws_iam_policy" "security_hub_org_policy_organizations" {
  name   = "sra-security-hub-org-policy-organizations-lambda"
  policy = data.aws_iam_policy_document.security_hub_org_policy_organizations.json
}

resource "aws_iam_policy" "security_hub_org_policy_sns" {
  name   = "sra-security-hub-org-policy-sns"
  policy = data.aws_iam_policy_document.security_hub_org_policy_sns.json
}

resource "aws_iam_policy" "security_hub_org_policy_sqs" {
  name   = "sra-security-hub-org-policy-sqs"
  policy = data.aws_iam_policy_document.security_hub_org_policy_sqs.json
}

########################################################################
# Lambda Attachment
########################################################################

resource "aws_iam_policy_attachment" "security_hub_org_policy_attachment_logs" {
  name       = "sra-security-hub-org-policy-attachment-logs"
  roles      = [aws_iam_role.security_hub_org_lambda_role.name]
  policy_arn = aws_iam_policy.security_hub_org_policy_logs.arn
}

resource "aws_iam_policy_attachment" "security_hub_org_policy_attachment_securityhub" {
  name       = "sra-security-hub-org-policy-attachment-securityhub"
  roles      = [aws_iam_role.security_hub_org_lambda_role.name]
  policy_arn = aws_iam_policy.security_hub_org_policy_securityhub.arn
}

resource "aws_iam_policy_attachment" "security_hub_org_policy_attachment_iam" {
  name       = "sra-security-hub-org-policy-attachment-iam"
  roles      = [aws_iam_role.security_hub_org_lambda_role.name]
  policy_arn = aws_iam_policy.security_hub_org_policy_iam.arn
}

resource "aws_iam_policy_attachment" "security_hub_org_policy_attachment_cloudformation" {
  name       = "sra-security-hub-org-policy-attachment-cloudformation"
  roles      = [aws_iam_role.security_hub_org_lambda_role.name]
  policy_arn = aws_iam_policy.security_hub_org_policy_cloudformation.arn
}

resource "aws_iam_policy_attachment" "security_hub_org_policy_attachment_ssm_access" {
  name       = "sra-security-hub-org-policy-attachment-ssm-access"
  roles      = [aws_iam_role.security_hub_org_lambda_role.name]
  policy_arn = aws_iam_policy.security_hub_org_policy_ssm_access.arn
}

resource "aws_iam_policy_attachment" "security_hub_org_policy_attachment_organizations" {
  name       = "sra-securityhub-org-policy-attachment-organizations"
  roles      = [aws_iam_role.security_hub_org_lambda_role.name]
  policy_arn = aws_iam_policy.security_hub_org_policy_organizations.arn
}

resource "aws_iam_policy_attachment" "security_hub_org_policy_attachment_sns" {
  name       = "sra-securityhub-org-policy-attachment-sns"
  roles      = [aws_iam_role.security_hub_org_lambda_role.name]
  policy_arn = aws_iam_policy.security_hub_org_policy_sns.arn
}

resource "aws_iam_policy_attachment" "security_hub_org_policy_attachment_sqs" {
  name       = "sra-securityhub-org-policy-attachment-sqs"
  roles      = [aws_iam_role.security_hub_org_lambda_role.name]
  policy_arn = aws_iam_policy.security_hub_org_policy_sqs.arn
}

########################################################################
# Cloud Watch Log Group
########################################################################

resource "aws_cloudwatch_log_group" "rSecurityHubOrgLambdaLogGroup" {
  count             = var.create_lambda_log_group ? 1 : 0
  name              = "/aws/lambda/${var.security_hub_org_lambda_function_name}"
  retention_in_days = var.lambda_log_group_retention

  kms_key_id = var.lambda_log_group_kms_key != null ? var.lambda_log_group_kms_key : null
}

########################################################################
# Lambda Function
########################################################################

data "archive_file" "hash_check" {
  type        = "zip"
  source_dir  = local.src_path
  output_path = "${path.module}/lambda/lambda_function.zip"
  excludes    = ["lambda_function.zip, data.zip"]
}

resource "null_resource" "package_lambda" {
  triggers = {
    src_hash = "${data.archive_file.hash_check.output_sha}"
  }

  provisioner "local-exec" {
    command = <<EOF
    rm -rf ${path.module}/lambda/package && mkdir ${path.module}/lambda/package
    python3 -m pip install -r ${local.src_path}requirements.txt -t ${path.module}/lambda/package
    python3 -m pip install -r ${local.src_path}../../layer/boto3/package.txt -t ${path.module}/lambda/package
    cp ${local.src_path}*.py ${path.module}/lambda/package/
    cd ${path.module}/lambda/package
    zip -r ../lambda_function.zip .
    EOF
  }
}

data "archive_file" "zipped_lambda" {
  depends_on  = [null_resource.package_lambda]
  type        = "zip"
  source_dir  = "${path.module}/lambda/package"
  output_path = "${path.module}/lambda/lambda_function.zip"
  excludes    = ["lambda_function.zip, data.zip"]
}

# main function
resource "aws_lambda_function" "security_hub_lambda_function" {
  #checkov:skip=CKV_AWS_272: Ensure AWS Lambda function is configured to validate code-signing
  #checkov:skip=CKV_AWS_116: Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) 
  #checkov:skip=CKV_AWS_173: Check encryption settings for Lambda environment variable
  #checkov:skip=CKV_AWS_115: Ensure that AWS Lambda function is configured for function-level concurrent execution limit
  #checkov:skip=CKV_AWS_117: Ensure that AWS Lambda function is configured inside a VPC
  #checkov:skip=CKV_AWS_50: X-Ray tracing is enabled for Lambda

  function_name = var.security_hub_org_lambda_function_name
  description   = "Configure Security Hub for the Organization"
  role          = aws_iam_role.security_hub_org_lambda_role.arn
  memory_size   = 512
  handler       = "app.terraform_handler"
  runtime       = "python3.9"
  timeout       = 900

  source_code_hash = data.archive_file.zipped_lambda.output_base64sha256
  filename         = data.archive_file.zipped_lambda.output_path

  dead_letter_config {
    target_arn = aws_sqs_queue.securityhub_org_dlq.arn
  }

  environment {
    variables = {
      LOG_LEVEL                               = var.lambda_log_level
      AWS_PARTITION                           = data.aws_partition.current.partition
      CIS_VERSION                             = var.cis_standard_version
      CONFIGURATION_ROLE_NAME                 = var.security_hub_configuration_role_name
      CONTROL_TOWER_REGIONS_ONLY              = var.securityhub_control_tower_regions_only
      DELEGATED_ADMIN_ACCOUNT_ID              = var.delegated_admin_account_id
      DISABLE_SECURITY_HUB                    = var.disable_security_hub
      ENABLED_REGIONS                         = var.enabled_regions
      ENABLE_CIS_STANDARD                     = var.enable_cis_standard
      ENABLE_PCI_STANDARD                     = var.enable_pci_standard
      ENABLE_NIST_STANDARD                    = var.enable_nist_standard
      ENABLE_SECURITY_BEST_PRACTICES_STANDARD = var.enable_security_best_practices_standard
      HOME_REGION                             = data.aws_region.current.name
      MANAGEMENT_ACCOUNT_ID                   = data.aws_caller_identity.current.account_id
      PCI_VERSION                             = var.pci_standard_version
      NIST_VERSION                            = var.nist_standard_version
      REGION_LINKING_MODE                     = var.region_linking_mode
      SECURITY_BEST_PRACTICES_VERSION         = var.security_best_practices_standard_version
      SNS_TOPIC_ARN                           = aws_sns_topic.securityhub_org_topic.arn
    }
  }

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

########################################################################
# Topics
########################################################################
# AWS SNS Topic
resource "aws_sns_topic" "securityhub_org_topic" {
  name              = "${var.sra_solution_name}-configuration"
  kms_master_key_id = "arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/aws/sns"

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

# AWS Lambda Permission for SNS Topic
resource "aws_lambda_permission" "securityhub_org_topic_lambda_permission" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_hub_lambda_function.arn
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.securityhub_org_topic.arn
}

# AWS SNS Subscription
resource "aws_sns_topic_subscription" "securityhub_org_topic_subscription" {
  endpoint  = aws_lambda_function.security_hub_lambda_function.arn
  protocol  = "lambda"
  topic_arn = aws_sns_topic.securityhub_org_topic.arn
}

# AWS SQS Queue
resource "aws_sqs_queue" "securityhub_org_dlq" {
  # checkov:skip=CKV2_AWS_73: Using default KMS key
  name              = "${var.sra_solution_name}-dlq"
  kms_master_key_id = "alias/aws/sqs"

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

# AWS SQS Queue Policy
data "aws_iam_policy_document" "securityhub_org_dlq_policy_document" {
  statement {
    sid       = "AllowSNSPublish"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.securityhub_org_dlq.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_lambda_function.security_hub_lambda_function.arn]
    }

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sqs_queue_policy" "securityhub_org_dlq_policy" {
  queue_url = aws_sqs_queue.securityhub_org_dlq.id
  policy    = data.aws_iam_policy_document.securityhub_org_dlq_policy_document.json
}

# AWS SNS Topic for DLQ Alarm
resource "aws_sns_topic" "securityhub_org_dlq_alarm_topic" {
  count             = local.create_dlq_alarm ? 1 : 0
  name              = "${var.sra_solution_name}-dlq-alarm"
  kms_master_key_id = "arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/aws/sns"

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_sns_topic_subscription" "securityhub_org_dlq_alarm_subscription" {
  count     = local.create_dlq_alarm ? 1 : 0
  topic_arn = aws_sns_topic.securityhub_org_dlq_alarm_topic[0].arn
  protocol  = "email"
  endpoint  = var.sra_alarm_email
}

# AWS CloudWatch Alarm for DLQ
resource "aws_cloudwatch_metric_alarm" "securityhub_org_dlq_alarm" {
  count             = local.create_dlq_alarm ? 1 : 0
  alarm_name        = "${var.sra_solution_name}-dlq-alarm"
  alarm_description = "SRA DLQ alarm if the queue depth is 1"
  namespace         = "AWS/SQS"
  metric_name       = "ApproximateNumberOfMessagesVisible"
  dimensions = {
    QueueName = aws_sqs_queue.securityhub_org_dlq.name
  }
  statistic                 = "Sum"
  period                    = 300
  evaluation_periods        = 1
  threshold                 = 1
  comparison_operator       = "GreaterThanThreshold"
  alarm_actions             = [aws_sns_topic.securityhub_org_dlq_alarm_topic[0].arn]
  insufficient_data_actions = [aws_sns_topic.securityhub_org_dlq_alarm_topic[0].arn]
}

########################################################################
# Events
########################################################################
# AWS EventBridge Rule for Organizations Update
resource "aws_cloudwatch_event_rule" "organizations_rule" {
  name        = "${var.control_tower_lifecycle_rule_name}-org-update"
  description = "SRA Security Hub Trigger on Organizations update"
  event_pattern = jsonencode({
    source      = ["aws.organizations"],
    detail_type = ["AWS API Call via CloudTrail"],
    detail = {
      eventSource = ["organizations.amazonaws.com"],
      eventName   = ["AcceptHandshake", "CreateAccountResult"]
    }
  })
}

resource "aws_cloudwatch_event_target" "organizations_rule_target" {
  rule      = aws_cloudwatch_event_rule.organizations_rule.name
  target_id = var.security_hub_org_lambda_function_name
  arn       = aws_lambda_function.security_hub_lambda_function.arn
}

# Permission for Organizations Rule to Invoke Lambda
resource "aws_lambda_permission" "permission_for_organizations_rule_to_invoke_lambda" {
  function_name = aws_lambda_function.security_hub_lambda_function.arn
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.organizations_rule.arn
}

# Permission for Scheduled Compliance Rule to Invoke Lambda
resource "aws_lambda_permission" "permission_for_scheduled_compliance_rule_to_invoke_lambda" {
  function_name = aws_lambda_function.security_hub_lambda_function.arn
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scheduled_compliance_rule.arn
}

# AWS EventBridge Rule for Scheduled Organization Compliance
resource "aws_cloudwatch_event_rule" "scheduled_compliance_rule" {
  name                = "${var.control_tower_lifecycle_rule_name}-organization-compliance"
  description         = "SRA Security Hub Trigger for scheduled organization compliance"
  schedule_expression = var.compliance_frequency == 1 ? "rate(${var.compliance_frequency} day)" : "rate(${var.compliance_frequency} days)"
}

resource "aws_cloudwatch_event_target" "scheduled_compliance_rule_target" {
  rule      = aws_cloudwatch_event_rule.scheduled_compliance_rule.name
  target_id = var.security_hub_org_lambda_function_name
  arn       = aws_lambda_function.security_hub_lambda_function.arn
}

# AWS IAM Role for Cross-Region Event Rule
resource "aws_iam_role" "cross_region_event_rule_role" {
  count = var.region_linking_mode != "GLOBAL" && data.aws_region.current.name != "us-east-1" ? 1 : 0
  name  = var.event_rule_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "sts:AssumeRole",
        Principal = {
          Service = ["events.amazonaws.com"]
        }
      }
    ]
  })
}

data "aws_iam_policy_document" "sra_securityhub_events" {
  statement {
    effect    = "Allow"
    actions   = ["events:PutEvents"]
    resources = ["arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:event-bus/default"]
  }
}
resource "aws_iam_policy" "sra_securityhub_events" {
  name   = "sra-securityhub-events"
  policy = data.aws_iam_policy_document.sra_securityhub_events.json
}
resource "aws_iam_policy_attachment" "sra_securityhub_events" {
  count      = var.region_linking_mode != "GLOBAL" && data.aws_region.current.name != "us-east-1" ? 1 : 0
  name       = "sra-securityhub-events-attachment"
  roles      = [aws_iam_role.cross_region_event_rule_role[0].name]
  policy_arn = aws_iam_policy.sra_securityhub_events.arn
}

# AWS EventBridge Policy for Org Default Event Bus
data "aws_iam_policy_document" "org_default_event_bus_policy" {
  statement {
    sid    = "AllowOrgDefaultBusAccess"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["events:PutEvents"]
    resources = ["arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:event-bus/default"]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgId"
      values   = [var.organization_id]
    }
  }
}
resource "aws_cloudwatch_event_bus_policy" "org_default_event_bus_policy" {
  policy = data.aws_iam_policy_document.org_default_event_bus_policy.json
}

# AWS EventBridge Rule for Recorder Start
resource "aws_cloudwatch_event_rule" "recorder_start_rule" {
  name        = var.sechub_rule_name
  description = "SRA Security Hub solution Event Bridge Rule for config recorder"
  event_pattern = jsonencode({
    source      = ["aws.config"],
    detail_type = ["AWS API Call via CloudTrail"],
    detail = {
      eventSource = ["config.amazonaws.com"],
      eventName   = ["StartConfigurationRecorder"]
    }
  })
}
resource "aws_cloudwatch_event_target" "recorder_start_rule_target" {
  rule      = aws_cloudwatch_event_rule.recorder_start_rule.name
  target_id = var.security_hub_org_lambda_function_name
  arn       = aws_lambda_function.security_hub_lambda_function.arn
}

# Permission for Recorder Start Rule to Invoke Lambda
resource "aws_lambda_permission" "permission_for_recorder_start_rule_to_invoke_lambda" {
  function_name = var.security_hub_org_lambda_function_name
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.recorder_start_rule.arn
}
