########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
locals {
  create_lambda_log_group         = var.create_lambda_log_group == "true"
  use_kms_key                     = var.lambda_log_group_kms_key != ""
  not_global_region_us_east_1     = data.aws_region.current.name != "us-east-1"
  compliance_frequency_single_day = var.compliance_frequency == 1
  create_dlq_alarm                = var.sra_alarm_email != ""
  partition                       = data.aws_partition.current.partition
  current_account                 = data.aws_caller_identity.current.account_id
  current_region                  = data.aws_region.current.name
  use_graviton = contains(
    [
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
    ],
    data.aws_region.current.name,
  )
  src_path = "${path.root}/../../solutions/inspector/inspector_org/lambda/src/"
}

########################################################################
# Lambda IAM Role
########################################################################
resource "aws_iam_role" "inspector_org_lambda_role" {
  name = var.inspector_org_lambda_role_name

  assume_role_policy = data.aws_iam_policy_document.inspector_org_assume_role.json

  tags = {
    sra-solution = var.sra_solution_name
  }
}

########################################################################
# Lambda Policies Documents
########################################################################
data "aws_iam_policy_document" "inspector_org_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}
########################################################################
# Lambda Policies
########################################################################
data "aws_iam_policy_document" "cloudformation" {
  statement {
    sid       = "CloudFormation"
    effect    = "Allow"
    actions   = ["cloudformation:ListStackInstances"]
    resources = ["arn:${local.partition}:cloudformation:${local.current_region}:${local.current_account}:stackset/AWSControlTowerBP-*"]
  }
}

data "aws_iam_policy_document" "ssm_access" {
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:${local.partition}:ssm:${local.current_region}:${local.current_account}:parameter/sra*"]
  }
}

data "aws_iam_policy_document" "inspector" {
  statement {
    sid    = "AllowAllTest"
    effect = "Allow"
    actions = [
      "inspector2:ListDelegatedAdminAccounts",
      "inspector2:DisableDelegatedAdminAccount",
      "inspector2:BatchGetAccountStatus",
      "inspector2:EnableDelegatedAdminAccount",
      "inspector2:Enable",
      "inspector2:Disable",
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "iam" {
  statement {
    sid       = "AssumeRole"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:${local.partition}:iam::*:role/${var.inspector_configuration_role_name}"]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgId"
      values   = [var.organization_id]
    }
  }

  statement {
    sid       = "AllowReadIamActions"
    effect    = "Allow"
    actions   = ["iam:GetRole"]
    resources = ["arn:${local.partition}:iam::${local.current_account}:role/*"]
  }

  statement {
    sid     = "AllowCreateServiceLinkedRole"
    effect  = "Allow"
    actions = ["iam:CreateServiceLinkedRole"]
    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"
      values   = ["inspector2.amazonaws.com"]
    }
    resources = ["arn:${local.partition}:iam::${local.current_account}:role/aws-service-role/inspector2.amazonaws.com/AWSServiceRoleForAmazonInspector2"]
  }

  statement {
    sid       = "AllowPolicyActions"
    effect    = "Allow"
    actions   = ["iam:PutRolePolicy"]
    resources = ["arn:${local.partition}:iam::${local.current_account}:role/aws-service-role/inspector2.amazonaws.com/AWSServiceRoleForAmazonInspector2"]
  }

  statement {
    sid       = "AllowDeleteServiceLinkedRole"
    effect    = "Allow"
    actions   = ["iam:DeleteServiceLinkedRole"]
    resources = ["arn:${local.partition}:iam::${local.current_account}:role/aws-service-role/inspector2.amazonaws.com/AWSServiceRoleForAmazonInspector2"]
  }
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "CreateLogGroupAndEvents"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:${local.partition}:logs:${local.current_region}:${local.current_account}:log-group:/aws/lambda/${var.inspector_org_lambda_function_name}:log-stream:*"]
  }
}

data "aws_iam_policy_document" "organizations" {
  statement {
    effect = "Allow"
    sid    = "OrganizationsReadAccess"
    actions = [
      "organizations:DescribeOrganization",
      "organizations:ListAWSServiceAccessForOrganization",
      "organizations:ListAccounts",
      "organizations:ListDelegatedAdministrators",
    ]
    resources = ["*"]
  }

  statement {
    effect  = "Allow"
    sid     = "AWSServiceAccess"
    actions = ["organizations:DisableAWSServiceAccess", "organizations:EnableAWSServiceAccess"]
    condition {
      test     = "StringLikeIfExists"
      variable = "organizations:ServicePrincipal"
      values   = ["inspector2.amazonaws.com"]
    }
    resources = ["*"]
  }

  statement {
    effect  = "Allow"
    sid     = "RegisterDeregisterDelegatedAdministrator"
    actions = ["organizations:DeregisterDelegatedAdministrator", "organizations:RegisterDelegatedAdministrator"]
    condition {
      test     = "StringLikeIfExists"
      variable = "organizations:ServicePrincipal"
      values   = ["inspector2.amazonaws.com"]
    }
    resources = ["arn:${local.partition}:organizations::*:account/o-*/*"]
  }
}

data "aws_iam_policy_document" "sns" {
  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish", "sns:PublishBatch"]
    resources = [aws_sns_topic.inspector_org_topic.arn]
  }
}

data "aws_iam_policy_document" "sqs" {
  statement {
    sid       = "SQSSendMessage"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.inspector_org_dlq.arn]
  }
}

########################################################################
# Lambda Policies
########################################################################
resource "aws_iam_policy" "cloudformation_policy" {
  name        = "sra-inspector-org-policy-cloudformation"
  description = "IAM policy for CloudFormation"
  policy      = data.aws_iam_policy_document.cloudformation.json
}

resource "aws_iam_policy" "ssm_access_policy" {
  name        = "sra-inspector-ssm-access"
  description = "IAM policy for SSM access"
  policy      = data.aws_iam_policy_document.ssm_access.json
}

resource "aws_iam_policy" "inspector_policy" {
  name        = "sra-inspector-org-policy-inspector"
  description = "IAM policy for Amazon Inspector"
  policy      = data.aws_iam_policy_document.inspector.json
}

resource "aws_iam_policy" "iam_policy" {
  name        = "sra-inspector-org-policy-iam"
  description = "IAM policy for IAM roles"
  policy      = data.aws_iam_policy_document.iam.json
}

resource "aws_iam_policy" "logs_policy" {
  name        = "sra-inspector-org-policy-logs"
  description = "IAM policy for CloudWatch Logs"
  policy      = data.aws_iam_policy_document.logs.json
}

resource "aws_iam_policy" "organizations_policy" {
  name        = "sra-inspector-org-policy-organizations"
  description = "IAM policy for AWS Organizations"
  policy      = data.aws_iam_policy_document.organizations.json
}

resource "aws_iam_policy" "sns_policy" {
  name        = "sra-inspector-org-policy-sns"
  description = "IAM policy for SNS"
  policy      = data.aws_iam_policy_document.sns.json
}

resource "aws_iam_policy" "sqs_policy" {
  name        = "sra-inspector-org-policy-sqs"
  description = "IAM policy for SQS"
  policy      = data.aws_iam_policy_document.sqs.json
}

########################################################################
# Lambda Policies Attachment
########################################################################
resource "aws_iam_role_policy_attachment" "cloudformation_attachment" {
  policy_arn = aws_iam_policy.cloudformation_policy.arn
  role       = aws_iam_role.inspector_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "ssm_access_attachment" {
  policy_arn = aws_iam_policy.ssm_access_policy.arn
  role       = aws_iam_role.inspector_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "inspector_attachment" {
  policy_arn = aws_iam_policy.inspector_policy.arn
  role       = aws_iam_role.inspector_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "iam_attachment" {
  policy_arn = aws_iam_policy.iam_policy.arn
  role       = aws_iam_role.inspector_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "logs_attachment" {
  policy_arn = aws_iam_policy.logs_policy.arn
  role       = aws_iam_role.inspector_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "organizations_attachment" {
  policy_arn = aws_iam_policy.organizations_policy.arn
  role       = aws_iam_role.inspector_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "sns_attachment" {
  policy_arn = aws_iam_policy.sns_policy.arn
  role       = aws_iam_role.inspector_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "sqs_attachment" {
  policy_arn = aws_iam_policy.sqs_policy.arn
  role       = aws_iam_role.inspector_org_lambda_role.name
}

########################################################################
# Cloud Watch Log Group
########################################################################
resource "aws_cloudwatch_log_group" "inspector_org_lambda_log_group" {
  count = local.create_lambda_log_group ? 1 : 0

  name              = "/aws/lambda/${var.inspector_org_lambda_function_name}"
  retention_in_days = var.lambda_log_group_retention
  kms_key_id        = local.use_kms_key ? var.lambda_log_group_kms_key : null
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
resource "aws_lambda_function" "inspector_org_lambda_function" {
  function_name = var.inspector_org_lambda_function_name
  description   = "Configure Inspector for the Organization"
  role          = aws_iam_role.inspector_org_lambda_role.arn
  handler       = "app.lambda_handler"
  memory_size   = 512
  runtime       = "python3.9"
  timeout       = 900


  source_code_hash = data.archive_file.zipped_lambda.output_base64sha256
  filename         = data.archive_file.zipped_lambda.output_path

  architectures = [local.use_graviton ? "arm64" : "x86_64"]

  depends_on = [
    aws_iam_role_policy_attachment.cloudformation_attachment,
    aws_iam_role_policy_attachment.iam_attachment,
    aws_iam_role_policy_attachment.inspector_attachment,
    aws_iam_role_policy_attachment.logs_attachment,
    aws_iam_role_policy_attachment.organizations_attachment,
    aws_iam_role_policy_attachment.sns_attachment,
    aws_iam_role_policy_attachment.sqs_attachment,
    aws_iam_role_policy_attachment.ssm_access_attachment,
  ]

  dead_letter_config {
    target_arn = aws_sqs_queue.inspector_org_dlq.arn
  }


  # Environment variables
  environment {
    variables = {
      LOG_LEVEL                  = var.lambda_log_level
      AWS_PARTITION              = local.partition
      CONFIGURATION_ROLE_NAME    = var.inspector_configuration_role_name
      CONTROL_TOWER_REGIONS_ONLY = var.inspector_control_tower_regions_only
      DELEGATED_ADMIN_ACCOUNT_ID = var.delegated_admin_account_id
      ENABLED_REGIONS            = var.enabled_regions
      MANAGEMENT_ACCOUNT_ID      = local.current_account
      SNS_TOPIC_ARN              = aws_sns_topic.inspector_org_topic.arn
      SCAN_COMPONENTS            = var.scan_components
      ECR_SCAN_DURATION          = var.ecr_rescan_duration
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
resource "aws_sns_topic" "inspector_org_topic" {
  name              = "${var.sra_solution_name}-configuration"
  kms_master_key_id = "arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/aws/sns"

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

# AWS Lambda Permission for SNS Topic
resource "aws_lambda_permission" "inspector_org_topic_lambda_permission" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.inspector_org_lambda_function.arn
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.inspector_org_topic.arn
}

# AWS SNS Subscription
resource "aws_sns_topic_subscription" "inspector_org_topic_subscription" {
  endpoint  = aws_lambda_function.inspector_org_lambda_function.arn
  protocol  = "lambda"
  topic_arn = aws_sns_topic.inspector_org_topic.arn
}

########################################################################
# DLQ
########################################################################
# AWS SQS Queue
resource "aws_sqs_queue" "inspector_org_dlq" {
  name              = "${var.sra_solution_name}-dlq"
  kms_master_key_id = "alias/aws/sqs"

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

# AWS SQS Queue Policy
data "aws_iam_policy_document" "inspector_org_dlq_policy_document" {
  statement {
    sid       = "AllowSNSPublish"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.inspector_org_dlq.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_lambda_function.inspector_org_lambda_function.arn]
    }

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sqs_queue_policy" "inspector_org_dlq_policy" {
  queue_url = aws_sqs_queue.inspector_org_dlq.id
  policy    = data.aws_iam_policy_document.inspector_org_dlq_policy_document.json
}

# AWS SNS Topic for DLQ Alarm
resource "aws_sns_topic" "inspector_org_dlq_alarm_topic" {
  count             = local.create_dlq_alarm ? 1 : 0
  name              = "${var.sra_solution_name}-dlq-alarm"
  kms_master_key_id = "arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/aws/sns"

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_sns_topic_subscription" "inspector_org_dlq_alarm_subscription" {
  count     = local.create_dlq_alarm ? 1 : 0
  topic_arn = aws_sns_topic.inspector_org_dlq_alarm_topic[0].arn
  protocol  = "email"
  endpoint  = var.sra_alarm_email
}

# AWS CloudWatch Alarm for DLQ
resource "aws_cloudwatch_metric_alarm" "inspector_org_dlq_alarm" {
  count             = local.create_dlq_alarm ? 1 : 0
  alarm_name        = "${var.sra_solution_name}-dlq-alarm"
  alarm_description = "SRA DLQ alarm if the queue depth is 1"
  namespace         = "AWS/SQS"
  metric_name       = "ApproximateNumberOfMessagesVisible"
  dimensions = {
    QueueName = aws_sqs_queue.inspector_org_dlq.name
  }
  statistic                 = "Sum"
  period                    = 300
  evaluation_periods        = 1
  threshold                 = 1
  comparison_operator       = "GreaterThanThreshold"
  alarm_actions             = [aws_sns_topic.inspector_org_dlq_alarm_topic[0].arn]
  insufficient_data_actions = [aws_sns_topic.inspector_org_dlq_alarm_topic[0].arn]
}

########################################################################
# Events
########################################################################
# Permission for Scheduled Compliance Rule to Invoke Lambda
resource "aws_lambda_permission" "permission_for_scheduled_compliance_rule_to_invoke_lambda" {
  function_name = aws_lambda_function.inspector_org_lambda_function.arn
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scheduled_compliance_rule.arn
}

# AWS EventBridge Rule for Scheduled Organization Compliance
resource "aws_cloudwatch_event_rule" "scheduled_compliance_rule" {
  name                = "${var.control_tower_lifecycle_rule_name}-organization-compliance"
  description         = "SRA Inspector Trigger for scheduled organization compliance"
  schedule_expression = var.compliance_frequency == 1 ? "rate(${var.compliance_frequency} day)" : "rate(${var.compliance_frequency} days)"
}

resource "aws_cloudwatch_event_target" "scheduled_compliance_rule_target" {
  rule      = aws_cloudwatch_event_rule.scheduled_compliance_rule.name
  target_id = var.inspector_org_lambda_function_name
  arn       = aws_lambda_function.inspector_org_lambda_function.arn
}

# AWS IAM Role for Cross-Region Event Rule
resource "aws_iam_role" "cross_region_event_rule_role" {
  count = data.aws_region.current.name != "us-east-1" ? 1 : 0
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

data "aws_iam_policy_document" "sra_inspector_events" {
  statement {
    effect    = "Allow"
    actions   = ["events:PutEvents"]
    resources = ["arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:event-bus/default"]
  }
}
resource "aws_iam_policy" "sra_inspector_events" {
  name   = "sra-account-org-inspector-policy-events"
  policy = data.aws_iam_policy_document.sra_inspector_events.json
}
resource "aws_iam_policy_attachment" "sra_inspector_events" {
  count      = data.aws_region.current.name != "us-east-1" ? 1 : 0
  name       = "sra-account-org-inspector-policy-events-attachment"
  roles      = [aws_iam_role.cross_region_event_rule_role[0].name]
  policy_arn = aws_iam_policy.sra_inspector_events.arn
}
