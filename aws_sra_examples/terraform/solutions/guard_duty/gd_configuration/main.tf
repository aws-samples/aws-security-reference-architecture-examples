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
  account_id       = data.aws_caller_identity.current.account_id
  region           = data.aws_region.current.name
  create_dlq_alarm = var.sra_alarm_email != "" ? true : false
  src_path         = "${path.root}/../../solutions/guardduty/guardduty_org/lambda/src/"
}

########################################################################
# Lambda Policies Documents
########################################################################

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "guardduty_lambda_role" {
  name        = var.guardduty_lambda_role_name
  description = "Role for '${var.guardduty_lambda_role_name}' Lambda function"

  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

data "aws_iam_policy_document" "sra_guardduty_org_policy_cloudformation" {
  statement {
    sid       = "CloudFormation"
    effect    = "Allow"
    actions   = ["cloudformation:ListStackInstances"]
    resources = ["arn:${data.aws_partition.current.partition}:cloudformation:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:stackset/AWSControlTowerBP-*"]
  }
}

data "aws_iam_policy_document" "sra_guardduty_org_policy_acct" {
  #checkov:skip=CKV_AWS_356: Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions
  statement {
    sid       = "AcctListRegions"
    effect    = "Allow"
    actions   = ["account:ListRegions"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "sra_guardduty_org_policy_ssm_access" {
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

data "aws_iam_policy_document" "sra_guardduty_org_policy_guardduty" {
  statement {
    sid    = "GuardDutyNoResource"
    effect = "Allow"
    actions = [
      "guardduty:DisableOrganizationAdminAccount",
      "guardduty:EnableOrganizationAdminAccount",
      "guardduty:ListDetectors",
      "guardduty:ListOrganizationAdminAccounts",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "GuardDutyWithResource"
    effect = "Allow"
    actions = [
      "guardduty:DeleteDetector",
      "guardduty:ListMembers",
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:guardduty:*:${data.aws_caller_identity.current.account_id}:detector/*",
      "arn:${data.aws_partition.current.partition}:guardduty:*:${data.aws_caller_identity.current.account_id}:/detector/*",
    ]
  }
}

data "aws_iam_policy_document" "sra_guardduty_org_policy_iam" {
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
      values   = ["guardduty.amazonaws.com"]
    }
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty"]
  }

  statement {
    sid       = "AllowPolicyActions"
    effect    = "Allow"
    actions   = ["iam:PutRolePolicy"]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty"]
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
      "arn:${data.aws_partition.current.partition}:iam::*:role/${var.delete_detector_role_name}",
      "arn:${data.aws_partition.current.partition}:iam::*:role/${var.guardduty_org_configuration_role_name}",
    ]
  }
}

data "aws_iam_policy_document" "sra_guardduty_org_policy_logs" {
  statement {
    sid       = "CreateLogGroupAndEvents"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.guardduty_lambda_function_name}:log-stream:*"]
  }
}

data "aws_iam_policy_document" "sra_guardduty_org_policy_organizations" {
  #checkov:skip=CKV_AWS_111: Ensure IAM policies does not allow write access without constraints
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
    sid    = "RegisterDeregisterDelegatedAdministrator"
    effect = "Allow"
    actions = [
      "organizations:DeregisterDelegatedAdministrator",
      "organizations:DisableAWSServiceAccess",
      "organizations:EnableAWSServiceAccess",
      "organizations:RegisterDelegatedAdministrator",
    ]
    condition {
      test     = "StringLikeIfExists"
      variable = "organizations:ServicePrincipal"
      values   = ["guardduty.amazonaws.com", "malware-protection.guardduty.amazonaws.com"]
    }
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "sra_guardduty_org_policy_sns" {
  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.guardduty_topic.arn]
  }
}

data "aws_iam_policy_document" "sra_guardduty_org_policy_sqs" {
  statement {
    sid       = "SQSSendMessage"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.guardduty_dlq.arn]
  }
}

########################################################################
# Lambda Policies
########################################################################

resource "aws_iam_policy" "sra_guardduty_org_policy_logs" {
  name   = "sra-guardduty-org-policy-logs"
  policy = data.aws_iam_policy_document.sra_guardduty_org_policy_logs.json
}

resource "aws_iam_policy" "sra_guardduty_org_policy_organizations" {
  name   = "sra-guardduty-org-policy-organizations"
  policy = data.aws_iam_policy_document.sra_guardduty_org_policy_organizations.json
}

resource "aws_iam_policy" "sra_guardduty_org_policy_sns" {
  name   = "sra-guardduty-org-policy-sns"
  policy = data.aws_iam_policy_document.sra_guardduty_org_policy_sns.json
}

resource "aws_iam_policy" "sra_guardduty_org_policy_sqs" {
  name   = "sra-guardduty-org-policy-sqs"
  policy = data.aws_iam_policy_document.sra_guardduty_org_policy_sqs.json
}

resource "aws_iam_policy" "sra_guardduty_org_policy_iam" {
  name   = "sra-guardduty-org-policy-iam"
  policy = data.aws_iam_policy_document.sra_guardduty_org_policy_iam.json
}

resource "aws_iam_policy" "sra_guardduty_org_policy_cloudformation" {
  name   = "sra-guardduty-org-policy-cloudformation"
  policy = data.aws_iam_policy_document.sra_guardduty_org_policy_cloudformation.json
}

resource "aws_iam_policy" "sra_guardduty_org_policy_acct" {
  name   = "sra-guardduty-org-policy-acct"
  policy = data.aws_iam_policy_document.sra_guardduty_org_policy_acct.json
}

resource "aws_iam_policy" "sra_guardduty_org_policy_ssm_access" {
  name   = "ssm-access"
  policy = data.aws_iam_policy_document.sra_guardduty_org_policy_ssm_access.json
}

resource "aws_iam_policy" "sra_guardduty_org_policy_guardduty" {
  name   = "sra-guardduty-org-policy-guardduty"
  policy = data.aws_iam_policy_document.sra_guardduty_org_policy_guardduty.json
}

########################################################################
# Lambda Attachment
########################################################################

resource "aws_iam_policy_attachment" "sra_guardduty_org_policy_attachment_logs" {
  name       = "sra-guardduty-org-policy-attachment-logs"
  roles      = [aws_iam_role.guardduty_lambda_role.name]
  policy_arn = aws_iam_policy.sra_guardduty_org_policy_logs.arn
}

resource "aws_iam_policy_attachment" "sra_guardduty_org_policy_attachment_organizations" {
  name       = "sra-guardduty-org-policy-attachment-organizations"
  roles      = [aws_iam_role.guardduty_lambda_role.name]
  policy_arn = aws_iam_policy.sra_guardduty_org_policy_organizations.arn
}

resource "aws_iam_policy_attachment" "sra_guardduty_org_policy_attachment_sns" {
  name       = "sra-guardduty-org-policy-attachment-sns"
  roles      = [aws_iam_role.guardduty_lambda_role.name]
  policy_arn = aws_iam_policy.sra_guardduty_org_policy_sns.arn
}

resource "aws_iam_policy_attachment" "sra_guardduty_org_policy_attachment_sqs" {
  name       = "sra-guardduty-org-policy-attachment-sqs"
  roles      = [aws_iam_role.guardduty_lambda_role.name]
  policy_arn = aws_iam_policy.sra_guardduty_org_policy_sqs.arn
}

resource "aws_iam_policy_attachment" "sra_guardduty_org_policy_attachment_iam" {
  name       = "sra-guardduty-org-policy-attachment-iam"
  roles      = [aws_iam_role.guardduty_lambda_role.name]
  policy_arn = aws_iam_policy.sra_guardduty_org_policy_iam.arn
}

resource "aws_iam_policy_attachment" "sra_guardduty_org_policy_attachment_cloudformation" {
  name       = "sra-guardduty-org-policy-attachment-cloudformation"
  roles      = [aws_iam_role.guardduty_lambda_role.name]
  policy_arn = aws_iam_policy.sra_guardduty_org_policy_cloudformation.arn
}

resource "aws_iam_policy_attachment" "sra_guardduty_org_policy_attachment_acct" {
  name       = "sra-guardduty-org-policy-attachment-acct"
  roles      = [aws_iam_role.guardduty_lambda_role.name]
  policy_arn = aws_iam_policy.sra_guardduty_org_policy_acct.arn
}

resource "aws_iam_policy_attachment" "sra_guardduty_org_policy_attachment_ssm_access" {
  name       = "sra-guardduty-org-policy-attachment-ssm-access"
  roles      = [aws_iam_role.guardduty_lambda_role.name]
  policy_arn = aws_iam_policy.sra_guardduty_org_policy_ssm_access.arn
}

resource "aws_iam_policy_attachment" "sra_guardduty_org_policy_attachment_guardduty" {
  name       = "sra-guardduty-org-policy-attachment-guardduty"
  roles      = [aws_iam_role.guardduty_lambda_role.name]
  policy_arn = aws_iam_policy.sra_guardduty_org_policy_guardduty.arn
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
resource "aws_lambda_function" "guardduty_lambda_function" {
  #checkov:skip=CKV_AWS_272: Ensure AWS Lambda function is configured to validate code-signing
  #checkov:skip=CKV_AWS_116: Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) 
  #checkov:skip=CKV_AWS_173: Check encryption settings for Lambda environment variable
  #checkov:skip=CKV_AWS_115: Ensure that AWS Lambda function is configured for function-level concurrent execution limit
  #checkov:skip=CKV_AWS_117: Ensure that AWS Lambda function is configured inside a VPC
  #checkov:skip=CKV_AWS_50: X-Ray tracing is enabled for Lambda

  function_name = var.guardduty_lambda_function_name
  description   = "Configure GuardDuty for the Organization"
  role          = aws_iam_role.guardduty_lambda_role.arn
  memory_size   = 512
  handler       = "app.terraform_handler"
  runtime       = "python3.12"
  timeout       = 900

  source_code_hash = data.archive_file.zipped_lambda.output_base64sha256
  filename         = data.archive_file.zipped_lambda.output_path

  dead_letter_config {
    target_arn = aws_sqs_queue.guardduty_dlq.arn
  }

  environment {
    variables = {
      LOG_LEVEL = var.lambda_log_level
    }
  }

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_lambda_permission" "guardduty_topic_permission" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guardduty_lambda_function.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.guardduty_topic.arn
}

resource "aws_cloudwatch_log_group" "guardduty_lambda_log_group" {
  count             = var.create_lambda_log_group ? 1 : 0
  name              = "/aws/lambda/${var.guardduty_lambda_function_name}"
  retention_in_days = var.lambda_log_group_retention
  kms_key_id        = var.lambda_log_group_kms_key != "" ? var.lambda_log_group_kms_key : null
}

resource "aws_sns_topic" "guardduty_topic" {
  name              = "${var.sra_solution_name}-configuration"
  display_name      = "${var.sra_solution_name}-configuration"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_sns_topic_subscription" "guardduty_topic_subscription" {
  topic_arn = aws_sns_topic.guardduty_topic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.guardduty_lambda_function.arn
}

resource "aws_sqs_queue" "guardduty_dlq" {
  #checkov:skip=CKV_AWS_27: Ensure all data stored in the SQS queue is encrypted 
  name = "${var.sra_solution_name}-dlq"
  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

data "aws_iam_policy_document" "guardduty_dlq_policy_document" {
  statement {
    sid       = "AllowSNSPublish"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.guardduty_dlq.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_lambda_function.guardduty_lambda_function.arn]
    }

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sqs_queue_policy" "guardduty_dlq_policy" {
  queue_url = aws_sqs_queue.guardduty_dlq.id
  policy    = data.aws_iam_policy_document.guardduty_dlq_policy_document.json
}

resource "aws_cloudwatch_metric_alarm" "guardduty_dlq_alarm" {
  count                     = local.create_dlq_alarm ? 1 : 0
  alarm_name                = "${var.sra_solution_name}-dlq-alarm"
  comparison_operator       = "GreaterThanThreshold"
  evaluation_periods        = 1
  metric_name               = "ApproximateNumberOfMessagesVisible"
  namespace                 = "AWS/SQS"
  period                    = 300
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "SRA DLQ alarm if the queue depth is 1"
  alarm_actions             = [aws_sns_topic.guardduty_dlq_alarm_topic[0].arn]
  insufficient_data_actions = [aws_sns_topic.guardduty_dlq_alarm_topic[0].arn]

  dimensions = {
    QueueName = aws_sqs_queue.guardduty_dlq.name
  }
}

resource "aws_sns_topic" "guardduty_dlq_alarm_topic" {
  count             = local.create_dlq_alarm ? 1 : 0
  name              = "${var.sra_solution_name}-dlq-alarm"
  display_name      = "${var.sra_solution_name}-dlq-alarm"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_sns_topic_subscription" "guardduty_dlq_alarm_subscription" {
  count     = local.create_dlq_alarm ? 1 : 0
  topic_arn = aws_sns_topic.guardduty_dlq_alarm_topic[0].arn
  protocol  = "email"
  endpoint  = var.sra_alarm_email
}
