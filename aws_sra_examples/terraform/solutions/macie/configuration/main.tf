########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
locals {
  src_path = "${path.root}/../../solutions/macie/macie_org/lambda/src/"
}

resource "aws_cloudwatch_log_group" "rMacieOrgLambdaLogGroup" {
  count             = var.p_create_lambda_log_group == "true" ? 1 : 0
  name              = "/aws/lambda/${var.p_macie_org_lambda_function_name}"
  retention_in_days = var.p_lambda_log_group_retention
  kms_key_id        = var.p_lambda_log_group_kms_key != "" ? var.p_lambda_log_group_kms_key : null
}

########################################################################
# Lambda Policies Documents
########################################################################
resource "aws_iam_role" "r_macie_org_lambda_role" {
  name = var.p_macie_org_lambda_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "lambda.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    "sra-solution" = var.p_sra_solution_name
  }
}

# IAM Policies
data "aws_iam_policy_document" "sra_macie_org_policy_logs" {
  version = "2012-10-17"

  statement {
    sid       = "CreateLogStreamAndEvents"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [format("arn:%s:logs:%s:%s:log-group:/aws/lambda/%s:log-stream:*", data.aws_partition.current.partition, data.aws_region.current.name, data.aws_caller_identity.current.account_id, var.p_macie_org_lambda_function_name)]
  }
}

data "aws_iam_policy_document" "sra_macie_org_policy_organizations" {
  version = "2012-10-17"

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
    sid     = "AWSServiceAccess"
    effect  = "Allow"
    actions = ["organizations:DisableAWSServiceAccess", "organizations:EnableAWSServiceAccess"]
    condition {
      test     = "StringLikeIfExists"
      variable = "organizations:ServicePrincipal"
      values   = ["macie.amazonaws.com"]
    }
    resources = ["*"]
  }

  statement {
    sid     = "RegisterDeregisterDelegatedAdministrator"
    effect  = "Allow"
    actions = ["organizations:DeregisterDelegatedAdministrator", "organizations:RegisterDelegatedAdministrator"]
    condition {
      test     = "StringLikeIfExists"
      variable = "organizations:ServicePrincipal"
      values   = ["macie.amazonaws.com"]
    }
    resources = [format("arn:%s:organizations::*:account/o-*/*", data.aws_partition.current.partition)]
  }
}

data "aws_iam_policy_document" "sra_macie_org_policy_macie" {
  version = "2012-10-17"

  statement {
    sid    = "MacieNoResource"
    effect = "Allow"
    actions = [
      "macie2:DisableOrganizationAdminAccount",
      "macie2:EnableMacie",
      "macie2:EnableOrganizationAdminAccount",
      "macie2:ListOrganizationAdminAccounts",
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "sra_macie_org_policy_iam" {
  version = "2012-10-17"

  statement {
    sid     = "AssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    resources = [
      format("arn:%s:iam::%s:role/%s", data.aws_partition.current.partition, var.p_delegated_admin_account_id, var.p_macie_org_configuration_role_name),
      format("arn:%s:iam::*:role/%s", data.aws_partition.current.partition, var.p_disable_macie_role_name),
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgId"
      values   = [var.p_organization_id]
    }
  }

  statement {
    sid       = "AllowReadIamActions"
    effect    = "Allow"
    actions   = ["iam:GetRole"]
    resources = [format("arn:%s:iam::%s:role/*", data.aws_partition.current.partition, data.aws_caller_identity.current.account_id)]
  }

  statement {
    sid       = "AllowCreateServiceLinkedRole"
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = [format("arn:%s:iam::%s:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie", data.aws_partition.current.partition, data.aws_caller_identity.current.account_id)]
    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"
      values   = ["macie.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowPolicyActions"
    effect    = "Allow"
    actions   = ["iam:PutRolePolicy"]
    resources = [format("arn:%s:iam::%s:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie", data.aws_partition.current.partition, data.aws_caller_identity.current.account_id)]
  }
}

data "aws_iam_policy_document" "macie_org_policy_cloudformation" {
  version = "2012-10-17"

  statement {
    effect    = "Allow"
    actions   = ["cloudformation:ListStackInstances"]
    resources = [format("arn:%s:cloudformation:%s:%s:stackset/AWSControlTowerBP-*", data.aws_partition.current.partition, data.aws_region.current.name, data.aws_caller_identity.current.account_id)]
  }
}

data "aws_iam_policy_document" "sra_macie_org_policy_sns" {
  version = "2012-10-17"

  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.r_macie_org_topic.arn]
  }
}

data "aws_iam_policy_document" "sra_macie_org_policy_sqs" {
  version = "2012-10-17"

  statement {
    sid       = "SQSSendMessage"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.macie_org_dlq.arn]
  }
}

data "aws_iam_policy_document" "sra_macie_org_policy_ssm" {
  version = "2012-10-17"

  statement {
    sid    = "SSMAccess"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]
    resources = [format("arn:%s:ssm:%s:%s:parameter/sra*", data.aws_partition.current.partition, data.aws_region.current.name, data.aws_caller_identity.current.account_id)]
  }
}

########################################################################
# Lambda Policies
########################################################################
resource "aws_iam_policy" "sra_macie_org_policy_logs" {
  name        = "sra-macie-org-policy-logs"
  description = "IAM policy for Macie Org Lambda Logs"
  policy      = data.aws_iam_policy_document.sra_macie_org_policy_logs.json
}

resource "aws_iam_policy" "sra_macie_org_policy_organizations" {
  name        = "sra-macie-org-policy-organizations"
  description = "IAM policy for Macie Org Lambda Organizations"
  policy      = data.aws_iam_policy_document.sra_macie_org_policy_organizations.json
}

resource "aws_iam_policy" "sra_macie_org_policy_macie" {
  name        = "sra-macie-org-policy-macie"
  description = "IAM policy for Macie Org Lambda Macie"
  policy      = data.aws_iam_policy_document.sra_macie_org_policy_macie.json
}

resource "aws_iam_policy" "sra_macie_org_policy_iam" {
  name        = "sra-macie-org-policy-iam"
  description = "IAM policy for Macie Org Lambda IAM"
  policy      = data.aws_iam_policy_document.sra_macie_org_policy_iam.json
}

resource "aws_iam_policy" "macie_org_policy_cloudformation" {
  name        = "macie-org-policy-cloudformation"
  description = "IAM policy for Macie Org Lambda CloudFormation"
  policy      = data.aws_iam_policy_document.macie_org_policy_cloudformation.json
}

resource "aws_iam_policy" "sra_macie_org_policy_sns" {
  name        = "sra-macie-org-policy-sns"
  description = "IAM policy for Macie Org Lambda SNS"
  policy      = data.aws_iam_policy_document.sra_macie_org_policy_sns.json
}

resource "aws_iam_policy" "sra_macie_org_policy_sqs" {
  name        = "sra-macie-org-policy-sqs"
  description = "IAM policy for Macie Org Lambda SQS"
  policy      = data.aws_iam_policy_document.sra_macie_org_policy_sqs.json
}

resource "aws_iam_policy" "sra_macie_org_policy_ssm" {
  name        = "sra-macie-org-policy-ssm"
  description = "IAM policy for Macie Org Lambda SSM"
  policy      = data.aws_iam_policy_document.sra_macie_org_policy_ssm.json
}

########################################################################
# Lambda Attachment
########################################################################
resource "aws_iam_role_policy_attachment" "rMacieOrgLambdaLogsPolicyAttachment" {
  policy_arn = aws_iam_policy.sra_macie_org_policy_logs.arn
  role       = aws_iam_role.r_macie_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "rMacieOrgLambdaOrganizationsPolicyAttachment" {
  policy_arn = aws_iam_policy.sra_macie_org_policy_organizations.arn
  role       = aws_iam_role.r_macie_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "rMacieOrgLambdaMaciePolicyAttachment" {
  policy_arn = aws_iam_policy.sra_macie_org_policy_macie.arn
  role       = aws_iam_role.r_macie_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "rMacieOrgLambdaIamPolicyAttachment" {
  policy_arn = aws_iam_policy.sra_macie_org_policy_iam.arn
  role       = aws_iam_role.r_macie_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "rMacieOrgLambdaCloudFormationPolicyAttachment" {
  policy_arn = aws_iam_policy.macie_org_policy_cloudformation.arn
  role       = aws_iam_role.r_macie_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "rMacieOrgLambdaSnsPolicyAttachment" {
  policy_arn = aws_iam_policy.sra_macie_org_policy_sns.arn
  role       = aws_iam_role.r_macie_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "rMacieOrgLambdaSqsPolicyAttachment" {
  policy_arn = aws_iam_policy.sra_macie_org_policy_sqs.arn
  role       = aws_iam_role.r_macie_org_lambda_role.name
}

resource "aws_iam_role_policy_attachment" "rMacieOrgLambdaSsmPolicyAttachment" {
  policy_arn = aws_iam_policy.sra_macie_org_policy_ssm.arn
  role       = aws_iam_role.r_macie_org_lambda_role.name
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

resource "aws_lambda_function" "r_macie_org_lambda_function" {
  #checkov:skip=CKV_AWS_272: Ensure AWS Lambda function is configured to validate code-signing
  #checkov:skip=CKV_AWS_116: Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) 
  #checkov:skip=CKV_AWS_173: Check encryption settings for Lambda environment variable
  #checkov:skip=CKV_AWS_115: Ensure that AWS Lambda function is configured for function-level concurrent execution limit
  #checkov:skip=CKV_AWS_117: Ensure that AWS Lambda function is configured inside a VPC
  #checkov:skip=CKV_AWS_50: X-Ray tracing is enabled for Lambda

  function_name = var.p_macie_org_lambda_function_name
  description   = "Configure Macie for the Organization"
  role          = aws_iam_role.r_macie_org_lambda_role.arn
  handler       = "app.terraform_handler"
  memory_size   = 512
  runtime       = "python3.9"
  timeout       = 900

  source_code_hash = data.archive_file.zipped_lambda.output_base64sha256
  filename         = data.archive_file.zipped_lambda.output_path

  dead_letter_config {
    target_arn = aws_sqs_queue.macie_org_dlq.arn
  }
  environment {
    variables = {
      LOG_LEVEL = var.p_lambda_log_level
    }
  }
  tags = {
    "sra-solution" = var.p_sra_solution_name
  }
}

resource "aws_lambda_permission" "r_macie_org_topic_lambda_permission" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.r_macie_org_lambda_function.arn
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.r_macie_org_topic.arn
}

resource "aws_sns_topic" "r_macie_org_topic" {
  display_name      = "${var.p_sra_solution_name}-configuration"
  kms_master_key_id = "alias/aws/sns"
  tags = {
    "sra-solution" = var.p_sra_solution_name
  }
}

resource "aws_sns_topic_subscription" "r_macie_org_topic_subscription" {
  endpoint  = aws_lambda_function.r_macie_org_lambda_function.arn
  protocol  = "lambda"
  topic_arn = aws_sns_topic.r_macie_org_topic.arn
}

resource "aws_sqs_queue" "macie_org_dlq" {
  # checkov:skip=CKV2_AWS_73: Using default KMS key
  name              = "${var.p_sra_solution_name}-dlq"
  kms_master_key_id = "alias/aws/sqs"
  tags = {
    "sra-solution" = var.p_sra_solution_name
  }
}

resource "aws_sqs_queue_policy" "rMacieOrgDLQPolicy" {
  queue_url = aws_sqs_queue.macie_org_dlq.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "SQS:SendMessage",
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_lambda_function.r_macie_org_lambda_function.arn
        }
      },
      Effect = "Allow",
      Principal = {
        Service = "events.amazonaws.com"
      },
      Resource = [aws_sqs_queue.macie_org_dlq.arn]
    }]
  })
}

resource "aws_sns_topic" "rMacieOrgDLQAlarmTopic" {
  count             = var.p_sra_alarm_email != "" ? 1 : 0
  display_name      = "${var.p_sra_solution_name}-dlq-alarm"
  kms_master_key_id = "alias/aws/sns"
  tags = {
    "sra-solution" = var.p_sra_solution_name
  }
}

resource "aws_cloudwatch_metric_alarm" "rMacieOrgDLQAlarm" {
  count                     = var.p_sra_alarm_email != "" ? 1 : 0
  alarm_name                = "SRA DLQ alarm if the queue depth is 1"
  comparison_operator       = "GreaterThanThreshold"
  evaluation_periods        = 1
  metric_name               = "ApproximateNumberOfMessagesVisible"
  namespace                 = "AWS/SQS"
  period                    = 300
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "SRA DLQ alarm if the queue depth is 1"
  alarm_actions             = [aws_sns_topic.rMacieOrgDLQAlarmTopic[0].arn]
  insufficient_data_actions = [aws_sns_topic.rMacieOrgDLQAlarmTopic[0].arn]

  dimensions = {
    QueueName = aws_sqs_queue.macie_org_dlq.name
  }
}
