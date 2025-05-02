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
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  src_path   = "${path.root}/../../solutions/common/common_prerequisites/lambda/src/"
}


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

resource "aws_lambda_function" "management_account_parameters" {
  #checkov:skip=CKV_AWS_272: Ensure AWS Lambda function is configured to validate code-signing
  #checkov:skip=CKV_AWS_116: Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) 
  #checkov:skip=CKV_AWS_173: Check encryption settings for Lambda environment variable
  #checkov:skip=CKV_AWS_115: Ensure that AWS Lambda function is configured for function-level concurrent execution limit
  #checkov:skip=CKV_AWS_117: Ensure that AWS Lambda function is configured inside a VPC
  #checkov:skip=CKV_AWS_50: X-Ray tracing is enabled for Lambda
  function_name    = var.management_account_parameters_lambda_function_name
  source_code_hash = data.archive_file.zipped_lambda.output_base64sha256
  filename         = data.archive_file.zipped_lambda.output_path
  handler          = "app.terraform_handler"
  runtime          = "python3.9"
  role             = aws_iam_role.management_account_parameters_lambda_role.arn
  timeout          = 300
  memory_size      = 128

  environment {
    variables = {
      LOG_LEVEL              = var.lambda_log_level
      TAG_KEY                = var.sra_solution_tag_key
      TAG_VALUE              = var.sra_solution_name
      CONTROL_TOWER          = var.control_tower
      OTHER_REGIONS          = var.governed_regions
      OTHER_SECURITY_ACCT    = var.security_account_id
      OTHER_LOG_ARCHIVE_ACCT = var.log_archive_account_id
    }
  }

  # TODO: Add conditions for other reigons if needed to check...
  architectures = ["arm64"]

  tags = {
    "${var.sra_solution_tag_key}" = var.sra_solution_name
  }
}

resource "aws_cloudwatch_log_group" "management_account_parameters" {
  count = var.create_lambda_log_group ? 1 : 0

  name              = "/aws/lambda/${aws_lambda_function.management_account_parameters.function_name}"
  kms_key_id        = var.lambda_log_group_kms_key
  retention_in_days = var.lambda_log_group_retention
}

resource "aws_iam_role" "management_account_parameters_lambda_role" {
  name        = var.management_account_parameters_lambda_role_name
  description = "Role for '${var.management_account_parameters_lambda_role_name}' Lambda function"

  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = {
    "${var.sra_solution_tag_key}" = var.sra_solution_name
  }
}

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

data "aws_iam_policy_document" "cloudwatch_policy" {
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.management_account_parameters_lambda_function_name}:log-stream:*"
    ]
  }
}

data "aws_iam_policy_document" "management_account_parameters_lambda_ssm_policy" {
  #checkov:skip=CKV_AWS_356: Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions

  statement {
    sid    = "STSOrganizationRead"
    effect = "Allow"
    actions = [
      "organizations:DescribeOrganization",
      "organizations:ListAccounts",
      "organizations:ListRoots"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "CloudFormationRead"
    effect = "Allow"
    actions = [
      "cloudformation:DescribeStackSet",
      "cloudformation:ListStackInstances"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "SSMParameterRead"
    effect = "Allow"
    actions = [
      "ssm:DescribeParameters"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "SSMParameterReadValues"
    effect = "Allow"
    actions = [
      "ssm:GetParameters"
    ]
    resources = [
      "arn:aws:ssm:*:${local.account_id}:parameter/sra/*"
    ]
  }
  statement {
    sid    = "SSMParameterWrite"
    effect = "Allow"
    actions = [
      "ssm:AddTagsToResource",
      "ssm:DeleteParameters",
      "ssm:PutParameter"
    ]
    resources = [
      "arn:aws:ssm:*:${local.account_id}:parameter/sra/*"
    ]
  }
  statement {
    sid    = "TagsRead"
    effect = "Allow"
    actions = [
      "tag:GetResources",
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_iam_role_policy" "cloudwatch_policy_attachment" {
  name   = "CloudWatchLogGroup"
  role   = aws_iam_role.management_account_parameters_lambda_role.id
  policy = data.aws_iam_policy_document.cloudwatch_policy.json
}

resource "aws_iam_role_policy" "management_account_parameters_lambda_ssm_policy_attachment" {
  name   = "ssm-account-parameter-creator"
  role   = aws_iam_role.management_account_parameters_lambda_role.id
  policy = data.aws_iam_policy_document.management_account_parameters_lambda_ssm_policy.json
}