########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
locals {
  create_lambda_log_group = var.create_lambda_log_group == "true"
  use_kms_key             = var.lambda_log_group_kms_key != ""
  partition               = data.aws_partition.current.partition
  current_account         = data.aws_caller_identity.current.account_id
  current_region          = data.aws_region.current.name
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
  src_path = "${path.root}/../../solutions/iam/iam_password_policy/lambda/src/"
}

########################################################################
# Lambda IAM Role
########################################################################
resource "aws_iam_role" "iam_password_policy_lambda_role" {
  name = var.lambda_role_name

  assume_role_policy = data.aws_iam_policy_document.iam_password_policy_assume_role.json

  tags = {
    sra-solution = var.sra_solution_name
  }
}

########################################################################
# Lambda Policies Documents
########################################################################
data "aws_iam_policy_document" "iam_password_policy_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda_policy" {
  statement {
    sid    = "CreateLogStreamAndEvents"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "arn:${local.partition}:logs:${local.current_region}:${local.current_account}:log-group:/aws/lambda/${var.lambda_function_name}:log-stream:*",
    ]
  }

  statement {
    sid    = "IAMUpdateAccountPasswordPolicy"
    effect = "Allow"
    actions = [
      "iam:UpdateAccountPasswordPolicy",
    ]
    resources = ["*"]
  }
}


########################################################################
# Lambda Policies
########################################################################
resource "aws_iam_policy" "lambda_policy" {
  name        = "sra-iam-password-policy"
  description = "Policy for the IAM Password Policy Lambda function"
  policy      = data.aws_iam_policy_document.lambda_policy.json
}

########################################################################
# Lambda Policies Attachment
########################################################################
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  policy_arn = aws_iam_policy.lambda_policy.arn
  role       = aws_iam_role.iam_password_policy_lambda_role.name
}

########################################################################
# Cloud Watch Log Group
########################################################################
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  count             = local.create_lambda_log_group ? 1 : 0
  name              = "/aws/lambda/${var.lambda_function_name}"
  retention_in_days = var.lambda_log_group_retention

  kms_key_id = local.use_kms_key ? var.lambda_log_group_kms_key : null
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
resource "aws_lambda_function" "iam_password_policy_lambda_function" {
  #checkov:skip=CKV_AWS_272: Ensure AWS Lambda function is configured to validate code-signing
  #checkov:skip=CKV_AWS_116: Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) 
  #checkov:skip=CKV_AWS_173: Check encryption settings for Lambda environment variable
  #checkov:skip=CKV_AWS_115: Ensure that AWS Lambda function is configured for function-level concurrent execution limit
  #checkov:skip=CKV_AWS_117: Ensure that AWS Lambda function is configured inside a VPC
  #checkov:skip=CKV_AWS_50: X-Ray tracing is enabled for Lambda

  function_name = var.lambda_function_name
  description   = "SRA Update IAM password policy"
  role          = aws_iam_role.iam_password_policy_lambda_role.arn
  handler       = "app.lambda_handler"
  memory_size   = 512
  runtime       = "python3.9"
  timeout       = 900

  source_code_hash = data.archive_file.zipped_lambda.output_base64sha256
  filename         = data.archive_file.zipped_lambda.output_path

  architectures = [local.use_graviton ? "arm64" : "x86_64"]

  # Environment variables
  environment {
    variables = {
      LOG_LEVEL = var.lambda_log_level
    }
  }

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}