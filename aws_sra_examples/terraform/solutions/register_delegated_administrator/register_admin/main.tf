########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
locals {
  src_path = "${path.root}/../../solutions/common/common_register_delegated_administrator/lambda/src/"
}

resource "aws_cloudwatch_log_group" "register_delegated_admin_lambda_log_group" {
  count             = var.create_lambda_log_group == "true" ? 1 : 0
  name              = "/aws/lambda/${var.register_delegated_admin_lambda_function_name}"
  retention_in_days = var.lambda_log_group_retention
  kms_key_id        = var.lambda_log_group_kms_key != "" ? var.lambda_log_group_kms_key : null
}

resource "aws_iam_role" "register_delegated_admin_lambda_role" {
  name = var.register_delegated_admin_lambda_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

data "aws_iam_policy_document" "register_delegated_admin_policy_logs" {
  version = "2012-10-17"

  statement {
    sid    = "CreateLogStreamAndEvents"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.register_delegated_admin_lambda_function_name}:log-stream:*"
    ]
  }
}

data "aws_iam_policy_document" "register_delegated_admin_policy_organizations" {
  #checkov:skip=CKV_AWS_111: Ensure IAM policies does not allow write access without constraints
  #checkov:skip=CKV_AWS_356: Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions

  version = "2012-10-17"

  statement {
    sid    = "OrganizationsAccess"
    effect = "Allow"

    actions = [
      "organizations:DeregisterDelegatedAdministrator",
      "organizations:DescribeOrganization",
      "organizations:DisableAWSServiceAccess",
      "organizations:EnableAWSServiceAccess",
      "organizations:ListAWSServiceAccessForOrganization",
      "organizations:ListDelegatedAdministrators",
      "organizations:RegisterDelegatedAdministrator",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_policy" "register_delegated_admin_policy_logs" {
  name   = "sra-register-delegated-admin-policy-logs"
  policy = data.aws_iam_policy_document.register_delegated_admin_policy_logs.json
}

resource "aws_iam_policy" "register_delegated_admin_policy_organizations" {
  name   = "sra-register-delegated-admin-policy-organizations"
  policy = data.aws_iam_policy_document.register_delegated_admin_policy_organizations.json
}

resource "aws_iam_policy_attachment" "register_delegated_admin_policy_attachment_logs" {
  name       = "sra-register-delegated-admin-policy-logs-attachment"
  roles      = [aws_iam_role.register_delegated_admin_lambda_role.name]
  policy_arn = aws_iam_policy.register_delegated_admin_policy_logs.arn
}

resource "aws_iam_policy_attachment" "register_delegated_admin_policy_attachment_organizations" {
  name       = "sra-register-delegated-admin-policy-organizations-attachment"
  roles      = [aws_iam_role.register_delegated_admin_lambda_role.name]
  policy_arn = aws_iam_policy.register_delegated_admin_policy_organizations.arn
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

# main function
resource "aws_lambda_function" "register_delegated_admin_lambda_function" {
  #checkov:skip=CKV_AWS_272: Ensure AWS Lambda function is configured to validate code-signing
  #checkov:skip=CKV_AWS_116: Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) 
  #checkov:skip=CKV_AWS_173: Check encryption settings for Lambda environment variable
  #checkov:skip=CKV_AWS_115: Ensure that AWS Lambda function is configured for function-level concurrent execution limit
  #checkov:skip=CKV_AWS_117: Ensure that AWS Lambda function is configured inside a VPC
  #checkov:skip=CKV_AWS_50: X-Ray tracing is enabled for Lambda

  function_name = var.register_delegated_admin_lambda_function_name
  description   = "Enable service access and register delegated admin account"
  role          = aws_iam_role.register_delegated_admin_lambda_role.arn
  runtime       = "python3.12"
  handler       = "app.terraform_handler"
  timeout       = 300

  environment {
    variables = {
      LOG_LEVEL = var.lambda_log_level
    }
  }

  source_code_hash = data.archive_file.zipped_lambda.output_base64sha256
  filename         = data.archive_file.zipped_lambda.output_path

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}