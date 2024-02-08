########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
locals {
  src_path = "${path.root}/../../solutions/cloudtrail/cloudtrail_org/lambda/src/"
}

resource "aws_iam_role" "cloudtrail_log_group_role" {
  count = var.create_cloudtrail_log_group == "true" ? 1 : 0

  name = "${var.cloudtrail_name}-cloudwatch-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    "sra-solution" = var.sra_solution_name
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_logs_policy" {
  count = var.create_cloudtrail_log_group == "true" ? 1 : 0

  name = "sra-cloudtrail-cloudwatch-logs"
  role = aws_iam_role.cloudtrail_log_group_role[0].id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "CreateLogStreamAndEvents",
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ],
        Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail_log_group[0].name}:log-stream:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  #checkov:skip=CKV_AWS_158: Ensure that CloudWatch Log Group is encrypted by KMS 
  count = var.create_cloudtrail_log_group == "true" ? 1 : 0

  name              = "sra/${var.cloudtrail_name}"
  kms_key_id        = var.cloudtrail_log_group_kms_key != "" ? var.cloudtrail_log_group_kms_key : null
  retention_in_days = var.cloudtrail_log_group_retention
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  #checkov:skip=CKV_AWS_158: Ensure that CloudWatch Log Group is encrypted by KMS 
  count = var.create_lambda_log_group == "true" ? 1 : 0

  name              = "/aws/lambda/${var.cloudtrail_lambda_function_name}"
  kms_key_id        = var.lambda_log_group_kms_key != "" ? var.lambda_log_group_kms_key : null
  retention_in_days = var.lambda_log_group_retention
}

resource "aws_iam_role" "cloudtrail_lambda_role" {
  name = var.cloudtrail_lambda_role_name

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
    "sra-solution" = var.sra_solution_name
  }
}
########################################################################
# Lambda Policies
########################################################################
resource "aws_iam_role_policy" "cloudtrail_log_group_policy" {
  name = "sra-cloudtrail-org-policy-logs"
  role = aws_iam_role.cloudtrail_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "CloudWatchLogs",
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ],
        Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.cloudtrail_lambda_function_name}:log-stream:*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_policy" {
  name = "sra-cloudtrail-org-policy-cloudtrail"
  role = aws_iam_role.cloudtrail_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowCloudTrail",
        Effect = "Allow",
        Action = [
          "cloudtrail:AddTags",
          "cloudtrail:CreateTrail",
          "cloudtrail:DeleteTrail",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:PutEventSelectors",
          "cloudtrail:RemoveTags",
          "cloudtrail:StartLogging",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
        ],
        Resource = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/*"
      },
      {
        Sid    = "AllowCloudTrailDelegatedAdministrator",
        Effect = "Allow",
        Action = [
          "cloudtrail:RegisterOrganizationDelegatedAdmin",
          "cloudtrail:DeregisterOrganizationDelegatedAdmin",
        ],
        Resource = "*"
      },
      {
        Sid    = "RegisterDeregisterDelegatedAdministrator",
        Effect = "Allow",
        Action = [
          "organizations:DeregisterDelegatedAdministrator",
          "organizations:RegisterDelegatedAdministrator",
        ],
        Condition = {
          StringLikeIfExists = {
            "organizations:ServicePrincipal" : "cloudtrail.amazonaws.com"
          }
        },
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_org_policy" {
  name = "cloudtrail-org-policy-organization"
  role = aws_iam_role.cloudtrail_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowOrganizationsAccess",
        Effect = "Allow",
        Action = [
          "organizations:DescribeOrganization",
          "organizations:ListAWSServiceAccessForOrganization",
          "organizations:ListAccounts",
          "organizations:ListDelegatedAdministrators",
        ],
        Resource = "*"
      },
      {
        Sid    = "AWSServiceAccess",
        Effect = "Allow",
        Action = [
          "organizations:DisableAWSServiceAccess",
          "organizations:EnableAWSServiceAccess",
        ],
        Condition = {
          StringLikeIfExists = {
            "organizations:ServicePrincipal" : "cloudtrail.amazonaws.com"
          }
        },
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_iam_policy" {
  name = "sra-cloudtrail-org-policy-iam"
  role = aws_iam_role.cloudtrail_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "AllowReadIamActions",
        Effect   = "Allow",
        Action   = "iam:GetRole",
        Resource = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/*"
      },
      {
        Sid    = "AllowCreateDeleteServiceLinkedRole",
        Effect = "Allow",
        Action = [
          "iam:CreateServiceLinkedRole",
          "iam:DeleteServiceLinkedRole",
        ],
        Resource = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/cloudtrail.amazonaws.com/AWSServiceRoleForCloudTrail*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_logs_policy2" {
  count = var.create_cloudtrail_log_group == "true" ? 1 : 0

  name = "cloudtrail-org-policy-organization2"
  role = aws_iam_role.cloudtrail_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "AllowPassRoleForCWLogGroupRole",
        Effect   = "Allow",
        Action   = "iam:PassRole",
        Resource = aws_iam_role.cloudtrail_log_group_role[0].arn,
        Condition = {
          StringEqualsIfExists = {
            "iam:PassedToService" : "cloudtrail.amazonaws.com"
          }
        }
      },
    ]
  })
}

########################################################################
# Lambda Functions
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

resource "aws_lambda_function" "cloudtrail_org_lambda_function" {
  #checkov:skip=CKV_AWS_272: Ensure AWS Lambda function is configured to validate code-signing
  #checkov:skip=CKV_AWS_116: Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) 
  #checkov:skip=CKV_AWS_173: Check encryption settings for Lambda environment variable
  #checkov:skip=CKV_AWS_115: Ensure that AWS Lambda function is configured for function-level concurrent execution limit
  #checkov:skip=CKV_AWS_117: Ensure that AWS Lambda function is configured inside a VPC
  #checkov:skip=CKV_AWS_50: X-Ray tracing is enabled for Lambda
  
  description   = "Creates an Organization CloudTrail"
  function_name = var.cloudtrail_lambda_function_name
  role          = aws_iam_role.cloudtrail_lambda_role.arn
  runtime       = "python3.9"
  timeout       = 300

  handler = "app.terraform_handler"

  source_code_hash = data.archive_file.zipped_lambda.output_base64sha256
  filename         = data.archive_file.zipped_lambda.output_path

  environment {
    variables = {
      LOG_LEVEL                  = var.lambda_log_level
      DELEGATED_ADMIN_ACCOUNT_ID = var.delegated_admin_account_id
    }
  }
  tags = {
    "sra-solution" = var.sra_solution_name
  }
}