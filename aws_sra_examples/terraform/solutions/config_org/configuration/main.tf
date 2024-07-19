########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
locals {
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
  src_path   = "${path.root}/../../solutions/config/config_org/lambda/src/"

  compliance_frequency_single_day = var.p_compliance_frequency == 1
  create_dlq_alarm                = var.p_sra_alarm_email != ""
  create_lambda_log_group         = var.p_create_lambda_log_group == "true"
  is_all_supported                = var.p_all_supported == "true"
  use_graviton                    = contains(local.graviton_regions, data.aws_region.current.name)
  use_kms_key                     = var.p_lambda_log_group_kms_key != ""
  not_global_region_us_east_1     = var.p_current_region != "us-east-1"
}

resource "aws_cloudwatch_log_group" "r_config_org_lambda_log_group" {
  count             = local.create_lambda_log_group ? 1 : 0
  name              = "/aws/lambda/${var.p_config_org_lambda_function_name}"
  retention_in_days = var.p_lambda_log_group_retention
  kms_key_id        = local.use_kms_key != "" ? var.p_lambda_log_group_kms_key : null
  lifecycle {
    prevent_destroy = true
  }
}

########################################################################
# Lambda Policies Documents
########################################################################
resource "aws_iam_role" "r_config_org_lambda_role" {
  name = var.p_config_org_lambda_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = ["lambda.amazonaws.com"]
        }
      }
    ]
  })
}

resource "aws_iam_policy" "sra_config_org_policy_organizations" {
  name        = "sra-config-org-policy-organizations"
  description = "IAM policy for Macie Org Lambda Organizations"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "OrganizationsReadAccess"
        Effect = "Allow"
        Action = [
          "organizations:DescribeAccount",
          "organizations:ListAccounts"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "ssm_access" {
  name        = "ssm-access"
  description = "IAM policy for SSM access"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ],
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/sra*"
        ]
      }
    ]
  })
}

resource "aws_iam_policy" "sra_config_org_policy_sns" {
  name        = "sra-config-org-policy-sns"
  description = "IAM policy for SNS access"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "SNSPublish"
        Effect = "Allow"
        Action = [
          "sns:Publish",
          "sns:PublishBatch"
        ],
        Resource = aws_sns_topic.r_config_org_topic.arn
      }
    ]
  })
}

resource "aws_iam_policy" "sra_config_org_policy_iam" {
  name        = "sra-config-org-policy-iam-lambda"
  description = "IAM policy for IAM access"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AssumeRole"
        Effect = "Allow"
        Action = ["sts:AssumeRole"]
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgId" = var.p_organization_id
          }
        },
        Resource = [
          "arn:aws:iam::*:role/${var.p_config_configuration_role_name}"
        ]
      },
      {
        Sid      = "AllowReadIamActions"
        Effect   = "Allow"
        Action   = ["iam:GetRole"]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*"
      },
      {
        Sid    = "AllowCreateServiceLinkedRole"
        Effect = "Allow"
        Action = ["iam:CreateServiceLinkedRole"]
        Condition = {
          StringLike = {
            "iam:AWSServiceName" = "config.amazonaws.com"
          }
        },
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
      },
      {
        Sid      = "AllowPolicyActions"
        Effect   = "Allow"
        Action   = ["iam:PutRolePolicy"]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
      }
    ]
  })
}

resource "aws_iam_policy" "sra_config_org_policy_logs" {
  name        = "sra-config-org-policy-logs"
  description = "IAM policy for logs access"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "CreateLogGroupAndEvents"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.p_config_org_lambda_function_name}:log-stream:*"
      }
    ]
  })
}

resource "aws_iam_policy" "sra_config_org_policy_sqs" {
  name        = "sra-config-org-policy-sqs"
  description = "IAM policy for SQS access"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "SQSSendMessage"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"],
        Resource = aws_sqs_queue.r_config_org_dlq.arn
      }
    ]
  })
}

########################################################################
# Policy Attachment
########################################################################
resource "aws_iam_role_policy_attachment" "r_config_org_lambda_role_organizations" {
  role       = aws_iam_role.r_config_org_lambda_role.name
  policy_arn = aws_iam_policy.sra_config_org_policy_organizations.arn
}

resource "aws_iam_role_policy_attachment" "r_config_org_lambda_role_ssm_access" {
  role       = aws_iam_role.r_config_org_lambda_role.name
  policy_arn = aws_iam_policy.ssm_access.arn
}

resource "aws_iam_role_policy_attachment" "r_config_org_lambda_role_sns" {
  role       = aws_iam_role.r_config_org_lambda_role.name
  policy_arn = aws_iam_policy.sra_config_org_policy_sns.arn
}

resource "aws_iam_role_policy_attachment" "r_config_org_lambda_role_iam" {
  role       = aws_iam_role.r_config_org_lambda_role.name
  policy_arn = aws_iam_policy.sra_config_org_policy_iam.arn
}

resource "aws_iam_role_policy_attachment" "r_config_org_lambda_role_logs" {
  role       = aws_iam_role.r_config_org_lambda_role.name
  policy_arn = aws_iam_policy.sra_config_org_policy_logs.arn
}

resource "aws_iam_role_policy_attachment" "r_config_org_lambda_role_sqs" {
  role       = aws_iam_role.r_config_org_lambda_role.name
  policy_arn = aws_iam_policy.sra_config_org_policy_sqs.arn
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

resource "aws_lambda_function" "r_config_org_lambda_function" {
  #checkov:skip=CKV_AWS_272: Ensure AWS Lambda function is configured to validate code-signing
  #checkov:skip=CKV_AWS_116: Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) 
  #checkov:skip=CKV_AWS_173: Check encryption settings for Lambda environment variable
  #checkov:skip=CKV_AWS_115: Ensure that AWS Lambda function is configured for function-level concurrent execution limit
  #checkov:skip=CKV_AWS_117: Ensure that AWS Lambda function is configured inside a VPC
  #checkov:skip=CKV_AWS_50: X-Ray tracing is enabled for Lambda

  function_name = var.p_config_org_lambda_function_name
  description   = "configure Config for the Organization"
  role          = aws_iam_role.r_config_org_lambda_role.arn
  handler       = "app.lambda_handler"
  memory_size   = 512
  runtime       = "python3.9"
  timeout       = 900

  source_code_hash = data.archive_file.zipped_lambda.output_base64sha256
  filename         = data.archive_file.zipped_lambda.output_path

  dead_letter_config {
    target_arn = aws_sqs_queue.r_config_org_dlq.arn
  }

  environment {
    variables = {
      AUDIT_ACCOUNT                     = var.p_audit_account_id
      LOG_LEVEL                         = var.p_lambda_log_level
      AWS_PARTITION                     = data.aws_partition.current.partition
      CONFIGURATION_ROLE_NAME           = var.p_config_configuration_role_name
      CONTROL_TOWER_REGIONS_ONLY        = var.p_control_tower_regions_only
      ENABLED_REGIONS                   = var.p_enabled_regions
      ALL_SUPPORTED                     = var.p_all_supported
      INCLUDE_GLOBAL_RESOURCE_TYPES     = var.p_include_global_resource_types
      FREQUENCY                         = var.p_frequency
      RESOURCE_TYPES                    = var.p_resource_types == "" ? null : var.p_resource_types
      DELIVERY_S3_KEY_PREFIX            = var.p_delivery_s3_key_prefix
      S3_BUCKET_NAME                    = "${var.p_config_org_delivery_bucket_prefix}-${var.p_log_archive_account_id}-${var.p_home_region}"
      DELIVERY_CHANNEL_NAME             = var.p_delivery_channel_name
      CONFIG_TOPIC_NAME                 = var.p_config_topic_name
      RECORDER_NAME                     = var.p_recorder_name
      KMS_KEY_SECRET_NAME               = var.p_kms_key_arn_secret_name
      HOME_REGION                       = var.p_home_region
      SNS_TOPIC_ARN_FANOUT              = aws_sns_topic.r_config_org_topic.arn
      PUBLISHING_DESTINATION_BUCKET_ARN = "arn:${data.aws_partition.current.partition}:s3:::${var.p_publishing_destination_bucket_name}"
    }
  }
}

resource "aws_lambda_permission" "r_config_org_topic_lambda_permission" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.r_config_org_lambda_function.arn
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.r_config_org_topic.arn
}

resource "aws_sns_topic" "r_config_org_topic" {
  display_name      = "${var.p_sra_solution_name}-configuration"
  kms_master_key_id = "alias/aws/sns"
  tags = {
    "sra-solution" = var.p_sra_solution_name
  }
}

resource "aws_sns_topic_subscription" "r_config_org_topic_subscription" {
  endpoint  = aws_lambda_function.r_config_org_lambda_function.arn
  protocol  = "lambda"
  topic_arn = aws_sns_topic.r_config_org_topic.arn
}

resource "aws_sqs_queue" "r_config_org_dlq" {
  name                      = "${var.p_sra_solution_name}-dlq"
  kms_master_key_id         = "alias/aws/sqs"
  message_retention_seconds = 345600

  lifecycle {
    prevent_destroy       = false
    create_before_destroy = true
  }
}

resource "aws_sqs_queue_policy" "r_config_org_dlq_policy" {
  queue_url = aws_sqs_queue.r_config_org_dlq.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "SQS:SendMessage",
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_lambda_function.r_config_org_lambda_function.arn
        }
      },
      Effect = "Allow",
      Principal = {
        Service = "events.amazonaws.com"
      },
      Resource = aws_sqs_queue.r_config_org_dlq.arn
    }]
  })
}

resource "aws_sns_topic" "r_config_org_dlq_alarm_topic" {
  count             = var.p_sra_alarm_email != "" ? 1 : 0
  display_name      = "${var.p_sra_solution_name}-dlq-alarm"
  kms_master_key_id = "alias/aws/sns"
  name              = "${var.p_sra_solution_name}-dlq-alarm"
}

resource "aws_sns_topic_subscription" "r_config_org_dlq_alarm_topic_subscription" {
  count     = var.p_sra_alarm_email != "" ? 1 : 0
  endpoint  = var.p_sra_alarm_email
  protocol  = "email"
  topic_arn = aws_sns_topic.r_config_org_dlq_alarm_topic[0].arn
}

resource "aws_cloudwatch_metric_alarm" "r_config_org_dlq_alarm" {
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
  alarm_actions             = [aws_sns_topic.r_config_org_dlq_alarm_topic[0].arn]
  insufficient_data_actions = [aws_sns_topic.r_config_org_dlq_alarm_topic[0].arn]

  dimensions = {
    QueueName = aws_sqs_queue.r_config_org_dlq.name
  }
}

resource "aws_cloudwatch_event_rule" "r_scheduled_compliance_rule" {
  name                = "${var.p_control_tower_life_cycle_rule_name}-organization-compliance"
  description         = "SRA Config Trigger for scheduled organization compliance"
  schedule_expression = local.compliance_frequency_single_day ? "rate(${var.p_compliance_frequency} day)" : "rate(${var.p_compliance_frequency} days)"
  state               = "ENABLED"
}

resource "aws_cloudwatch_event_target" "r_scheduled_compliance_rule_target" {
  rule      = aws_cloudwatch_event_rule.r_scheduled_compliance_rule.name
  target_id = var.p_config_org_lambda_function_name
  arn       = aws_lambda_function.r_config_org_lambda_function.arn
}

resource "aws_lambda_permission" "r_permission_for_scheduled_compliance_rule_to_invoke_lambda" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.r_config_org_lambda_function.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.r_scheduled_compliance_rule.arn
}

resource "aws_iam_role" "r_cross_region_event_rule_role" {
  count = local.not_global_region_us_east_1 ? 1 : 0

  name = var.p_event_rule_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "sts:AssumeRole",
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })

  inline_policy {
    name = "sra-account-org-config-policy-events"
    policy = jsonencode({
      Version = "2012-10-17",
      Statement = [
        {
          Effect   = "Allow",
          Action   = "events:PutEvents",
          Resource = "arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:event-bus/default"
        }
      ]
    })
  }
}

resource "aws_cloudwatch_event_rule" "r_organizations_rule" {
  name        = "${var.p_control_tower_life_cycle_rule_name}-org-update"
  description = "SRA Config Trigger on Organizations update"
  event_pattern = jsonencode({
    source        = ["aws.organizations"],
    "detail-type" = ["AWS Service Event via CloudTrail", "AWS API Call via CloudTrail"],
    detail = {
      eventSource = ["organizations.amazonaws.com"],
      eventName   = ["AcceptHandshake", "CreateAccountResult"]
    }
  })
  state = "ENABLED"
}

resource "aws_cloudwatch_event_target" "r_organizations_rule_target" {
  rule      = aws_cloudwatch_event_rule.r_organizations_rule.name
  target_id = var.p_config_org_lambda_function_name
  arn       = aws_lambda_function.r_config_org_lambda_function.arn
}

resource "aws_lambda_permission" "r_permission_for_organizations_rule_to_invoke_lambda" {
  statement_id  = "AllowExecutionFromOrganizations"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.r_config_org_lambda_function.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.r_organizations_rule.arn
}
