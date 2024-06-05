resource "aws_iam_role" "r_config_recorder_role" {
  name               = var.p_config_configuration_role_name
  assume_role_policy = data.aws_iam_policy_document.r_config_recorder_assume_role_policy.json

  tags = {
    "${var.p_sra_solution_tag_key}" = var.p_sra_solution_name
  }
}

resource "aws_iam_policy" "r_config_org_policy_iam" {
  name   = "sra-config-org-policy-iam"
  policy = data.aws_iam_policy_document.r_config_org_policy_iam.json
}

resource "aws_iam_policy" "r_config_org_policy_config" {
  name   = "sra-config-org-policy-config"
  policy = data.aws_iam_policy_document.r_config_org_policy_config.json
}

resource "aws_iam_policy" "r_config_org_policy_secrets_manager" {
  name   = "sra-config-org-policy-secrets-manager"
  policy = data.aws_iam_policy_document.r_config_org_policy_secrets_manager.json
}

resource "aws_iam_policy" "r_config_org_policy_kms" {
  name   = "sra-config-org-policy-kms"
  policy = data.aws_iam_policy_document.r_config_org_policy_kms.json
}

resource "aws_iam_role_policy_attachment" "r_config_org_attach_iam" {
  role       = aws_iam_role.r_config_recorder_role.name
  policy_arn = aws_iam_policy.r_config_org_policy_iam.arn
}

resource "aws_iam_role_policy_attachment" "r_config_org_attach_config" {
  role       = aws_iam_role.r_config_recorder_role.name
  policy_arn = aws_iam_policy.r_config_org_policy_config.arn
}

resource "aws_iam_role_policy_attachment" "r_config_org_attach_secrets_manager" {
  role       = aws_iam_role.r_config_recorder_role.name
  policy_arn = aws_iam_policy.r_config_org_policy_secrets_manager.arn
}

resource "aws_iam_role_policy_attachment" "r_config_org_attach_kms" {
  role       = aws_iam_role.r_config_recorder_role.name
  policy_arn = aws_iam_policy.r_config_org_policy_kms.arn
}

data "aws_iam_policy_document" "r_config_recorder_assume_role_policy" {
  statement {
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::${var.p_management_account_id}:role/${var.p_config_org_lambda_role_name}"]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${var.p_management_account_id}:root"]
    }
  }
}

data "aws_iam_policy_document" "r_config_org_policy_iam" {
  statement {
    sid       = "AllowReadIamActions"
    effect    = "Allow"
    actions   = ["iam:GetRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*"]
  }

  statement {
    sid       = "AllowIamPassRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"]
  }

  statement {
    sid       = "AllowCreateServiceLinkedRole"
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole"]
    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"
      values   = ["config.amazonaws.com"]
    }
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"]
  }

  statement {
    sid       = "AllowDeleteServiceLinkRole"
    effect    = "Allow"
    actions   = ["iam:DeleteServiceLinkedRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"]
  }
}

data "aws_iam_policy_document" "r_config_org_policy_config" {
  statement {
    effect    = "Allow"
    actions   = [
      "config:DeleteDeliveryChannel",
      "config:DescribeConfigurationRecorders",
      "config:DescribeDeliveryChannels",
      "config:StartConfigurationRecorder",
      "config:PutDeliveryChannel",
      "config:DeleteConfigurationRecorder",
      "config:DescribeConfigurationRecorderStatus",
      "config:PutConfigurationRecorder"
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "r_config_org_policy_secrets_manager" {
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    condition {
      test     = "StringLike"
      variable = "aws:PrincipalAccount"
      values   = [var.p_audit_account_id]
    }
    resources = ["arn:aws:secretsmanager:${var.p_home_region}:${var.p_audit_account_id}:secret:${var.p_kms_key_arn_secret_name}*"]
  }
}

data "aws_iam_policy_document" "r_config_org_policy_kms" {
  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    condition {
      test     = "StringLike"
      variable = "aws:PrincipalAccount"
      values   = [var.p_audit_account_id]
    }
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = ["alias/sra-secrets-key"]
    }
    resources = ["*"]
  }
}