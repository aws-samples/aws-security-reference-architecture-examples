resource "aws_kms_key" "r_config_sns_key" {
  description         = "SRA Config SNS Key"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.r_config_sns_key_policy.json
  tags = {
    "sra-solution" = var.p_sra_solution_name
  }
}

resource "aws_kms_alias" "r_config_sns_key_alias" {
  name          = "alias/${var.p_config_org_sns_key_alias}"
  target_key_id = aws_kms_key.r_config_sns_key.key_id
}

data "aws_iam_policy_document" "r_config_sns_key_policy" {
  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "Allow Config to encrypt logs"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }

  statement {
    sid       = "Allow alias creation during setup"
    effect    = "Allow"
    actions   = ["kms:CreateAlias"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["cloudformation.${data.aws_region.current.name}.amazonaws.com"]
    }
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

#Add email policy