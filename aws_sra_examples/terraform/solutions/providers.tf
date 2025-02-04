########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

terraform {
  # checkov:skip=CKV_TF_3:Ensure state files are locked
  required_providers {
    aws = ">= 5.1.0"
  }

  backend "s3" {}
}

provider "aws" {
  alias  = "management"
  region = var.account_region

  assume_role {
    role_arn     = "arn:aws:iam::${var.management_account_id}:role/sra-execution"
    session_name = "Pipeline_Run"
  }

  default_tags {
    tags = {
      Owner = "Security"
    }
  }
}

provider "aws" {
  alias  = "target"
  region = var.account_region

  assume_role {
    role_arn     = "arn:aws:iam::${var.account_id}:role/sra-execution"
    session_name = "Pipeline_Run"
  }
  default_tags {
    tags = {
      Owner = "Security"
    }
  }
}

provider "aws" {
  alias  = "log_archive"
  region = var.account_region

  assume_role {
    role_arn     = "arn:aws:iam::${var.log_archive_account_id}:role/sra-execution"
    session_name = "Pipeline_Run"
  }
  default_tags {
    tags = {
      Owner = "Security"
    }
  }
}