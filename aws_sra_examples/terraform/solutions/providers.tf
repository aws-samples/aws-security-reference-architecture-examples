########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.31.0"
    }
  }
  backend "s3" {}
}

provider "aws" {
  alias  = "target"
  region = var.account_region

  default_tags {
    tags = {
      Owner       = "Security"
      Environment = "SRA"
      Terraform   = "true"
    }
  }
}

provider "aws" {
  alias  = "management"
  region = var.home_region

  assume_role {
    role_arn = "arn:${var.aws_partition}:iam::${var.management_account_id}:role/sra-execution"
  }

  default_tags {
    tags = {
      Owner       = "Security"
      Environment = "SRA"
      Terraform   = "true"
    }
  }
}

provider "aws" {
  alias  = "log_archive"
  region = var.home_region

  assume_role {
    role_arn = "arn:${var.aws_partition}:iam::${var.log_archive_account_id}:role/sra-execution"
  }

  default_tags {
    tags = {
      Owner       = "Security"
      Environment = "SRA"
      Terraform   = "true"
    }
  }
}
