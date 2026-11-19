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