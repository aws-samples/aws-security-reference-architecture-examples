########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

terraform {
  required_providers {
    aws = ">= 5.1.0"
  }
}

provider "aws" {
  alias  = "target"
  region = var.account_region

  default_tags {
    tags = {
      Owner = "Security"
    }
  }
}