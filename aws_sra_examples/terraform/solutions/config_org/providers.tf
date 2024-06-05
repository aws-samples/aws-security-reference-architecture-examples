########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 5.1.0"
      configuration_aliases = [aws.main, aws.management, aws.log_archive, aws.audit]
    }
  }
}