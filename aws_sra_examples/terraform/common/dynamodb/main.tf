########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_dynamodb_table" "terraform_locks" {
  #checkov:skip=CKV_AWS_28: Ensure DynamoDB point in time recovery (backup) is enabled 
  #checkov:skip=CKV_AWS_119: Ensure DynamoDB Tables are encrypted using a KMS Customer Managed CMK
  name         = var.dynamodb_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"  
  attribute {
    name = "LockID"
    type = "S"
  }
}