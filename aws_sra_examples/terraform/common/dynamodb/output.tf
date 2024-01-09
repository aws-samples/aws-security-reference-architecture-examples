########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

output dynamo_db_table_name {
    value = aws_dynamodb_table.terraform_locks.name
}