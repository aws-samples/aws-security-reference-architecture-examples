"""Custom Resource to setup SRA Lambda resources in the organization.

Version: 0.1

LAMBDA module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
from time import sleep

# import re
# from time import sleep
from typing import TYPE_CHECKING

# , Literal, Optional, Sequence, Union

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# import urllib.parse
# import json

# import cfnresponse

if TYPE_CHECKING:
    # from mypy_boto3_cloudformation import CloudFormationClient
    # from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_lambda.client import LambdaClient
    # from mypy_boto3_iam.client import IAMClient
    # from mypy_boto3_iam.type_defs import CreatePolicyResponseTypeDef, CreateRoleResponseTypeDef, EmptyResponseMetadataTypeDef


class sra_lambda:
    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    UNEXPECTED = "Unexpected!"

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        LAMBDA_CLIENT: LambdaClient = MANAGEMENT_ACCOUNT_SESSION.client("lambda", config=BOTO3_CONFIG)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def find_lambda_function(self, function_name):
        """Find Lambda Function."""
        try:
            response = self.LAMBDA_CLIENT.get_function(FunctionName=function_name)
            return response
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            else:
                self.LOGGER.error(e)
                return None

    def create_lambda_function(self, code_s3_bucket, code_s3_key, role_arn, function_name, handler, runtime, timeout, memory_size):
        """Create Lambda Function."""
        try:
            response = self.LAMBDA_CLIENT.create_function(
                FunctionName=function_name,
                Runtime=runtime,
                Handler=handler,
                Role=role_arn,
                Code={"S3Bucket": code_s3_bucket, "S3Key": code_s3_key},
                Timeout=timeout,
                MemorySize=memory_size,
            )
            return response
        except ClientError as e:
            self.LOGGER.error(e)
            return None

    def get_permissions(self, function_name):
        """Get Lambda Function Permissions."""
        try:
            response = self.LAMBDA_CLIENT.get_policy(FunctionName=function_name)
            return response
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            else:
                self.LOGGER.error(e)
                return None

    def put_permissions(self, function_name, statement_id, principal, action, source_arn):
        """Put Lambda Function Permissions."""
        try:
            response = self.LAMBDA_CLIENT.add_permission(
                FunctionName=function_name,
                StatementId=statement_id,
                Action=action,
                Principal=principal,
                SourceArn=source_arn,
            )
            return response
        except ClientError as e:
            self.LOGGER.error(e)
            return None

    def put_permissions_acct(self, function_name, statement_id, principal, action, source_acct):
        """Put Lambda Function Permissions."""
        try:
            response = self.LAMBDA_CLIENT.add_permission(
                FunctionName=function_name,
                StatementId=statement_id,
                Action=action,
                Principal=principal,
                SourceAccount=source_acct,
            )
            return response
        except ClientError as e:
            self.LOGGER.error(e)
            return None