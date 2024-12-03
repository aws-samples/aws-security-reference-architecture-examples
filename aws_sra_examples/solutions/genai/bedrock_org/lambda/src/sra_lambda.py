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

    def create_lambda_function(self, code_zip_file, role_arn, function_name, handler, runtime, timeout, memory_size, solution_name):
        """Create Lambda Function."""
        self.LOGGER.info(f"Role ARN passed to create_lambda_function: {role_arn}...")
        max_retries = 10
        retries = 0
        self.LOGGER.info(f"Size of {code_zip_file} is {os.path.getsize(code_zip_file)} bytes")
        while retries < max_retries:
            try:
                create_response = self.LAMBDA_CLIENT.create_function(
                    FunctionName=function_name,
                    Runtime=runtime,
                    Handler=handler,
                    Role=role_arn,
                    Code={"ZipFile": open(code_zip_file, "rb").read()},
                    Timeout=timeout,
                    MemorySize=memory_size,
                    Tags={"sra-solution": solution_name},
                )
                self.LOGGER.info(f"Lambda function created successfully: {create_response}")
                break
            except ClientError as error:
                if error.response["Error"]["Code"] == "ResourceConflictException":
                    try:
                        self.LOGGER.info(f"{function_name} function already exists.  Updating...")
                        update_response = self.LAMBDA_CLIENT.update_function_code(
                            FunctionName=function_name,
                            ZipFile=open(code_zip_file, "rb").read(),
                        )
                        self.LOGGER.info(f"Lambda function code updated successfully: {update_response}")
                        break
                    except Exception as e:
                        self.LOGGER.info(f"Error deploying Lambda function: {e}")
                        break
                elif error.response["Error"]["Code"] == "InvalidParameterValueException":
                    self.LOGGER.info(f"Lambda not ready to deploy yet. {error}; Retrying...")
                    # TODO(liamschn): need to add a maximum retry mechanism here
                    retries += 1
                    sleep(5)
                else:
                    self.LOGGER.info(f"Error deploying Lambda function: {error}")
                    break
            # txt_response.insert(tk.END, f"Error deploying Lambda: {e}\n")
        try:
            retries = 0
            while retries < max_retries:
                get_response = self.LAMBDA_CLIENT.get_function(FunctionName=function_name)
                if get_response["Configuration"]["State"] == "Active":
                    self.LOGGER.info(f"Lambda function {function_name} is now active")
                    break
                # TODO(liamschn): need to add a maximum retry mechanism here
                retries += 1
                sleep(5)
        except Exception as e:
            self.LOGGER.info(f"Error getting Lambda function: {e}")

        # except ClientError as e:
        #     self.LOGGER.error(e)
        return get_response

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
            if e.response["Error"]["Code"] == "ResourceConflictException":
                # TODO(liamschn): consider updating the permission here
                self.LOGGER.info(f"{function_name} permission already exists.")
                return None
            else:
                self.LOGGER.info(f"Error adding lambda permission: {e}")
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

    def remove_permissions(self, function_name, statement_id):
        """Remove Lambda Function Permissions."""
        try:
            response = self.LAMBDA_CLIENT.remove_permission(FunctionName=function_name, StatementId=statement_id)
            return response
        except ClientError as e:
            self.LOGGER.error(e)
            return None
    
    def delete_lambda_function(self, function_name):
        """Delete Lambda Function."""
        try:
            response = self.LAMBDA_CLIENT.delete_function(FunctionName=function_name)
            return response
        except ClientError as e:
            self.LOGGER.error(e)
            return None
        
    def get_lambda_execution_role(self, function_name) -> str:
        """Get Lambda Function Execution Role.

        Args:
            function_name (str): Lambda Function Name

        Returns:
            str: Execution Role ARN
        """
        self.LOGGER.info(f"Getting execution role for Lambda function: {function_name}")
        try:      
            response = self.LAMBDA_CLIENT.get_function(FunctionName=function_name)
            execution_role_arn = response['Configuration']['Role']
            self.LOGGER.info(f"Execution Role ARN: {execution_role_arn}")
            return execution_role_arn
        except ClientError as e:
            self.LOGGER.error(e)
            return "Error"