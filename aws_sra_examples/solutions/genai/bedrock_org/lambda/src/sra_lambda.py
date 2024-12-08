"""Custom Resource to setup SRA Lambda resources in the organization.

Version: 1.0

LAMBDA module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
from time import sleep

from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_lambda.client import LambdaClient


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

    def find_lambda_function(self, function_name: str) -> str:
        """Find Lambda Function.
        
        Args:
            function_name: Lambda function name

        Returns:
            Lambda function arn if found, else "None"
        """
        try:
            response = self.LAMBDA_CLIENT.get_function(FunctionName=function_name)
            return response["Configuration"]["FunctionArn"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return "None"
            else:
                self.LOGGER.error(f"Error encountered searching for lambda function: {e}")
                return "None"

    def create_lambda_function(self, code_zip_file: str, role_arn: str, function_name: str, handler: str, runtime: str, timeout: int, memory_size: int, solution_name: str) -> str:
        """Create Lambda Function."""
        self.LOGGER.info(f"Role ARN passed to create_lambda_function: {role_arn}...")
        max_retries = 10
        retries = 0
        self.LOGGER.info(f"Size of {code_zip_file} is {os.path.getsize(code_zip_file)} bytes")
        while retries < max_retries:
            self.LOGGER.info(f"Create function attempt {retries+1} of {max_retries}...")
            try:
                create_response = self.LAMBDA_CLIENT.create_function(
                    FunctionName=function_name,
                    Runtime=runtime, # type: ignore
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
                    retries += 1
                    sleep(5)
                else:
                    self.LOGGER.info(f"Error deploying Lambda function: {error}")
                    break
        retries = 0
        while retries < max_retries:
            try:
                self.LOGGER.info(f"Search for function attempt {retries+1} of {max_retries}...")
                get_response = self.LAMBDA_CLIENT.get_function(FunctionName=function_name)
                if get_response["Configuration"]["State"] == "Active":
                    self.LOGGER.info(f"Lambda function {function_name} is now active")
                    break
                else:
                    self.LOGGER.info(f"{function_name} lambda function state is {get_response["Configuration"]["State"]}.  Waiting to retry...")
                retries += 1
                sleep(5)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    self.LOGGER.info(f"Lambda function {function_name} not found.  Retrying...")
                    retries += 1
                    sleep(5)
                else:
                    self.LOGGER.info(f"Error getting Lambda function: {e}")
                    raise ValueError(f"Error getting Lambda function: {e}") from None
        return get_response["Configuration"]["FunctionArn"]

    def get_permissions(self, function_name: str) -> str:
        """Get Lambda Function Permissions."""
        try:
            response = self.LAMBDA_CLIENT.get_policy(FunctionName=function_name)
            return response["Policy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return "None"
            else:
                self.LOGGER.error(e)
                return "None"

    def put_permissions(self, function_name: str, statement_id: str, principal: str, action: str, source_arn: str) -> str:
        """Put Lambda Function Permissions."""
        try:
            response = self.LAMBDA_CLIENT.add_permission(
                FunctionName=function_name,
                StatementId=statement_id,
                Action=action,
                Principal=principal,
                SourceArn=source_arn,
            )
            return response["Statement"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceConflictException":
                # TODO(liamschn): consider updating the permission here
                self.LOGGER.info(f"{function_name} permission already exists.")
                return "None"
            else:
                self.LOGGER.info(f"Error adding lambda permission: {e}")
            return "None"

    def put_permissions_acct(self, function_name: str, statement_id: str, principal: str, action: str, source_acct: str) -> str:
        """Put Lambda Function Permissions."""
        try:
            response = self.LAMBDA_CLIENT.add_permission(
                FunctionName=function_name,
                StatementId=statement_id,
                Action=action,
                Principal=principal,
                SourceAccount=source_acct,
            )
            return response["Statement"]
        except ClientError as e:
            self.LOGGER.error(e)
            return "None"

    def remove_permissions(self, function_name: str, statement_id: str) -> None:
        """Remove Lambda Function Permissions."""
        try:
            self.LAMBDA_CLIENT.remove_permission(FunctionName=function_name, StatementId=statement_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                self.LOGGER.info(f"{function_name} permission not found.")
                return
            else:
                self.LOGGER.info(f"Error removing lambda permission: {e}")
                return
    
    def delete_lambda_function(self, function_name: str) -> None:
        """Delete Lambda Function."""
        try:
            self.LAMBDA_CLIENT.delete_function(FunctionName=function_name)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                self.LOGGER.info(f"{function_name} function not found.")
                return
            else:
                self.LOGGER.info(f"Error deleting lambda function: {e}")
                return
        
    def get_lambda_execution_role(self, function_name: str) -> str:
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
    
    def find_permission(self, function_name: str, statement_id: str) -> bool:
        """Find Lambda Function Permissions."""
        try:
            response = self.LAMBDA_CLIENT.get_policy(FunctionName=function_name)
            policy = response["Policy"]
            if statement_id in policy:
                return True
            else:
                return False
        except ClientError as e:
            self.LOGGER.error(e)
            return False