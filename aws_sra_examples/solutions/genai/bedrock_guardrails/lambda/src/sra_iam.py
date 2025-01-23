"""Lambda module to setup SRA IAM resources in the management account.

Version: 1.0

IAM module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
import logging
import os
import urllib.parse
from time import sleep
from typing import TYPE_CHECKING

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_iam.type_defs import CreatePolicyResponseTypeDef, CreateRoleResponseTypeDef, EmptyResponseMetadataTypeDef
    from mypy_boto3_organizations import OrganizationsClient


class SRAIAM:
    """Class to setup SRA IAM resources in the management account."""

    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    # Global Variables
    UNEXPECTED = "Unexpected!"
    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations", config=BOTO3_CONFIG)
        CFN_CLIENT: CloudFormationClient = MANAGEMENT_ACCOUNT_SESSION.client("cloudformation", config=BOTO3_CONFIG)
        IAM_CLIENT: IAMClient = MANAGEMENT_ACCOUNT_SESSION.client("iam", config=BOTO3_CONFIG)
        STS_CLIENT = boto3.client("sts")
        HOME_REGION = MANAGEMENT_ACCOUNT_SESSION.region_name
        LOGGER.info(f"Detected home region: {HOME_REGION}")
        S3_HOST_NAME = urllib.parse.urlparse(boto3.client("s3", region_name=HOME_REGION).meta.endpoint_url).hostname
        MANAGEMENT_ACCOUNT = STS_CLIENT.get_caller_identity().get("Account")
        PARTITION: str = MANAGEMENT_ACCOUNT_SESSION.get_partition_for_region(HOME_REGION)
        LOGGER.info(f"Detected management account (current account): {MANAGEMENT_ACCOUNT}")
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    SRA_POLICY_DOCUMENTS: dict = {
        "sra-lambda-basic-execution": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "CreateLogGroup",
                    "Effect": "Allow",
                    "Action": "logs:CreateLogGroup",
                    "Resource": "arn:" + PARTITION + ":logs:*:ACCOUNT_ID:*",
                },
                {
                    "Sid": "CreateStreamPutEvents",
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "arn:" + PARTITION + ":logs:*:ACCOUNT_ID:log-group:/aws/lambda/CONFIG_RULE_NAME:*",
                },
            ],
        },
    }

    SRA_TRUST_DOCUMENTS: dict = {
        "sra-config-rule": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        "sra-logs": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        },
    }

    def create_role(self, role_name: str, trust_policy: dict, solution_name: str) -> CreateRoleResponseTypeDef:
        """Create IAM role.

        Args:
            role_name: Name of the role to be created
            trust_policy: Trust policy relationship for the role
            solution_name: Name of the solution to be created

        Returns:
            Dictionary output of a successful CreateRole request
        """
        self.LOGGER.info("Creating role %s.", role_name)
        return self.IAM_CLIENT.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=[{"Key": "sra-solution", "Value": solution_name}]
        )

    def create_policy(self, policy_name: str, policy_document: dict, solution_name: str) -> CreatePolicyResponseTypeDef:
        """Create IAM policy.

        Args:
            policy_name: Name of the policy to be created
            policy_document: IAM policy document for the role
            solution_name: Name of the solution to be created

        Returns:
            Dictionary output of a successful CreatePolicy request
        """
        self.LOGGER.info(f"Creating {policy_name} IAM policy")
        return self.IAM_CLIENT.create_policy(
            PolicyName=policy_name, PolicyDocument=json.dumps(policy_document), Tags=[{"Key": "sra-solution", "Value": solution_name}]
        )

    def attach_policy(self, role_name: str, policy_arn: str) -> EmptyResponseMetadataTypeDef:
        """Attach policy to IAM role.

        Args:
            role_name: Name of the role for policy to be attached to
            policy_arn: The Amazon Resource Name (ARN) of the policy to be attached

        Returns:
            Empty response metadata
        """
        self.LOGGER.info("Attaching policy to %s.", role_name)
        return self.IAM_CLIENT.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def detach_policy(self, role_name: str, policy_arn: str) -> EmptyResponseMetadataTypeDef:
        """Detach IAM policy.

        Args:
            role_name: Name of the role for which the policy is removed from
            policy_arn: The Amazon Resource Name (ARN) of the policy to be detached

        Returns:
            Empty response metadata
        """
        self.LOGGER.info("Detaching policy from %s.", role_name)
        return self.IAM_CLIENT.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def delete_policy(self, policy_arn: str) -> EmptyResponseMetadataTypeDef:
        """Delete IAM Policy.

        Args:
            policy_arn: The Amazon Resource Name (ARN) of the policy to be deleted

        Returns:
            Empty response metadata
        """
        self.LOGGER.info("Deleting policy %s.", policy_arn)
        # check for policy versions and delete them if found
        paginator = self.IAM_CLIENT.get_paginator("list_policy_versions")
        response_iterator = paginator.paginate(PolicyArn=policy_arn)
        for page in response_iterator:
            for version in page["Versions"]:
                if not version["IsDefaultVersion"]:
                    self.LOGGER.info(f"Deleting policy version {version['VersionId']}")
                    self.IAM_CLIENT.delete_policy_version(PolicyArn=policy_arn, VersionId=version["VersionId"])
                    sleep(1)
                    self.LOGGER.info("Policy version deleted.")
        return self.IAM_CLIENT.delete_policy(PolicyArn=policy_arn)

    def delete_role(self, role_name: str) -> EmptyResponseMetadataTypeDef:
        """Delete IAM role.

        Args:
            role_name: Name of the role to be deleted

        Returns:
            Empty response metadata
        """
        self.LOGGER.info("Deleting role %s.", role_name)
        return self.IAM_CLIENT.delete_role(RoleName=role_name)

    def check_iam_role_exists(self, role_name: str) -> tuple[bool, str | None]:
        """Check if an IAM role exists.

        Args:
            role_name: Name of the role to check

        Raises:
            ValueError: If an unexpected error occurs during the operation.

        Returns:
            Tuple of boolean and role ARN if the role exists, otherwise False and None.
        """
        try:
            response = self.IAM_CLIENT.get_role(RoleName=role_name)
            self.LOGGER.info(f"The role '{role_name}' exists.")
            return True, response["Role"]["Arn"]
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchEntity":
                self.LOGGER.info(f"The role '{role_name}' does not exist.")
                return False, None
            raise ValueError(f"Error performing get_role operation: {error}") from None

    def check_iam_policy_exists(self, policy_arn: str) -> bool:
        """Check if an IAM policy exists.

        Args:
            policy_arn: The Amazon Resource Name (ARN) of the policy to check.

        Raises:
            ValueError: If an unexpected error occurs during the operation.

        Returns:
            bool: True if the policy exists, False otherwise.
        """
        self.LOGGER.info(f"Checking if policy '{policy_arn}' exists.")
        try:
            result = self.IAM_CLIENT.get_policy(PolicyArn=policy_arn)
            self.LOGGER.info(f"Result: {result}")
            self.LOGGER.info(f"The policy '{policy_arn}' exists.")
            return True
        # Handle other possible exceptions (e.g., permission issues)
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchEntity":
                self.LOGGER.info(f"The policy '{policy_arn}' does not exist.")
                return False
            raise ValueError(f"Unexpected error: {error}") from None

    def check_iam_policy_attached(self, role_name: str, policy_arn: str) -> bool:
        """Check if an IAM policy is attached to an IAM role.

        Args:
            role_name (str): The name of the IAM role.
            policy_arn (str): The ARN of the IAM policy.

        Raises:
            ValueError: If an unexpected error occurs during the operation.

        Returns:
            bool: True if the policy is attached to the role, False otherwise.
        """
        try:
            response = self.IAM_CLIENT.list_attached_role_policies(RoleName=role_name)
            attached_policies = response["AttachedPolicies"]
            for policy in attached_policies:
                if policy["PolicyArn"] == policy_arn:
                    self.LOGGER.info(f"The policy '{policy_arn}' is attached to the role '{role_name}'.")
                    return True
            self.LOGGER.info(f"The policy '{policy_arn}' is not attached to the role '{role_name}'.")
            return False
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchEntity":
                self.LOGGER.info(f"The role '{role_name}' does not exist.")
                return False
            self.LOGGER.error(f"Error checking if policy '{policy_arn}' is attached to role '{role_name}': {error}")
            raise ValueError(f"Error checking if policy '{policy_arn}' is attached to role '{role_name}': {error}") from None

    def list_attached_iam_policies(self, role_name: str) -> list:
        """List all IAM policies attached to an IAM role.

        Args:
            role_name (str): The name of the IAM role.

        Raises:
            ValueError: If an unexpected error occurs during the operation.

        Returns:
            list: List of attached IAM policies
        """
        try:
            response = self.IAM_CLIENT.list_attached_role_policies(RoleName=role_name)
            attached_policies = response["AttachedPolicies"]
            self.LOGGER.info(f"Attached policies for role '{role_name}': {attached_policies}")
            return attached_policies
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchEntity":
                self.LOGGER.info(f"The role '{role_name}' does not exist.")
                return []
            self.LOGGER.error(f"Error listing attached policies for role '{role_name}': {error}")
            raise ValueError(f"Error listing attached policies for role '{role_name}': {error}") from None

    def get_iam_global_region(self) -> str:
        """Get the region name for the global region.

        Args:
            None

        Returns:
            str: The region name for the global region
        """
        partition_to_region = {"aws": "us-east-1", "aws-cn": "cn-north-1", "aws-us-gov": "us-gov-west-1"}
        return partition_to_region.get(self.PARTITION, "us-east-1")  # Default to us-east-1 if partition is unknown
