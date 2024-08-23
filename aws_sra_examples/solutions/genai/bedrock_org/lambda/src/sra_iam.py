"""Custom Resource to setup SRA IAM resources in the management account.

Version: 1.0

IAM module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

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

import urllib.parse
import json

import cfnresponse

if TYPE_CHECKING:
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_iam.type_defs import CreatePolicyResponseTypeDef, CreateRoleResponseTypeDef, EmptyResponseMetadataTypeDef


# TODO(liamschn): build execution role in management account
class sra_iam:
    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    # Global Variables
    STACKSET_NAME: str = "sra-stackset-execution-role"
    STACKSET2_NAME: str = "sra-stackset-admin-role"

    RESOURCE_TYPE: str = ""
    # CLOUDFORMATION_THROTTLE_PERIOD = 0.2
    # CLOUDFORMATION_PAGE_SIZE = 100
    SRA_STAGING_BUCKET: str = ""
    UNEXPECTED = "Unexpected!"
    # EMPTY_VALUE = "NONE"
    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    SRA_SOLUTION_NAME = "sra-common-prerequisites" # todo(liamschn): solution name should be in the main/app module
    CFN_RESOURCE_ID: str = "sra-iam-function"
    CFN_CUSTOM_RESOURCE: str = "Custom::LambdaCustomResource"
    SRA_EXECUTION_ROLE: str = "sra-execution"  # todo(liamschn): parameterize this role name
    SRA_STACKSET_ROLE: str = "sra-stackset"  # todo(liamschn): parameterize this role name
    SRA_EXECUTION_ROLE_STACKSET_ID: str = ""
    SRA_STACKSET_POLICY_NAME: str = "sra-assume-role-access"

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

    SRA_EXECUTION_TRUST: dict = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:" + PARTITION + ":iam::" + MANAGEMENT_ACCOUNT + ":root"}, "Action": "sts:AssumeRole"}
        ],
    }

    SRA_STACKSET_POLICY: dict = {
        "Version": "2012-10-17",
        "Statement": [
            {"Action": "sts:AssumeRole", "Resource": "arn:aws:iam::*:role/" + SRA_EXECUTION_ROLE, "Effect": "Allow", "Sid": "AssumeExecutionRole"}
        ],
    }

    SRA_POLICY_DOCUMENTS: dict = {
        "sra-lambda-basic-execution": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "arn:" + PARTITION + ":logs:*:ACCOUNT_ID:*"},
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "arn:" + PARTITION + ":logs:*:ACCOUNT_ID:log-group:/aws/lambda/CONFIG_RULE_NAME:*",
                },
            ],
        },
    }

    # TODO(liamschn): move stackset trust document to SRA_TRUST_DOCUMENTS variable
    SRA_STACKSET_TRUST: dict = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}],
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

    # Configuration
    # TODO(liamschn): move CFN params to cfn module
    CFN_CAPABILITIES = ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"]
    CFN_PARAMETERS = [
        {"ParameterKey": "pManagementAccountId", "ParameterValue": MANAGEMENT_ACCOUNT},
        # Add more parameters as needed
    ]
    ACCOUNT_IDS = []  # Will be filled with accounts in the root OU
    ROOT_OU: str = ""
    REGION_NAMES = ["us-east-1"]  # only global region for iam

    # Organization service functions
    def get_accounts_in_root_ou(self):
        self.ACCOUNT_IDS = []
        self.ROOT_OU = self.ORG_CLIENT.list_roots()["Roots"][0]["Id"]
        # root_ous = self.ORG_CLIENT.list_roots()["Roots"]
        # for root_ou in root_ous:
        #     paginator = self.ORG_CLIENT.get_paginator("list_accounts_for_parent")
        #     for page in paginator.paginate(ParentId=root_ou["Id"]):
        #         for account in page["Accounts"]:
        #             self.ACCOUNT_IDS.append(account["Id"])
        for account in self.ORG_CLIENT.list_accounts()["Accounts"]:
            if account["Status"] == "ACTIVE":
                self.ACCOUNT_IDS.append(account["Id"])

    # CloudFormation service functions
    # TODO(liamschn): Move cloudformation functions into its own class module
    def create_stack(self, parameters, capabilities, template_url, stack_name):
        # todo(liamschn): instead of building via stack, build in python boto3 (both admin and execution roles)
        response = self.CFN_CLIENT.create_stack(
            StackName=stack_name,
            TemplateURL=template_url,
            Parameters=parameters,
            Capabilities=capabilities,
        )
        self.LOGGER.info(f"Stack {stack_name} creation initiated.")
        return response

    def create_stack_set(self, parameters, capabilities, template_url, stack_set_name):
        response = self.CFN_CLIENT.create_stack_set(
            StackSetName=stack_set_name,
            TemplateURL=template_url,
            Parameters=parameters,
            Capabilities=capabilities,
            PermissionModel="SERVICE_MANAGED",
            AutoDeployment={"Enabled": True, "RetainStacksOnAccountRemoval": False},
        )
        self.LOGGER.info(f"StackSet {stack_set_name} creation initiated.")
        return response

    def create_stack_instances(self, root_ou_id, stack_set_name):
        response = self.CFN_CLIENT.create_stack_instances(
            StackSetName=stack_set_name,
            DeploymentTargets={"OrganizationalUnitIds": [root_ou_id]},
            Regions=self.REGION_NAMES,
            OperationPreferences={
                "FailureToleranceCount": 0,
                "MaxConcurrentCount": 1,
            },
        )
        self.LOGGER.info(f"Stack instances creation initiated for regions: {self.REGION_NAMES}.")
        return response

    def list_stack_instances(self, stack_set_name):
        response = self.CFN_CLIENT.list_stack_instances(
            StackSetName=stack_set_name,
        )
        return response

    def check_for_stack_set(self, stack_set_name) -> bool:
        try:
            response = self.CFN_CLIENT.describe_stack_set(StackSetName=stack_set_name)
            self.SRA_EXECUTION_ROLE_STACKSET_ID = response["StackSet"]["StackSetId"]
            return True
        except self.CFN_CLIENT.exceptions.StackSetNotFoundException as error:
            self.LOGGER.info(f"CloudFormation StackSet: {stack_set_name} not found.")
            return False

    def wait_for_stack_instances(self, stack_set_name, retries: int = 30):  # todo(liamschn): parameterize retries
        self.LOGGER.info(f"Waiting for stack instances to complete for {stack_set_name} stackset...")
        self.LOGGER.info({"Accounts": self.ACCOUNT_IDS})
        found_accounts = []
        while True:
            self.LOGGER.info("Getting stack instances...")
            paginator = self.CFN_CLIENT.get_paginator("list_stack_instances")
            found_all_accounts = True
            response_iterator = paginator.paginate(
                StackSetName=stack_set_name,
            )
            for page in response_iterator:
                self.LOGGER.info("Iterating through stack instances...")
                for instance in page["Summaries"]:
                    if instance["Account"] in found_accounts:
                        continue
                    else:
                        found_accounts.append(instance["Account"])
            for account in self.ACCOUNT_IDS:
                self.LOGGER.info("Checking for stack instance for all member accounts...")
                if account != self.MANAGEMENT_ACCOUNT:
                    self.LOGGER.info(f"Checking for stack instance for {account} account...")
                    if account in found_accounts:
                        self.LOGGER.info(f"Stack instance for {account} account found.")
                    else:
                        self.LOGGER.info(f"Stack instance for {account} account not found.")
                        found_all_accounts = False
            if found_all_accounts is True:
                break
            else:
                self.LOGGER.info("All accounts not found.  Waiting 10 seconds before retrying...")
                # TODO(liamschn): need to add a maximum retry mechanism here
                sleep(10)
        ready = False
        i = 0
        while ready is False:
            ready = True
            paginator = self.CFN_CLIENT.get_paginator("list_stack_instances")
            response_iterator = paginator.paginate(
                StackSetName=stack_set_name,
            )
            for page in response_iterator:
                for instance in page["Summaries"]:
                    if instance["StackInstanceStatus"]["DetailedStatus"] != "SUCCEEDED":
                        self.LOGGER.info(f"Stack instance in {instance['Account']} shows {instance['StackInstanceStatus']['DetailedStatus']}")
                        ready = False
            i += 1
            if i > retries:
                self.LOGGER.info("Timed out!  Please check cloudformation stackset and try again.")
                raise Exception("Timed out waiting for stackset!")
            if ready is False:
                self.LOGGER.info("Waiting 10 seconds before retrying...")
                sleep(10)
        return

    # IAM service functions
    def create_role(self, role_name: str, trust_policy: dict, solution_name: str) -> CreateRoleResponseTypeDef:
        """Create IAM role.

        Args:
            session: boto3 session used by boto3 API calls
            role_name: Name of the role to be created
            trust_policy: Trust policy relationship for the role

        Returns:
            Dictionary output of a successful CreateRole request
        """
        self.LOGGER.info("Creating role %s.", role_name)
        return self.IAM_CLIENT.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=[{"Key": "sra-solution", "Value": solution_name}])

    def create_policy(self, policy_name: str, policy_document: dict, solution_name: str) -> CreatePolicyResponseTypeDef:
        """Create IAM policy.

        Args:
            session: boto3 session used by boto3 API calls
            policy_name: Name of the policy to be created
            policy_document: IAM policy document for the role

        Returns:
            Dictionary output of a successful CreatePolicy request
        """
        self.LOGGER.info(f"Creating {policy_name} IAM policy")
        return self.IAM_CLIENT.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(policy_document), Tags=[{"Key": "sra-solution", "Value": solution_name}])

    # def attach_policy(self, role_name: str, policy_name: str, policy_document: str) -> EmptyResponseMetadataTypeDef:
    #     """Attach policy to IAM role.

    #     Args:
    #         session: boto3 session used by boto3 API calls
    #         role_name: Name of the role for policy to be attached to
    #         policy_name: Name of the policy to be attached
    #         policy_document: IAM policy document to be attached

    #     Returns:
    #         Empty response metadata
    #     """

    #     self.LOGGER.info("Attaching policy to %s.", role_name)
    #     return self.IAM_CLIENT.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_document)

    def attach_policy(self, role_name: str, policy_arn: str) -> EmptyResponseMetadataTypeDef:
        """Attach policy to IAM role.

        Args:
            session: boto3 session used by boto3 API calls
            role_name: Name of the role for policy to be attached to
            policy_name: Name of the policy to be attached
            policy_document: IAM policy document to be attached

        Returns:
            Empty response metadata
        """

        self.LOGGER.info("Attaching policy to %s.", role_name)
        return self.IAM_CLIENT.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def detach_policy(self, role_name: str, policy_arn: str) -> EmptyResponseMetadataTypeDef:
        """Detach IAM policy.

        Args:
            session: boto3 session used by boto3 API calls
            role_name: Name of the role for which the policy is removed from
            policy_name: Name of the policy to be removed (detached)

        Returns:
            Empty response metadata
        """
        self.LOGGER.info("Detaching policy from %s.", role_name)
        return self.IAM_CLIENT.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def delete_policy(self, policy_arn: str) -> EmptyResponseMetadataTypeDef:
        """Delete IAM Policy.

        Args:
            session: boto3 session used by boto3 API calls
            policy_arn: The Amazon Resource Name (ARN) of the policy to be deleted

        Returns:
            Empty response metadata
        """
        self.LOGGER.info("Deleting policy %s.", policy_arn)
        return self.IAM_CLIENT.delete_policy(PolicyArn=policy_arn)

    def delete_role(self, role_name: str) -> EmptyResponseMetadataTypeDef:
        """Delete IAM role.

        Args:
            session: boto3 session used by boto3 API calls
            role_name: Name of the role to be deleted

        Returns:
            Empty response metadata
        """
        self.LOGGER.info("Deleting role %s.", role_name)
        return self.IAM_CLIENT.delete_role(RoleName=role_name)

    def check_iam_role_exists(self, role_name):
        """
        Checks if an IAM role exists.

        Parameters:
        - role_name (str): The name of the IAM role to check.

        Returns:
        bool: True if the role exists, False otherwise.
        """
        try:
            response = self.IAM_CLIENT.get_role(RoleName=role_name)
            self.LOGGER.info(f"The role '{role_name}' exists.")
            return True, response["Role"]["Arn"]
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchEntity":
                self.LOGGER.info(f"The role '{role_name}' does not exist.")
                return False, None
            else:
                # Handle other possible exceptions (e.g., permission issues)
                raise ValueError(f"Error performing get_role operation: {error}") from None

    def check_iam_policy_exists(self, policy_arn):
        """
        Checks if an IAM policy exists.

        Parameters:
        - policy_arn (str): The Amazon Resource Name (ARN) of the IAM policy to check.

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
            else:
                raise ValueError(f"Unexpected error: {error}") from None

    def check_iam_policy_attached(self, role_name, policy_arn):
        """
        Checks if an IAM policy is attached to an IAM role.

        Parameters:
        - role_name (str): The name of the IAM role.
        - policy_arn (str): The Amazon Resource Name (ARN) of the IAM policy.

        Returns:
        bool: True if the policy is attached, False otherwise.
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
            self.LOGGER.error(f"Error checking if policy '{policy_arn}' is attached to role '{role_name}': {error}")
            raise

    def list_attached_iam_policies(self, role_name):
        """
        Lists all IAM policies attached to an IAM role.

        Parameters:
        - role_name (str): The name of the IAM role.

        Returns:
        list: A list of dictionaries containing information about the attached policies.
        """
        try:
            response = self.IAM_CLIENT.list_attached_role_policies(RoleName=role_name)
            attached_policies = response["AttachedPolicies"]
            self.LOGGER.info(f"Attached policies for role '{role_name}': {attached_policies}")
            return attached_policies
        except ClientError as error:
            self.LOGGER.error(f"Error listing attached policies for role '{role_name}': {error}")
            raise ValueError(f"Error listing attached policies for role '{role_name}': {error}") from None